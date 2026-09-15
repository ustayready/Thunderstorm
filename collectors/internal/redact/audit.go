package redact

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// AuditReport is the machine-readable result of the fail-closed self-audit.
type AuditReport struct {
	Pass          bool           `json:"pass"`
	MappedByType  map[string]int `json:"mapped_by_type"`
	RealTokens    int            `json:"real_tokens_scanned"`
	LeakHits      []LeakHit      `json:"leak_hits"`
	Isomorphism   []string       `json:"isomorphism_errors,omitempty"`
	DroppedFiles  []string       `json:"dropped_files,omitempty"`
	SyntheticBlob int            `json:"synthetic_blobs"`
}

// LeakHit is a real identifier found surviving in the output (a fatal failure).
type LeakHit struct {
	File  string `json:"file"`
	Token string `json:"token"`
}

// stopwords are common structural/vocabulary tokens that must not count as real
// identifiers (they legitimately recur in both input and output).
var stopwords = map[string]bool{
	"default": true, "admin": true, "owner": true, "editor": true, "viewer": true,
	"roles": true, "role": true, "compute": true, "storage": true, "google": true,
	"amazonaws": true, "gserviceaccount": true, "iam": true, "user": true, "users": true,
	"group": true, "groups": true, "service": true, "serviceaccount": true, "account": true,
	"aws": true, "gcp": true, "azure": true, "true": true, "false": true, "active": true,
	"global": true, "public": true, "external": true, "internal": true, "provider": true,
	"policy": true, "bucket": true, "buckets": true, "secret": true, "secrets": true,
	"instance": true, "function": true, "project": true, "projects": true, "network": true,
	"subnet": true, "region": true, "location": true, "resource": true, "resources": true,
	"example": true, "com": true, "org": true, "net": true, "http": true, "https": true,
	"multi": true, "unknown": true, "none": true, "null": true,
}

// structuralValueKeys hold values the transform deliberately KEEPS verbatim; their values
// (and identifier-shaped fragments of them, like permission verbs) must never be counted
// as real identifiers, or the audit would flag its own intentional structural output.
var structuralValueKeys = map[string]bool{
	"node_type": true, "type": true, "category": true, "relationship_kind": true,
	"nature": true, "state": true, "provider": true, "severity": true, "found": true,
	"emits_hint": true, "rule_id": true, "partition": true, "status": true, "kind": true,
	"region": true, "permissions": true, "confidence": true, "weight": true, "score": true,
}

// extractRealTokens walks every input file and returns the set of identifier-like tokens
// (and brute-forcible components) whose survival in the output would be a leak. INDEPENDENT
// of the registry, so it catches identifiers the registry may have missed. Structural
// vocabulary (node kinds, permission verbs, emits hints) is collected separately and
// subtracted, so only genuine identifiers remain.
func extractRealTokens(files map[string][]byte) map[string]bool {
	real := map[string]bool{}
	structural := map[string]bool{}
	addTo := func(set map[string]bool, s string) {
		s = strings.TrimSpace(s)
		if len(s) < 5 || stopwords[strings.ToLower(s)] {
			return
		}
		set[s] = true
	}
	add := func(s string) { addTo(real, s) }
	addComponents := func(s string) {
		add(s)
		if i := strings.IndexByte(s, '@'); i > 0 { // email: local + domain (+ SA project)
			add(s[:i])
			dom := s[i+1:]
			add(dom)
			if strings.HasSuffix(dom, ".iam.gserviceaccount.com") {
				add(strings.TrimSuffix(dom, ".iam.gserviceaccount.com"))
			}
		}
		for _, lbl := range strings.FieldsFunc(s, func(r rune) bool {
			return r == '.' || r == '/' || r == ':' || r == '|'
		}) {
			add(lbl)
		}
	}
	for name, b := range files {
		if strings.HasPrefix(name, "blobs/") {
			continue // blob bodies are dropped/replaced, never scanned as real
		}
		// (a) raw regex sweep — WHOLE identifier-shaped substrings (no component split here;
		//     structural dotted tokens like permission verbs are subtracted below).
		text := string(b)
		for _, re := range []*regexp.Regexp{reARN, reSAEmail, reGSAEmail, reEmail, reGUID, reAWSAcct, reHostname, reCIDR, reIPv4} {
			for _, m := range re.FindAllString(text, -1) {
				if m == "0.0.0.0" || m == "0.0.0.0/0" {
					continue // "any" — structural, kept verbatim
				}
				add(m)
			}
		}
		// (b) JSON walk — node_id account/native + identifying-key values (with components),
		//     plus collection of the structural allowlist to subtract.
		objs := splitNDJSON(b)
		if name == "engagement.json" {
			objs = [][]byte{b}
		}
		for _, line := range objs {
			var m map[string]any
			if json.Unmarshal(line, &m) != nil {
				continue
			}
			walkExtract("", m, addComponents, func(s string) { addTo(structural, s) })
		}
	}
	for s := range structural {
		delete(real, s)
	}
	return real
}

// walkExtract collects real identifiers (via add) and structural vocabulary (via addStruct).
func walkExtract(keyHint string, v any, add, addStruct func(string)) {
	if keyHint == "tags" || keyHint == "labels" {
		extractTags(v, add)
		return
	}
	if structuralValueKeys[keyHint] {
		collectStructural(v, addStruct)
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			walkExtract(strings.ToLower(k), e, add, addStruct)
		}
	case []any:
		for _, e := range x {
			walkExtract(keyHint, e, add, addStruct)
		}
	case string:
		if keyHint == "node_id" || keyHint == "source" || keyHint == "target" || keyHint == "resource_id" {
			parts := strings.SplitN(x, "|", 4)
			if len(parts) == 4 {
				addStruct(parts[0]) // provider — structural
				addStruct(parts[2]) // kind     — structural
				add(parts[1])       // account  — identifier
				addComponentsOf(parts[3], add)
			}
			return
		}
		if identifyingKeys[keyHint] && hasLetter(x) {
			addComponentsOf(x, add)
		}
	}
}

func addComponentsOf(s string, add func(string)) {
	add(s)
	if i := strings.IndexByte(s, '@'); i > 0 {
		add(s[:i])
		add(s[i+1:])
		if strings.HasSuffix(s[i+1:], ".iam.gserviceaccount.com") {
			add(strings.TrimSuffix(s[i+1:], ".iam.gserviceaccount.com"))
		}
	}
}

func collectStructural(v any, add func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			collectStructural(e, add)
		}
	case []any:
		for _, e := range x {
			collectStructural(e, add)
		}
	case string:
		add(x)
		for _, lbl := range strings.FieldsFunc(x, func(r rune) bool {
			return r == '.' || r == '/' || r == ':'
		}) {
			add(lbl)
		}
	}
}

func extractTags(v any, add func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			extractTags(e, add)
		}
	case []any:
		for _, e := range x {
			extractTags(e, add)
		}
	case string:
		add(x)
	}
}

// leakScan returns every real token found surviving in an output file.
func leakScan(out map[string][]byte, real map[string]bool) []LeakHit {
	tokens := make([]string, 0, len(real))
	for tkn := range real {
		tokens = append(tokens, tkn)
	}
	sort.Strings(tokens)
	var hits []LeakHit
	seen := map[string]bool{}
	for name, b := range out {
		text := string(b)
		for _, tkn := range tokens {
			if strings.Contains(text, tkn) {
				key := name + "\x00" + tkn
				if !seen[key] {
					seen[key] = true
					hits = append(hits, LeakHit{File: name, Token: tkn})
				}
			}
		}
	}
	return hits
}

// isomorphism verifies the output preserves graph structure (counts + type histograms +
// edge-endpoint referential integrity). Returns a list of discrepancies (empty = ok).
func isomorphism(in, out map[string][]byte) []string {
	var errs []string
	check := func(file, typeKey string) map[string]int {
		hist := map[string]int{}
		for _, line := range splitNDJSON(out[file]) {
			var m map[string]any
			if json.Unmarshal(line, &m) == nil {
				hist[str(m[typeKey])]++
			}
		}
		return hist
	}
	count := func(files map[string][]byte, file string) int { return len(splitNDJSON(files[file])) }

	for _, f := range []string{"graph/nodes.ndjson", "graph/edges.ndjson", "graph/paths.ndjson"} {
		if a, b := count(in, f), count(out, f); a != b {
			errs = append(errs, f+": count "+itoa(a)+" -> "+itoa(b))
		}
	}
	// node_type + edge type histograms preserved
	inN, outN := histogram(in, "graph/nodes.ndjson", "node_type"), check("graph/nodes.ndjson", "node_type")
	if !sameHist(inN, outN) {
		errs = append(errs, "node_type histogram changed")
	}
	inE, outE := histogram(in, "graph/edges.ndjson", "type"), check("graph/edges.ndjson", "type")
	if !sameHist(inE, outE) {
		errs = append(errs, "edge type histogram changed")
	}
	// every edge endpoint resolves to an output node id
	ids := map[string]bool{}
	for _, line := range splitNDJSON(out["graph/nodes.ndjson"]) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			ids[str(m["node_id"])] = true
		}
	}
	for _, line := range splitNDJSON(out["graph/edges.ndjson"]) {
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		for _, ep := range []string{"source", "target"} {
			if v := str(m[ep]); v != "" && !ids[v] {
				errs = append(errs, "dangling edge "+ep+": "+v)
			}
		}
	}
	return errs
}

func histogram(files map[string][]byte, file, typeKey string) map[string]int {
	hist := map[string]int{}
	for _, line := range splitNDJSON(files[file]) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			hist[str(m[typeKey])]++
		}
	}
	return hist
}

func sameHist(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
