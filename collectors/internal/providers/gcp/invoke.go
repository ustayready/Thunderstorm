package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Record is one result item, flat keys the registry manifest references.
type Record = map[string]any

// opSpec is a data-driven REST endpoint description for one operation. Path holds
// {project} / {location} / {param} placeholders substituted at invoke time.
// ItemsField is the response key holding the result array (dotted for nesting);
// empty means the whole response is a single record (get / getIamPolicy).
type opSpec struct {
	BaseURL    string // e.g. https://iam.googleapis.com/v1
	Method     string // GET | POST
	Path       string // e.g. /projects/{project}/serviceAccounts
	ItemsField string // e.g. accounts ; "" => single-object response
	Body       string // request body template for POST (e.g. {} for getIamPolicy)
}

// gcpOps is the operation registry, populated by register() from endpoints.go and
// the generated per-service endpoint files. Mirrors AWS's operations map.
var gcpOps = map[string]opSpec{}

func register(op string, spec opSpec) { gcpOps[op] = spec }

// fixedGlobalLoc: list ops whose collection is global-only and reject "-".
var fixedGlobalLoc = map[string]bool{
	"iam.projects.locations.workloadIdentityPools.list": true,
}

// isNotFound reports whether a request error is a 404 / NOT_FOUND.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, " 404 ") || strings.Contains(s, "NOT_FOUND") || strings.Contains(s, ": 404")
}

// HasOp reports whether an operation has an endpoint spec (validates manifests).
func HasOp(op string) bool { _, ok := gcpOps[op]; return ok }

// Invoke dispatches a registry operation by name against the GCP REST API. region
// is the location for regional resources ("" for global/project-level). Handles
// {project}/{location}/{param} substitution and nextPageToken pagination.
func (c *Client) Invoke(ctx context.Context, op, region string, params map[string]string) ([]Record, error) {
	spec, ok := gcpOps[op]
	if !ok {
		return nil, fmt.Errorf("no endpoint spec for operation %q", op)
	}
	// A handful of "global-only" collections (e.g. Workload Identity Federation
	// pools) live under locations/global and reject the "-" all-locations wildcard.
	if region == "" && fixedGlobalLoc[op] {
		region = "global"
	}
	base, err := c.buildURL(spec, region, params)
	if err != nil {
		return nil, err
	}
	method := spec.Method
	if method == "" {
		method = "GET"
	}

	var recs []Record
	pageToken := ""
	for {
		u := base
		if pageToken != "" {
			u = addQuery(u, "pageToken", pageToken)
		}
		var body []byte
		if method == "POST" {
			b := spec.Body
			if b == "" {
				b = "{}"
			}
			body, err = c.do(ctx, "POST", u, strings.NewReader(b))
		} else {
			body, err = c.do(ctx, "GET", u, nil)
		}
		if err != nil {
			// A 404 means the resource / parent doesn't exist: for a LIST op that's an
			// empty result, for a GET/access probe that's simply no hit. Endpoints are
			// discovery-derived so a 404 is never a wrong URL — treat it as empty, not
			// an error, so the ledger stays honest (no phantom failures).
			if isNotFound(err) {
				return recs, nil
			}
			return recs, err
		}

		if spec.ItemsField == "" {
			// single-object response (get / getIamPolicy): one record, no paging
			var rec Record
			if len(body) > 0 && json.Unmarshal(body, &rec) == nil {
				recs = append(recs, rec)
			}
			return recs, nil
		}

		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			return recs, fmt.Errorf("%s: decoding response: %w", op, err)
		}
		for _, item := range extractItems(envelope, spec.ItemsField) {
			if m, ok := item.(map[string]any); ok {
				recs = append(recs, Record(m))
			}
		}
		next, _ := envelope["nextPageToken"].(string)
		if next == "" {
			break
		}
		pageToken = next
	}
	return recs, nil
}

// buildURL substitutes placeholders and appends the project query for APIs that
// need it (Storage). Unresolved required placeholders are a hard error.
func (c *Client) buildURL(spec opSpec, region string, params map[string]string) (string, error) {
	path := spec.Path
	// Global scope (region==""): GCP list ops accept "-" as the all-locations
	// wildcard, so a location-templated path still resolves for a global run.
	loc := region
	if loc == "" {
		loc = "-"
	}
	repl := map[string]string{"project": c.project, "location": loc, "region": loc, "zone": loc}
	for k, v := range params {
		repl[k] = v
	}
	var missing []string
	path = substitute(path, repl, &missing)
	if len(missing) > 0 {
		return "", fmt.Errorf("unresolved path params %v for %s%s", missing, spec.BaseURL, spec.Path)
	}
	return spec.BaseURL + path, nil
}

// substitute replaces {key} tokens; records any left unresolved.
func substitute(s string, repl map[string]string, missing *[]string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			b.WriteString(s)
			break
		}
		key := s[i+1 : i+j]
		b.WriteString(s[:i])
		if v, ok := repl[key]; ok && v != "" {
			// resource names embed slashes; keep them (already URL-path-safe)
			b.WriteString(v)
		} else {
			*missing = append(*missing, key)
		}
		s = s[i+j+1:]
	}
	return b.String()
}

// extractItems walks a dotted ItemsField (supports aggregatedList: a map of
// scope -> {<items>: [...]} when the field ends in a wildcard segment).
func extractItems(env map[string]any, field string) []any {
	// aggregatedList form: items.*.<sub> — items is a map keyed by zone/region
	if strings.HasPrefix(field, "items.*.") {
		sub := strings.TrimPrefix(field, "items.*.")
		var out []any
		if m, ok := env["items"].(map[string]any); ok {
			for _, v := range m {
				if scoped, ok := v.(map[string]any); ok {
					if arr, ok := scoped[sub].([]any); ok {
						out = append(out, arr...)
					}
				}
			}
		}
		return out
	}
	cur := any(env)
	for _, seg := range strings.Split(field, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[seg]
	}
	if arr, ok := cur.([]any); ok {
		return arr
	}
	return nil
}

func addQuery(u, k, v string) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + k + "=" + url.QueryEscape(v)
}
