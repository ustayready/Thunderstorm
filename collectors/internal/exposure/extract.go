package exposure

import (
	"fmt"
	"strings"
)

// Extract pulls every scalar value at `path` from a jsonified API response
// (map[string]any / []any). It is a small JMESPath-lite supporting exactly the
// shapes the exposure catalogs use:
//
//	A.B.C                dotted map descent
//	A[].B                iterate a slice, then descend
//	A[].B[].C            nested slices
//	Parameters.<value>   map wildcard — <...> emits ALL map values
//	OpsItem.Data.<key>.V map wildcard then descend
//	X / Y                alternation — try each path, collect all (e.g. SecretString / SecretBinary)
//
// Empty/blank results are dropped by the caller (Assess).
func Extract(resp any, path string) []string {
	var out []string
	for _, alt := range strings.Split(path, "/") {
		alt = strings.TrimSpace(alt)
		if alt == "" {
			continue
		}
		nodes := walk([]any{resp}, splitSegs(alt))
		for _, n := range nodes {
			if s, ok := scalar(n); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func splitSegs(p string) []string {
	var segs []string
	for _, s := range strings.Split(p, ".") {
		s = strings.TrimSpace(s)
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

func walk(nodes []any, segs []string) []any {
	if len(segs) == 0 {
		return nodes
	}
	seg, rest := segs[0], segs[1:]
	iterate := strings.HasSuffix(seg, "[]")
	key := strings.TrimSuffix(seg, "[]")
	var next []any
	for _, n := range nodes {
		switch {
		case key == "": // bare "[]"
			next = append(next, asSlice(n)...)
		case strings.HasPrefix(key, "<"): // wildcard: all values of a map
			if m, ok := n.(map[string]any); ok {
				for _, v := range m {
					next = append(next, v)
				}
			}
		default:
			m, ok := n.(map[string]any)
			if !ok {
				continue
			}
			v, ok := m[key]
			if !ok {
				continue
			}
			if iterate {
				next = append(next, asSlice(v)...)
			} else {
				next = append(next, v)
			}
		}
	}
	return walk(next, rest)
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

// scalar returns a string form of a leaf value (string/number/bool). Maps and
// slices are not leaves — return ok=false so structural nodes aren't emitted.
func scalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return fmt.Sprintf("%v", t), true
	case float64:
		return fmt.Sprintf("%v", t), true
	case int, int64:
		return fmt.Sprintf("%v", t), true
	default:
		return "", false
	}
}
