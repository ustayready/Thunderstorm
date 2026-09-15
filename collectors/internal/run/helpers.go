package run

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"thunderstorm/collector/internal/model"
)

// deniedPermissions maps denied ledger rows to the IAM actions the run couldn't
// exercise (operation names ARE the action names). This is the expected-gap set.
func deniedPermissions(rows []model.LedgerRow) []string {
	set := map[string]struct{}{}
	for _, r := range rows {
		if r.Status == model.OutcomeDenied {
			set[r.Operation] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func parseCSVSet(s string) map[string]bool {
	if s == "" {
		return nil
	}
	set := map[string]bool{}
	for _, p := range splitComma(s) {
		if p != "" {
			set[p] = true
		}
	}
	return set
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	return append(out, cur)
}

// FindRepoRoot walks up from cwd to the dir containing collectors/COMPATIBILITY.yaml.
func FindRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "collectors", "COMPATIBILITY.yaml")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not found from cwd upward")
		}
		dir = parent
	}
}
