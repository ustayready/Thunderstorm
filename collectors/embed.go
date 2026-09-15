// Package assets bundles the collector's declarative data INTO the binary so a
// built `thunderstorm` runs anywhere, not just from inside the repo tree.
//
// RAGE is the source of truth. `collectors/rage/` is the vendored snapshot of
// RAGE (github.com/trustedsec/rage) and is the DEFAULT catalog location: it is
// embedded into the binary, so a built `thunderstorm` runs anywhere with no RAGE
// checkout on disk. Set $RAGE_ROOT to read a live checkout instead (e.g. when
// developing RAGE itself). `COMPATIBILITY.yaml` is the collector's own version
// contract.
//
// Layout inside the embedded FS:
//
//	COMPATIBILITY.yaml
//	rage/providers/<provider>.json
//	rage/exposure-db/<provider>.json + vocabulary.json
//	rage/vocab/<node|edge>-types.json + conditions.json
//
// Refresh the vendored snapshot from a live RAGE checkout ($RAGE_ROOT):
//
//	RAGE_ROOT=/path/to/rage go generate ./...   (or: make RAGE_ROOT=/path/to/rage)
//
//go:generate sh scripts/vendor-rage.sh
package assets

import (
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

//go:embed COMPATIBILITY.yaml
//go:embed rage
var files embed.FS

// FS is the embedded asset tree, rooted at the collectors module directory.
var FS embed.FS = files

// RageRoot returns a live RAGE checkout to read instead of the embedded snapshot,
// or "" to use the default (the vendored collectors/rage snapshot baked into the
// binary). Set $RAGE_ROOT to override — there is no implicit home-directory path.
func RageRoot() string {
	return os.Getenv("RAGE_ROOT")
}

// ReadRAGE returns a RAGE registry file (e.g. "providers/aws.json", "exposure-db/aws.json"):
// a live $RAGE_ROOT checkout when set, else the vendored snapshot embedded in the binary.
func ReadRAGE(rel string) ([]byte, error) {
	if root := RageRoot(); root != "" {
		if b, err := os.ReadFile(filepath.Join(root, rel)); err == nil {
			return b, nil
		}
	}
	return files.ReadFile("rage/" + rel)
}

// RageVersion returns the RAGE spec_version the collector is running against —
// read live from the providers registry ($RAGE_ROOT when set, else the vendored
// snapshot). This is the single number that pins Thunderstorm to a RAGE release:
// it is stamped into every emitted bundle and reported by `thunderstorm version`.
func RageVersion() string {
	b, err := ReadRAGE("providers/aws.json")
	if err != nil {
		return "unknown"
	}
	var doc struct {
		SpecVersion string `json:"spec_version"`
	}
	if json.Unmarshal(b, &doc) != nil || strings.TrimSpace(doc.SpecVersion) == "" {
		return "unknown"
	}
	return doc.SpecVersion
}
