package assets

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedRAGEInSync guards against drift between the vendored RAGE snapshot embedded in the
// binary (collectors/rage) and a live RAGE source of truth ($RAGE_ROOT). If this fails, run
// `RAGE_ROOT=/path/to/rage go generate ./...` from the collectors module to refresh the snapshot.
// When $RAGE_ROOT is unset the test is skipped (CI/offline builds rely on the committed snapshot).
func TestEmbeddedRAGEInSync(t *testing.T) {
	root := RageRoot()
	if root == "" {
		t.Skip("no RAGE checkout")
	}
	files := []string{
		"providers/aws.json", "providers/gcp.json", "providers/azure.json",
		"exposure-db/aws.json", "exposure-db/gcp.json", "exposure-db/azure.json",
		"exposure-db/vocabulary.json",
		"vocab/node-types.json", "vocab/edge-types.json", "vocab/conditions.json",
	}
	for _, rel := range files {
		want, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Skipf("RAGE not fully present (%s): %v", rel, err)
		}
		got, err := files_ReadFile("rage/" + rel)
		if err != nil {
			t.Errorf("%s missing from embedded RAGE snapshot — run `go generate ./...`", rel)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from RAGE source — run `go generate ./...`", rel)
		}
	}
}

// files_ReadFile reads from the embedded FS (test helper so we compare against the snapshot, not disk).
func files_ReadFile(p string) ([]byte, error) { return files.ReadFile(p) }
