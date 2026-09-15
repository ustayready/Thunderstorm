// Package view opens Blaze Lite — the self-contained, offline attack-path
// viewer that ships embedded in the thunderstorm binary. With an engagement it
// injects the graph inline and opens the result in the default browser; without
// one it opens the viewer showing a "drag a file here" prompt. No server: the
// viewer is a single HTML file that runs entirely over file://.
package view

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// blaze-lite.html is the built viewer, mirrored from ../../../viewer/blaze-lite.html
// by `make` (see the repo Makefile). Committed so a bare `go build` works too.
//
//go:embed blaze-lite.html
var viewerHTML []byte

// the empty placeholder the viewer looks for on load; we fill it with the
// engagement so the page auto-loads (base64 keeps the payload </script>-safe).
const placeholder = `<script type="application/json" id="blaze-embedded"></script>`

// Run writes the viewer to a temp file (with the engagement injected when inPath
// is given) and opens it in the default browser.
func Run(inPath string) error {
	html := viewerHTML
	if inPath != "" {
		data, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("read --in %q: %w", inPath, err)
		}
		html, err = inject(viewerHTML, filepath.Base(inPath), data)
		if err != nil {
			return err
		}
	}
	tmp, err := writeTemp(html)
	if err != nil {
		return err
	}
	fmt.Printf("  %-12s %s\n", "viewer", tmp)
	if inPath != "" {
		fmt.Printf("  %-12s %s\n", "engagement", inPath)
	} else {
		fmt.Printf("  %-12s %s\n", "note", "no --in given — drag a .ndjson or .zip into the window")
	}
	if err := openBrowser(tmp); err != nil {
		fmt.Printf("  %-12s open it manually: %s\n", "note", tmp)
		return err
	}
	return nil
}

// inject replaces the placeholder <script> with the base64-embedded engagement
// (the raw file bytes — a .zip or .ndjson — the viewer parses client-side).
func inject(html []byte, filename string, data []byte) ([]byte, error) {
	if !strings.Contains(string(html), placeholder) {
		return nil, fmt.Errorf("viewer is missing the blaze-embedded placeholder (stale build?)")
	}
	payload, err := json.Marshal(struct {
		Filename string `json:"filename"`
		B64      string `json:"b64"`
	}{filename, base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		return nil, err
	}
	filled := `<script type="application/json" id="blaze-embedded">` + string(payload) + `</script>`
	return []byte(strings.Replace(string(html), placeholder, filled, 1)), nil
}

func writeTemp(html []byte) (string, error) {
	f, err := os.CreateTemp("", "blaze-lite-*.html")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(html); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// openBrowser opens path in the OS default handler. Best-effort across platforms.
func openBrowser(path string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", path).Start()
	default: // linux, *bsd
		return exec.Command("xdg-open", path).Start()
	}
}
