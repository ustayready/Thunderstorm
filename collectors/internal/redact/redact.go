package redact

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Options configure a run.
type Options struct {
	AuditPath string // optional path to write the JSON audit report
}

// Run redacts the engagement zip at inPath and writes an isomorphic, de-identified zip
// to outPath. It is fail-closed: if the self-audit finds any surviving real identifier or
// a structural mismatch, it writes a *.quarantine.zip instead and returns an error.
func Run(inPath, outPath string, opts Options) (*AuditReport, error) {
	files, err := readZip(inPath)
	if err != nil {
		return nil, err
	}
	if _, ok := files["graph/nodes.ndjson"]; !ok {
		return nil, fmt.Errorf("%s is not an engagement.zip (missing graph/nodes.ndjson)", inPath)
	}

	reg, err := NewRegistry()
	if err != nil {
		return nil, err
	}
	t := newTransformer(reg)

	// Pass 1 — build the registry from nodes + engagement.json.
	if b, ok := files["engagement.json"]; ok {
		if m := parseObject(b); m != nil {
			t.registerRecord(m)
		}
	}
	for _, line := range splitNDJSON(files["graph/nodes.ndjson"]) {
		if m := parseObject(line); m != nil {
			t.registerRecord(m)
		}
	}
	reg.Prepare()

	// Pass 2 — apply to every file.
	out := map[string][]byte{}
	report := &AuditReport{MappedByType: map[string]int{}}
	for name, b := range files {
		switch {
		case name == "engagement.json":
			nb, err := transformObject(t, b)
			if err != nil {
				return nil, fmt.Errorf("engagement.json: %w", err)
			}
			out[name] = nb
		case strings.HasPrefix(name, "graph/") && strings.HasSuffix(name, ".ndjson"),
			strings.HasPrefix(name, "exposure/") && strings.HasSuffix(name, ".ndjson"):
			nb, err := transformNDJSON(t, b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			out[name] = nb
		case strings.HasPrefix(name, "blobs/"):
			sn, sb := t.syntheticBlob(name, len(b))
			out[sn] = sb
			report.SyntheticBlob++
		default:
			report.DroppedFiles = append(report.DroppedFiles, name) // unknown → dropped (safe)
		}
	}

	// Audit — independent real-token extraction, leak scan, isomorphism.
	real := extractRealTokens(files)
	report.RealTokens = len(real)
	report.LeakHits = leakScan(out, real)
	report.Isomorphism = isomorphism(files, out)
	report.MappedByType = mappedByPrefix(reg)
	report.Pass = len(report.LeakHits) == 0 && len(report.Isomorphism) == 0

	dest := outPath
	if !report.Pass {
		dest = strings.TrimSuffix(outPath, ".zip") + ".quarantine.zip"
	}
	if err := writeZip(dest, out); err != nil {
		return report, err
	}
	if opts.AuditPath != "" {
		rb, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(opts.AuditPath, append(rb, '\n'), 0o644); err != nil {
			return report, err
		}
	}
	if !report.Pass {
		return report, fmt.Errorf("audit FAILED: %d leak(s), %d structural error(s) — wrote %s",
			len(report.LeakHits), len(report.Isomorphism), dest)
	}
	return report, nil
}

func (t *transformer) syntheticBlob(origName string, n int) (string, []byte) {
	name := "blobs/blob-" + t.slug("blob", origName, 4) + ".stub"
	body, _ := json.Marshal(map[string]any{
		"synthetic": true, "note": "blob body removed by redactor", "orig_bytes": n,
	})
	return name, append(body, '\n')
}

// ---- record transforms ----------------------------------------------------------------

func transformObject(t *transformer, b []byte) ([]byte, error) {
	m := parseObject(b)
	if m == nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	nb, err := json.MarshalIndent(t.transformMap(m), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(nb, '\n'), nil
}

func transformNDJSON(t *transformer, b []byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, line := range splitNDJSON(b) {
		m := parseObject(line)
		if m == nil {
			return nil, fmt.Errorf("invalid ndjson line")
		}
		nb, err := json.Marshal(t.transformMap(m))
		if err != nil {
			return nil, err
		}
		buf.Write(nb)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func mappedByPrefix(r *Registry) map[string]int {
	out := map[string]int{}
	for f := range r.fakes {
		p := f
		if i := strings.IndexByte(f, '-'); i > 0 {
			p = f[:i]
		} else if strings.Contains(f, ".") || strings.Contains(f, ":") {
			p = "structured"
		}
		out[p]++
	}
	return out
}

// ---- zip + json helpers ---------------------------------------------------------------

func readZip(path string) (map[string][]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	files := map[string][]byte{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		files[f.Name] = b
	}
	return files, nil
}

func writeZip(path string, files map[string][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			return err
		}
		if _, err := w.Write(files[n]); err != nil {
			return err
		}
	}
	return zw.Close()
}

func parseObject(b []byte) map[string]any {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func splitNDJSON(b []byte) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			out = append(out, line)
		}
	}
	return out
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }
