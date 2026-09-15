// Package output writes the Evidence Bundle: an inspectable NDJSON directory
// (full/) plus a compact upload.zip for the web UI.
package output

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"thunderstorm/collector/internal/model"
)

// Bundle is a writer over a bundle directory. NDJSON shard writers are
// concurrency-safe; large blobs go under blobs/ by content hash (excluded from
// the upload tier).
type Bundle struct {
	Dir string

	fresh bool // truncate shards on first open (fresh run); append when resuming
	mu    sync.Mutex
	files map[string]*os.File // relpath -> open file
}

// New creates the bundle directory skeleton. fresh=true truncates NDJSON shards
// on first write so re-running into the same dir replaces (not accumulates)
// data; fresh=false appends (for --resume into a prior bundle).
func New(dir string, fresh bool) (*Bundle, error) {
	// A fresh run clears prior data dirs entirely, so stale shards from an
	// earlier run (even ones not re-written this run) never linger.
	if fresh {
		for _, sub := range []string{"inventory", "facts", "exposure", "blobs"} {
			if err := os.RemoveAll(filepath.Join(dir, sub)); err != nil {
				return nil, err
			}
		}
	}
	for _, sub := range []string{"inventory", "facts", "exposure", "ledger", "blobs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return &Bundle{Dir: dir, fresh: fresh, files: map[string]*os.File{}}, nil
}

// AppendJSON writes one NDJSON record to the named shard (relative to the bundle
// dir, e.g. "inventory/aws-ec2.ndjson"). Safe for concurrent callers.
func (b *Bundle) AppendJSON(relpath string, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.files[relpath]
	if f == nil {
		p := filepath.Join(b.Dir, relpath)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if b.fresh {
			flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC // first open of a fresh run replaces
		}
		f, err = os.OpenFile(p, flags, 0o644)
		if err != nil {
			return err
		}
		b.files[relpath] = f
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// WriteFile writes a whole file (manifest, report) relative to the bundle dir.
func (b *Bundle) WriteFile(relpath string, data []byte) error {
	p := filepath.Join(b.Dir, relpath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// WriteManifest serializes the bundle manifest.
func (b *Bundle) WriteManifest(m model.Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return b.WriteFile("manifest.json", data)
}

// Close flushes and closes all open shard files.
func (b *Bundle) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var firstErr error
	for _, f := range b.files {
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	b.files = map[string]*os.File{}
	return firstErr
}

// Zip packages the compact upload tier: everything EXCEPT blobs/ (size
// discipline). Returns the zip path and its byte size. includeBlobs bundles the
// raw evidence too (offline use only).
func (b *Bundle) Zip(zipPath string, includeBlobs bool) (int64, error) {
	zf, err := os.Create(zipPath)
	if err != nil {
		return 0, err
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)

	err = filepath.Walk(b.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(b.Dir, path)
		if err != nil {
			return err
		}
		if !includeBlobs && strings.HasPrefix(filepath.ToSlash(rel), "blobs/") {
			return nil // exclude large raw evidence from the upload tier
		}
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(w, src)
		return err
	})
	if err != nil {
		zw.Close()
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	st, err := os.Stat(zipPath)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// HumanSize renders a byte count compactly.
func HumanSize(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
