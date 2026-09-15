// Package bundle reads an Evidence Bundle directory produced by the collector.
// The bundle's NDJSON files are the contract between collector and engine.
package bundle

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"thunderstorm/engine/internal/model"
)

// Bundle is an in-memory view of one Evidence Bundle's `full/` tree.
type Bundle struct {
	Dir       string
	Manifest  model.Manifest
	Artifacts []model.Artifact
	Facts     []model.Fact
	Hits      []model.ExposureHit
}

// Load reads the bundle rooted at dir. dir may point at the bundle root (which
// contains `full/`) or directly at a `full/` tree.
func Load(dir string) (*Bundle, error) {
	root := dir
	if _, err := os.Stat(filepath.Join(dir, "full")); err == nil {
		root = filepath.Join(dir, "full")
	}
	b := &Bundle{Dir: root}

	if err := readJSON(filepath.Join(root, "manifest.json"), &b.Manifest); err != nil {
		// manifest is optional for M4a (some test bundles omit it); warn via zero value.
		b.Manifest = model.Manifest{}
	}

	if err := eachNDJSON(filepath.Join(root, "inventory"), func(line []byte) error {
		var a model.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			return err
		}
		b.Artifacts = append(b.Artifacts, a)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("reading inventory: %w", err)
	}

	if err := eachNDJSON(filepath.Join(root, "facts"), func(line []byte) error {
		var f model.Fact
		if err := json.Unmarshal(line, &f); err != nil {
			return err
		}
		b.Facts = append(b.Facts, f)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("reading facts: %w", err)
	}

	// hits live in exposure/hits.ndjson (single file, not a dir).
	_ = eachLine(filepath.Join(root, "exposure", "hits.ndjson"), func(line []byte) error {
		var h model.ExposureHit
		if err := json.Unmarshal(line, &h); err != nil {
			return err
		}
		b.Hits = append(b.Hits, h)
		return nil
	})

	return b, nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// eachNDJSON walks every *.ndjson file under a directory, calling fn per line.
// A missing directory is not an error (that fact kind simply wasn't produced).
func eachNDJSON(dir string, fn func([]byte) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".ndjson" {
			continue
		}
		if err := eachLine(filepath.Join(dir, e.Name()), fn); err != nil {
			return err
		}
	}
	return nil
}

func eachLine(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 32*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		buf := make([]byte, len(line))
		copy(buf, line)
		if err := fn(buf); err != nil {
			return err
		}
	}
	return sc.Err()
}
