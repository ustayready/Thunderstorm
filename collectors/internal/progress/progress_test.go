package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestComma(t *testing.T) {
	cases := map[int]string{0: "0", 42: "42", 1000: "1,000", 60861: "60,861", -12345: "-12,345"}
	for in, want := range cases {
		if got := comma(in); got != want {
			t.Errorf("comma(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderGlyphs(t *testing.T) {
	cases := []struct {
		pct, n int
		want   string
	}{
		{0, 4, "░░░░"},
		{50, 4, "██░░"},
		{100, 4, "████"},
		{150, 4, "████"}, // clamps
		{-5, 4, "░░░░"},  // clamps
	}
	for _, c := range cases {
		if got := renderGlyphs(c.pct, c.n); got != c.want {
			t.Errorf("renderGlyphs(%d,%d) = %q, want %q", c.pct, c.n, got, c.want)
		}
	}
}

// TestRenderBar checks a percentage line: real percent, thousands separators, and
// the trailing note all appear.
func TestRenderBar(t *testing.T) {
	b := New(&bytes.Buffer{}, "collect", 12, nil)
	b.start = time.Now().Add(-12 * time.Second)
	line := b.render(Snapshot{Done: 842, Total: 1750, Note: "60,861 artifacts"}, 0)
	for _, want := range []string{"collect", "48%", "842/1,750", "60,861 artifacts"} {
		if !strings.Contains(line, want) {
			t.Errorf("render bar %q missing %q", line, want)
		}
	}
}

// TestRenderSpinner checks the indeterminate (Total<=0) form shows a spinner frame
// and the note, not a percentage.
func TestRenderSpinner(t *testing.T) {
	b := New(&bytes.Buffer{}, "facts", 12, nil)
	b.start = time.Now()
	line := b.render(Snapshot{Note: "collecting facts"}, 2)
	if strings.Contains(line, "%") {
		t.Errorf("spinner line should have no percent: %q", line)
	}
	if !strings.Contains(line, "collecting facts") {
		t.Errorf("spinner line missing note: %q", line)
	}
}

// TestNonTTYEmitsLine verifies the non-terminal path writes a newline-terminated
// progress line (so piped/nohup logs still show forward motion).
func TestNonTTYEmitsLine(t *testing.T) {
	var buf bytes.Buffer
	done := 0
	b := New(&buf, "collect", 12, func() Snapshot {
		done += 100
		return Snapshot{Done: done, Total: 1000, Note: comma(done) + " artifacts"}
	})
	// buf is not an *os.File, so isTTY is false -> non-TTY line path.
	if b.tty {
		t.Fatal("bytes.Buffer must not be detected as a TTY")
	}
	b.Start()
	time.Sleep(30 * time.Millisecond)
	b.Stop()
	out := buf.String()
	if !strings.Contains(out, "collect") || !strings.HasSuffix(out, "\n") {
		t.Errorf("expected a newline-terminated collect line, got %q", out)
	}
}
