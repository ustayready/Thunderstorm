// Package progress renders live, accurate progress for the long collection phases.
//
// A Bar polls a caller-supplied snapshot on a ticker and repaints ONE line in
// place when stdout is a TTY, or emits a periodic newline-terminated line when it
// is not (piped / nohup / CI) so a log file still shows forward motion. The
// percentage is real: it is done/total where total is known up front (seed tasks
// for collect, catalog sites for exposure) — never a fabricated estimate. When
// total is unknown (<=0) it shows a spinner with a live count instead of a bar.
//
// A Bar owns only its transient live line. When the phase ends the caller stops
// the Bar (which erases the live line) and prints the permanent summary line
// itself, so the on-screen history stays clean and aligned.
package progress

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshot is the live state of a phase. Done/Total drive the bar; Note is the
// trailing human detail (e.g. "60,861 artifacts · 12 denied"). Total<=0 renders a
// spinner (indeterminate work) with Done shown as a running count.
type Snapshot struct {
	Done  int
	Total int
	Note  string
}

// Bar drives one phase's live line.
type Bar struct {
	w     io.Writer
	label string
	width int // label column width, so the live line aligns with final summary lines
	poll  func() Snapshot

	tty       bool
	cols      int
	repaint   time.Duration // TTY repaint cadence
	lineEvery time.Duration // non-TTY: how often to emit a progress line

	start   time.Time
	stopCh  chan struct{}
	doneCh  chan struct{}
	lastLen int

	mu      sync.Mutex
	stopped bool
}

// New creates a Bar that will render `label` (padded to width) followed by a live
// bar/spinner driven by poll(). It does not start rendering until Start is called.
func New(w io.Writer, label string, width int, poll func() Snapshot) *Bar {
	return &Bar{
		w:         w,
		label:     label,
		width:     width,
		poll:      poll,
		tty:       isTTY(w),
		cols:      terminalCols(),
		repaint:   125 * time.Millisecond,
		lineEvery: 15 * time.Second,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start begins rendering in a background goroutine. Safe to call once.
func (b *Bar) Start() {
	b.start = time.Now()
	go b.loop()
}

func (b *Bar) loop() {
	defer close(b.doneCh)
	spin := 0
	if b.tty {
		b.paint(spin)
		t := time.NewTicker(b.repaint)
		defer t.Stop()
		for {
			select {
			case <-b.stopCh:
				return
			case <-t.C:
				spin++
				b.paint(spin)
			}
		}
	}
	// Non-TTY: emit an opening line immediately, then one every lineEvery.
	b.line()
	t := time.NewTicker(b.lineEvery)
	defer t.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-t.C:
			b.line()
		}
	}
}

// Stop halts rendering and erases the transient TTY line. The caller prints the
// permanent summary line afterwards. Idempotent.
func (b *Bar) Stop() {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	b.mu.Unlock()

	close(b.stopCh)
	<-b.doneCh
	if b.tty && b.lastLen > 0 {
		// Erase the live line so the caller's summary line takes its place.
		fmt.Fprintf(b.w, "\r%s\r", strings.Repeat(" ", b.lastLen))
	}
}

// Log prints a permanent line ABOVE the live bar without corrupting it: on a TTY
// it erases the transient bar line, writes msg, then the next tick repaints the
// bar beneath it; off a TTY it just writes the line. Use for streaming events
// (e.g. "a new resource type started") while a phase is in progress.
func (b *Bar) Log(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tty && b.lastLen > 0 {
		fmt.Fprintf(b.w, "\r%s\r", strings.Repeat(" ", b.lastLen))
		b.lastLen = 0
	}
	fmt.Fprintln(b.w, msg)
}

// paint redraws the in-place TTY line.
func (b *Bar) paint(spin int) {
	s := b.poll()
	line := b.render(s, spin)
	if b.cols > 2 && len(line) > b.cols-1 {
		line = line[:b.cols-1]
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Pad to erase any remnant of a previously longer line (e.g. after Log reset it).
	pad := ""
	if len(line) < b.lastLen {
		pad = strings.Repeat(" ", b.lastLen-len(line))
	}
	fmt.Fprintf(b.w, "\r%s%s", line, pad)
	b.lastLen = len(line)
}

// line emits a single newline-terminated progress line (non-TTY path).
func (b *Bar) line() {
	s := b.poll()
	b.mu.Lock()
	fmt.Fprintln(b.w, b.render(s, 0))
	b.mu.Unlock()
}

var spinFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// render builds the phase line for a snapshot: either a percentage bar (known
// total) or a spinner with a running count (unknown total).
func (b *Bar) render(s Snapshot, spin int) string {
	elapsed := fmtDur(time.Since(b.start))
	head := fmt.Sprintf("  %-*s ", b.width, b.label)
	if s.Total > 0 {
		pct := 0
		if s.Total > 0 {
			pct = int(float64(s.Done) / float64(s.Total) * 100)
		}
		if pct > 100 {
			pct = 100
		}
		bar := renderGlyphs(pct, 13)
		body := fmt.Sprintf("%3d%% %s  %s/%s", pct, bar, comma(s.Done), comma(s.Total))
		if s.Note != "" {
			body += " · " + s.Note
		}
		return fmt.Sprintf("%s%s   %s", head, body, elapsed)
	}
	frame := spinFrames[spin%len(spinFrames)]
	body := string(frame)
	if s.Note != "" {
		body += "  " + s.Note
	} else if s.Done > 0 {
		body += "  " + comma(s.Done)
	}
	return fmt.Sprintf("%s%s   %s", head, body, elapsed)
}

// renderGlyphs draws an n-cell bar filled to pct%.
func renderGlyphs(pct, n int) string {
	fill := pct * n / 100
	if fill > n {
		fill = n
	}
	if fill < 0 {
		fill = 0
	}
	return strings.Repeat("█", fill) + strings.Repeat("░", n-fill)
}

// comma renders an int with thousands separators (e.g. 60861 -> "60,861").
func comma(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(c)
	}
	if neg {
		return "-" + out.String()
	}
	return out.String()
}

// fmtDur renders a duration compactly: sub-minute to 0.1s, else m/s.
func fmtDur(d time.Duration) string {
	if d < time.Minute {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// terminalCols returns a best-effort terminal width for truncation. Uses $COLUMNS
// when set (no extra deps / no ioctl); defaults to a safe 100.
func terminalCols() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return 100
}
