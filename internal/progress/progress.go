// Package progress draws a one-line spinner with a counter on a terminal,
// for the slow parts safe-install does itself (registry lookups, code scans,
// downloads). It draws nothing unless the output is an interactive terminal.
package progress

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bar is one progress line. A nil *Bar is valid and does nothing, so
// callers never need to check whether progress is shown.
type Bar struct {
	w     io.Writer
	label string
	total atomic.Int64
	done  atomic.Int64

	stop chan struct{}
	wg   sync.WaitGroup
	last int // width of the last line drawn
}

// Terminal reports whether w is an interactive terminal on which a
// progress line can be redrawn.
func Terminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Start shows "label done/total" on w and redraws it until Stop. It returns
// nil (no output) when show is false or w is not a terminal.
func Start(w io.Writer, show bool, label string, total int) *Bar {
	if !show || !Terminal(w) {
		return nil
	}
	b := &Bar{w: w, label: label, stop: make(chan struct{})}
	b.total.Store(int64(total))
	b.wg.Add(1)
	go b.loop()
	return b
}

// Done counts one finished item. Safe for concurrent use.
func (b *Bar) Done() {
	if b != nil {
		b.done.Add(1)
	}
}

// Set replaces both counts, for callers that learn the total as they go.
func (b *Bar) Set(done, total int) {
	if b != nil {
		b.done.Store(int64(done))
		b.total.Store(int64(total))
	}
}

// Stop erases the line, leaving the terminal as it was.
func (b *Bar) Stop() {
	if b == nil {
		return
	}
	close(b.stop)
	b.wg.Wait()
	_, _ = fmt.Fprint(b.w, "\r"+strings.Repeat(" ", b.last)+"\r")
}

func (b *Bar) loop() {
	defer b.wg.Done()
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	if runtime.GOOS == "windows" {
		frames = []string{"|", "/", "-", `\`} // console fonts often lack braille
	}
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for i := 0; ; i++ {
		b.draw(frames[i%len(frames)])
		select {
		case <-b.stop:
			return
		case <-t.C:
		}
	}
}

func (b *Bar) draw(frame string) {
	line := fmt.Sprintf("%s %s", frame, b.label)
	if total := b.total.Load(); total > 0 {
		line += fmt.Sprintf(" %d/%d", min(b.done.Load(), total), total)
	}
	n := len([]rune(line))
	pad := ""
	if n < b.last {
		pad = strings.Repeat(" ", b.last-n) // overwrite a longer previous line
	}
	b.last = n
	_, _ = fmt.Fprint(b.w, "\r"+line+pad)
}
