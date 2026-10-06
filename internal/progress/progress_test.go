package progress

import (
	"bytes"
	"testing"
)

func TestNoTerminalNoOutput(t *testing.T) {
	var buf bytes.Buffer
	b := Start(&buf, true, "checking", 3)
	if b != nil {
		t.Fatal("a buffer is not a terminal")
	}
	b.Done() // nil-safe
	b.Stop()
	if buf.Len() != 0 {
		t.Fatalf("wrote %q", buf.String())
	}
}

func TestDrawAndErase(t *testing.T) {
	var buf bytes.Buffer
	b := &Bar{w: &buf, label: "checking", stop: make(chan struct{})}
	b.total.Store(3)
	b.Done()
	b.draw("*")
	if got := buf.String(); got != "\r* checking 1/3" {
		t.Fatalf("draw = %q", got)
	}
	b.Stop()
	if got := buf.String(); got != "\r* checking 1/3\r"+"               "[:14]+"\r" {
		t.Fatalf("stop = %q", got)
	}
}
