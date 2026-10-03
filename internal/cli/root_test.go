package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.HasPrefix(out.String(), "safe-install dev") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestUnknownCommandIsToolError(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"nope"})
	root.SetErr(&bytes.Buffer{})

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for unknown command")
	}
}
