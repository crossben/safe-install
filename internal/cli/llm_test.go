package cli

import (
	"strings"
	"testing"
)

func TestVersionFlagMatchesCommand(t *testing.T) {
	want, err := runCmd(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--version", "-v"} {
		got, err := runCmd(t, flag)
		if err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", flag, got, err, want)
		}
	}
}

func TestLLMGuide(t *testing.T) {
	out, err := runCmd(t, "llm")
	if err != nil {
		t.Fatal(err)
	}
	// The guide must tell agents the one thing that matters most.
	for _, s := range []string{"# safe-install: instructions for AI coding agents", "Never approve scripts yourself", "safe-install approve <package>"} {
		if !strings.Contains(out, s) {
			t.Errorf("guide is missing %q", s)
		}
	}
}
