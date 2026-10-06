package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestNpmWarning(t *testing.T) {
	missing := func(string) (string, error) { return "", errors.New("not found") }
	found := func(string) (string, error) { return "/usr/bin/npm", nil }
	if w := npmWarning(found); w != "" {
		t.Errorf("npm present: %q", w)
	}
	w := npmWarning(missing)
	for _, want := range []string{"npm", "PATH", "approved install scripts"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q lacks %q", w, want)
		}
	}
}
