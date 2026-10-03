package popularity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedList(t *testing.T) {
	l := Default()
	if l.Len() < 10000 {
		t.Fatalf("only %d names embedded", l.Len())
	}
	if !l.Popular("react") || l.Popular("definitely-not-a-real-package-xyz") {
		t.Fatal("Popular")
	}
	if r, ok := l.Rank("semver"); !ok || r != 0 {
		t.Fatalf("Rank(semver) = %d, %v", r, ok)
	}
}

func TestTyposquat(t *testing.T) {
	l := Default()
	squats := map[string]string{
		"lodahs":  "lodash",  // transposition
		"lodashh": "lodash",  // insertion
		"expres":  "express", // deletion
		"axois":   "axios",
		"re-act":  "react",  // separators
		"Lodash":  "lodash", // case
		"chalkk":  "chalk",
	}
	for name, want := range squats {
		if got, ok := l.Typosquat(name); !ok || got != want {
			t.Errorf("Typosquat(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"lodash", "react", "ws", "ms", "debug", "chalk", "zzqx-unique-thing", "@types/react", "a"} {
		if got, ok := l.Typosquat(name); ok {
			t.Errorf("Typosquat(%q) flagged as %q", name, got)
		}
	}
}

func TestDistance(t *testing.T) {
	tests := []struct {
		a, b string
		d    int
	}{
		{"lodash", "lodash", 0}, {"lodash", "lodahs", 1}, {"lodash", "lodas", 1},
		{"lodash", "xodash", 1}, {"lodash", "loadsh", 1}, {"abc", "xyz", 3},
	}
	for _, tt := range tests {
		if d := distance(tt.a, tt.b, 3); d != tt.d {
			t.Errorf("distance(%q, %q) = %d, want %d", tt.a, tt.b, d, tt.d)
		}
	}
}

func TestWeeklyDownloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.EscapedPath(), "/downloads/point/last-week/")
		switch path {
		case "a,b":
			_, _ = w.Write([]byte(`{"a":{"downloads":5,"package":"a"},"b":null}`))
		case "@s%2Fc", "@s/c":
			_, _ = w.Write([]byte(`{"downloads":42,"package":"@s/c"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := &Downloads{BaseURL: srv.URL}
	got, err := c.Weekly(context.Background(), []string{"a", "b", "@s/c"})
	if err != nil {
		t.Fatal(err)
	}
	if got["a"] != 5 || got["@s/c"] != 42 {
		t.Fatalf("got %v", got)
	}
	if _, ok := got["b"]; ok {
		t.Fatalf("unknown package b should be absent: %v", got)
	}
}
