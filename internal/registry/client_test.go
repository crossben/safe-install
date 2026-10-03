package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

const msPackument = `{
  "name": "ms",
  "dist-tags": {"latest": "2.1.3"},
  "time": {"created": "2011-12-21T19:38:08.664Z", "2.1.3": "2020-12-08T13:54:35.223Z"},
  "maintainers": [{"name": "leo"}],
  "versions": {
    "2.1.3": {
      "version": "2.1.3",
      "_npmUser": {"name": "styfle"},
      "maintainers": [{"name": "leo"}, {"name": "styfle"}],
      "deprecated": "use something else",
      "dist": {"integrity": "sha512-abc", "tarball": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"}
    }
  }
}`

func newServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.EscapedPath() {
		case "/ms", "/@scope%2Fpkg":
		default:
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(msPackument))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPackument(t *testing.T) {
	var hits atomic.Int32
	srv := newServer(t, &hits)
	c := &Client{BaseURL: srv.URL, CacheDir: t.TempDir()}

	p, err := c.Packument(context.Background(), "ms")
	if err != nil {
		t.Fatal(err)
	}
	v := p.Versions["2.1.3"]
	if p.Name != "ms" || v.NpmUser.Name != "styfle" || v.Dist.Integrity != "sha512-abc" || v.Deprecated != "use something else" {
		t.Fatalf("unexpected packument: %+v", p)
	}
	if got := p.Published("2.1.3"); got.IsZero() || got.Year() != 2020 {
		t.Fatalf("Published = %v", got)
	}
	if len(v.Maintainers) != 2 {
		t.Fatalf("maintainers = %v", v.Maintainers)
	}
}

func TestScopedNameIsEscaped(t *testing.T) {
	var hits atomic.Int32
	srv := newServer(t, &hits)
	c := &Client{BaseURL: srv.URL + "/", CacheDir: t.TempDir()}
	if _, err := c.Packument(context.Background(), "@scope/pkg"); err != nil {
		t.Fatal(err)
	}
}

func TestCacheRevalidatesAndServesOffline(t *testing.T) {
	var hits atomic.Int32
	srv := newServer(t, &hits)
	cache := t.TempDir()
	ctx := context.Background()

	c := &Client{BaseURL: srv.URL, CacheDir: cache}
	if _, err := c.Packument(ctx, "ms"); err != nil {
		t.Fatal(err)
	}
	// Second call revalidates with the ETag and gets 304: still a full result.
	p, err := c.Packument(ctx, "ms")
	if err != nil || p.Name != "ms" {
		t.Fatalf("revalidated: %v, %v", p, err)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d, want 2", hits.Load())
	}

	off := &Client{BaseURL: srv.URL, CacheDir: cache, Offline: true}
	if _, err := off.Packument(ctx, "ms"); err != nil {
		t.Fatalf("offline cached: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatal("offline client hit the network")
	}
	if _, err := off.Packument(ctx, "other"); !errors.Is(err, ErrNotCached) {
		t.Fatalf("offline uncached: got %v, want ErrNotCached", err)
	}
}

func TestNotFound(t *testing.T) {
	var hits atomic.Int32
	srv := newServer(t, &hits)
	c := &Client{BaseURL: srv.URL, CacheDir: t.TempDir()}
	if _, err := c.Packument(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestFixtures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixtures.json")
	if err := os.WriteFile(path, []byte(`{"ms": `+msPackument+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewFixtureClient(path)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := c.Packument(context.Background(), "ms"); err != nil || p.Name != "ms" {
		t.Fatalf("fixture ms: %v, %v", p, err)
	}
	if _, err := c.Packument(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestUnpublishedTimeEntry(t *testing.T) {
	// Unpublished packages put an object in "time"; that must not break parsing.
	var p Packument
	if err := p.UnmarshalJSON([]byte(`{"name":"x","time":{"unpublished":{"time":"2020-01-01T00:00:00Z"}}}`)); err != nil {
		t.Fatal(err)
	}
	if !p.Published("1.0.0").IsZero() {
		t.Fatal("expected zero time")
	}
}
