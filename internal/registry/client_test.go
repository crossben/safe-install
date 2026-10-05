package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/crossben/safe-install/internal/npmrc"
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

// Packages go to their (scoped) registry, each with only its own credentials.
func TestPrivateRegistries(t *testing.T) {
	seen := map[string]string{} // path -> Authorization received
	var mu sync.Mutex
	handler := func(want string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[r.Host+r.URL.EscapedPath()] = r.Header.Get("Authorization")
			mu.Unlock()
			if r.Header.Get("Authorization") != want {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(msPackument))
		}
	}
	corp := httptest.NewServer(handler("Bearer corp-token"))
	defer corp.Close()
	public := httptest.NewServer(handler(""))
	defer public.Close()

	dir := t.TempDir()
	npmrcText := "registry=" + public.URL + "/\n" +
		"@corp:registry=" + corp.URL + "/npm/\n" +
		strings.TrimPrefix(corp.URL, "http:") + "/npm/:_authToken=${CORP_TOKEN}\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrcText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := npmrc.Load(dir, func(k string) string {
		return map[string]string{"HOME": t.TempDir(), "CORP_TOKEN": "corp-token"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{Config: cfg, CacheDir: t.TempDir()}
	ctx := context.Background()
	if _, err := c.Packument(ctx, "@corp/ui"); err != nil {
		t.Fatalf("scoped private package: %v", err)
	}
	if _, err := c.Packument(ctx, "ms"); err != nil {
		t.Fatalf("public package: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for path, auth := range seen {
		if strings.Contains(path, "/npm/") != (auth != "") {
			t.Errorf("%s received Authorization %q", path, auth)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("requests = %v", seen)
	}
}

func TestUnauthorizedIsAClearError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	_, err := c.Packument(context.Background(), "x")
	if !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), ".npmrc") {
		t.Fatalf("err = %v", err)
	}
}
