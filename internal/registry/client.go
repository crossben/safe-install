package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crossben/safe-install/internal/cache"
	"github.com/crossben/safe-install/internal/npmrc"
)

// DefaultURL is the public npm registry.
const DefaultURL = "https://registry.npmjs.org"

// maxPackument bounds a registry response (the largest real packuments are tens of MB).
const maxPackument = 128 << 20

// Errors.
var (
	ErrNotFound     = errors.New("package not found in registry")
	ErrNotCached    = errors.New("not in cache (offline mode)")
	ErrUnauthorized = errors.New("registry refused access; check the registry credentials in .npmrc / .yarnrc.yml")
)

// Fetcher returns packuments by package name.
type Fetcher interface {
	Packument(ctx context.Context, name string) (*Packument, error)
}

// Client fetches packuments over HTTP with an ETag-revalidated disk cache.
type Client struct {
	Config   *npmrc.Config // registries and credentials; nil uses BaseURL without auth
	BaseURL  string        // default DefaultURL, when Config is nil
	HTTP     *http.Client  // default: 30s timeout
	CacheDir string        // "" disables the cache
	Offline  bool          // serve from cache only

	MaxTarball int64 // largest tarball Tarball downloads; default 100 MB
}

type cacheEntry struct {
	ETag string          `json:"etag"`
	Body json.RawMessage `json:"body"`
}

// Packument fetches the full document for name.
func (c *Client) Packument(ctx context.Context, name string) (*Packument, error) {
	u := c.url(name)
	cached, _ := c.readCache(u)
	if c.Offline {
		if cached == nil {
			return nil, fmt.Errorf("%s: %w", name, ErrNotCached)
		}
		return decode(cached.Body)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "safe-install")
	if c.Config != nil {
		// Credentials only for the registry configured for this URL; Go drops
		// the header if the registry redirects to another host.
		if auth := c.Config.AuthFor(u); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}
	if cached != nil && cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified && cached != nil:
		return decode(cached.Body)
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", name, ErrNotFound)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%s: %w (%s)", name, ErrUnauthorized, resp.Status)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: registry returned %s", name, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPackument+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(body) > maxPackument {
		return nil, fmt.Errorf("%s: registry response over %d bytes", name, maxPackument)
	}
	p, err := decode(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	c.writeCache(u, cacheEntry{ETag: resp.Header.Get("ETag"), Body: body})
	return p, nil
}

func decode(body []byte) (*Packument, error) {
	var p Packument
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decoding packument: %w", err)
	}
	return &p, nil
}

func (c *Client) url(name string) string {
	base := c.BaseURL
	if c.Config != nil {
		base = c.Config.RegistryFor(name)
	}
	if base == "" {
		base = DefaultURL
	}
	// Scoped names keep the "@" but escape the "/": @scope%2fpkg.
	return strings.TrimSuffix(base, "/") + "/" + url.PathEscape(name)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) cachePath(u string) string {
	sum := sha256.Sum256([]byte(u))
	return filepath.Join(c.CacheDir, hex.EncodeToString(sum[:])+".json")
}

func (c *Client) readCache(u string) (*cacheEntry, error) {
	if c.CacheDir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(c.cachePath(u))
	if err != nil {
		return nil, err
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// writeCache is best effort: a cache failure never fails a check.
func (c *Client) writeCache(u string, e cacheEntry) {
	if c.CacheDir == "" {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	if os.MkdirAll(c.CacheDir, 0o750) != nil {
		return
	}
	tmp, err := os.CreateTemp(c.CacheDir, ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), c.cachePath(u)) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// DefaultCacheDir is the cache for registry metadata.
func DefaultCacheDir() string { return cache.Sub(cache.Registry) }

// FixtureClient serves packuments from a JSON file ({"name": packument}),
// for tests (SAFE_INSTALL_REGISTRY_FIXTURES).
type FixtureClient struct {
	docs map[string]*Packument
}

// NewFixtureClient loads the fixtures file at path.
func NewFixtureClient(path string) (*FixtureClient, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path given by the user via env
	if err != nil {
		return nil, err
	}
	var docs map[string]*Packument
	if err := json.Unmarshal(data, &docs); err != nil {
		return nil, fmt.Errorf("registry fixtures %s: %w", path, err)
	}
	return &FixtureClient{docs: docs}, nil
}

// Packument returns the fixture for name.
func (f *FixtureClient) Packument(_ context.Context, name string) (*Packument, error) {
	if p, ok := f.docs[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("%s: %w", name, ErrNotFound)
}
