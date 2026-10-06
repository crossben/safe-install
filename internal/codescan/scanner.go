package codescan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/cache"
)

// Target is one installed package to scan.
type Target struct {
	ID        string // name@version
	Integrity string // lockfile integrity; "" (file:, git) disables caching
	Dir       string
}

// Scanner scans packages in parallel and caches results per version.
type Scanner struct {
	CacheDir string // "" disables the cache
}

// DefaultCacheDir is the cache for scan results.
func DefaultCacheDir() string { return cache.Sub(cache.Scan) }

type cached struct {
	Rule     string `json:"rule"`
	Severity int    `json:"severity"`
	Message  string `json:"message"`
}

// ScanAll scans every target and returns findings by ID (absent when clean).
func (s *Scanner) ScanAll(targets []Target) map[string][]analyze.Finding {
	out := map[string][]analyze.Finding{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan Target)
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range work {
				fs := s.scan(t)
				if len(fs) > 0 {
					mu.Lock()
					out[t.ID] = fs
					mu.Unlock()
				}
			}
		}()
	}
	for _, t := range targets {
		work <- t
	}
	close(work)
	wg.Wait()
	return out
}

func (s *Scanner) scan(t Target) []analyze.Finding {
	if fs, ok := s.Lookup(t); ok {
		return fs
	}
	fs := Package(t.Dir)
	s.Store(t, fs)
	return fs
}

// Lookup returns cached findings for t (ID and Integrity; Dir is ignored).
func (s *Scanner) Lookup(t Target) ([]analyze.Finding, bool) {
	path := s.cachePath(t)
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- our cache file
	if err != nil {
		return nil, false
	}
	var cs []cached
	if json.Unmarshal(data, &cs) != nil {
		return nil, false
	}
	out := make([]analyze.Finding, 0, len(cs))
	for _, c := range cs {
		out = append(out, analyze.Finding{Rule: c.Rule, Severity: analyze.Severity(c.Severity), Message: c.Message})
	}
	return out, true
}

// Store caches findings for t (best effort; no-op without integrity).
func (s *Scanner) Store(t Target, fs []analyze.Finding) {
	path := s.cachePath(t)
	if path == "" {
		return
	}
	cs := make([]cached, 0, len(fs))
	for _, f := range fs {
		cs = append(cs, cached{f.Rule, int(f.Severity), f.Message})
	}
	if data, err := json.Marshal(cs); err == nil && os.MkdirAll(filepath.Dir(path), 0o750) == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
}

func (s *Scanner) cachePath(t Target) string {
	if s.CacheDir == "" || t.Integrity == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("v%d\x00%s\x00%s", Version, t.ID, t.Integrity)))
	return filepath.Join(s.CacheDir, hex.EncodeToString(sum[:])+".json")
}
