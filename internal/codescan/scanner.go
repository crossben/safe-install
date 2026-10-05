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

// DefaultCacheDir is the per-user cache for scan results
// ($SAFE_INSTALL_CACHE_DIR/codescan when set).
func DefaultCacheDir() string {
	if dir := os.Getenv("SAFE_INSTALL_CACHE_DIR"); dir != "" {
		return filepath.Join(dir, "codescan")
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "safe-install", "codescan")
}

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
	path := s.cachePath(t)
	if path != "" {
		if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- our cache file
			var cs []cached
			if json.Unmarshal(data, &cs) == nil {
				out := make([]analyze.Finding, 0, len(cs))
				for _, c := range cs {
					out = append(out, analyze.Finding{Rule: c.Rule, Severity: analyze.Severity(c.Severity), Message: c.Message})
				}
				return out
			}
		}
	}
	fs := Package(t.Dir)
	if path != "" {
		cs := make([]cached, 0, len(fs))
		for _, f := range fs {
			cs = append(cs, cached{f.Rule, int(f.Severity), f.Message})
		}
		if data, err := json.Marshal(cs); err == nil && os.MkdirAll(filepath.Dir(path), 0o750) == nil {
			_ = os.WriteFile(path, data, 0o600) // best effort
		}
	}
	return fs
}

func (s *Scanner) cachePath(t Target) string {
	if s.CacheDir == "" || t.Integrity == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("v%d\x00%s\x00%s", Version, t.ID, t.Integrity)))
	return filepath.Join(s.CacheDir, hex.EncodeToString(sum[:])+".json")
}
