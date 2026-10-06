// Package cache locates, measures, cleans and caps safe-install's cache:
// registry metadata, code-scan results and the organization policy.
package cache

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The cache's parts.
const (
	Registry = "registry"
	Scan     = "codescan"
	Org      = "org"
)

// Parts lists every part, in display order.
var Parts = []string{Registry, Scan, Org}

// DefaultMax is the default size cap.
const DefaultMax = 1 << 30

// Dir is the cache root: $SAFE_INSTALL_CACHE_DIR, else the OS cache dir.
func Dir() string {
	if d := os.Getenv("SAFE_INSTALL_CACHE_DIR"); d != "" {
		return d
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "safe-install")
}

// Sub is one part's directory.
func Sub(part string) string {
	if Dir() == "" {
		return ""
	}
	return filepath.Join(Dir(), part)
}

// Usage returns each part's size in bytes.
func Usage() map[string]int64 {
	out := map[string]int64{}
	for _, p := range Parts {
		for _, f := range files(Sub(p)) {
			out[p] += f.size
		}
	}
	return out
}

// Clean empties the given parts (all of them when none are given).
func Clean(parts ...string) error {
	if len(parts) == 0 {
		parts = Parts
	}
	var errs []error
	for _, p := range parts {
		if !contains(Parts, p) {
			return fmt.Errorf("unknown cache part %q (%s)", p, strings.Join(Parts, ", "))
		}
		if d := Sub(p); d != "" {
			errs = append(errs, os.RemoveAll(d))
		}
	}
	return errors.Join(errs...)
}

// Prune removes the least recently modified files until the cache is at most
// 80% of limit, when it is over limit. It returns the bytes removed.
func Prune(limit int64) (int64, error) {
	var all []entry
	var total int64
	for _, p := range Parts {
		fs := files(Sub(p))
		all = append(all, fs...)
		for _, f := range fs {
			total += f.size
		}
	}
	if total <= limit {
		return 0, nil
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod < all[j].mod })
	target := limit * 8 / 10
	var removed int64
	var errs []error
	for _, f := range all {
		if total-removed <= target {
			break
		}
		if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		removed += f.size
	}
	return removed, errors.Join(errs...)
}

// ParseSize reads "500MB", "2GB", "100KB" or a byte count; "" is DefaultMax.
func ParseSize(s string) (int64, error) {
	if s == "" {
		return DefaultMax, nil
	}
	mult := int64(1)
	num := strings.ToUpper(strings.TrimSpace(s))
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}} {
		if strings.HasSuffix(num, u.suffix) {
			num, mult = strings.TrimSuffix(num, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid cache size %q (e.g. 500MB, 2GB)", s)
	}
	return n * mult, nil
}

type entry struct {
	path string
	size int64
	mod  int64
}

func files(dir string) []entry {
	if dir == "" {
		return nil
	}
	var out []entry
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			out = append(out, entry{path, info.Size(), info.ModTime().UnixNano()})
		}
		return nil
	})
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
