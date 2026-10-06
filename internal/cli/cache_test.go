package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/cache"
)

func TestCacheCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SAFE_INSTALL_CACHE_DIR", dir)
	if err := os.MkdirAll(cache.Sub(cache.Registry), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.Sub(cache.Registry), "x.json"), make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runArgs(t, "cache", "dir")
	if code != 0 || strings.TrimSpace(out) != dir {
		t.Fatalf("cache dir: %d %q", code, out)
	}
	out, code = runArgs(t, "cache", "info")
	if code != 0 || !strings.Contains(out, "registry") || !strings.Contains(out, "2.0 KB") {
		t.Fatalf("cache info: %d\n%s", code, out)
	}
	if out, code := runArgs(t, "cache", "clean", "registry"); code != 0 {
		t.Fatalf("cache clean: %d\n%s", code, out)
	}
	if cache.Usage()[cache.Registry] != 0 {
		t.Fatal("registry cache not cleaned")
	}
	if _, code := runArgs(t, "cache", "clean", "bogus"); code == 0 {
		t.Fatal("unknown part accepted")
	}
}

func TestCacheIsPrunedAfterCommands(t *testing.T) {
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_CACHE_MAX", "4KB")
	old := filepath.Join(cache.Sub(cache.Registry), "old.json")
	if err := os.MkdirAll(filepath.Dir(old), 0o750); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"old.json", "a.json", "b.json"} {
		p := filepath.Join(cache.Sub(cache.Registry), name)
		if err := os.WriteFile(p, make([]byte, 2048), 0o600); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(time.Duration(i-3) * time.Hour)
		_ = os.Chtimes(p, when, when)
	}
	if _, code := runArgs(t, "version"); code != 0 {
		t.Fatal("version failed")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("cache over its cap was not pruned (usage %v)", cache.Usage())
	}
}
