package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func file(t *testing.T, path string, size int, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func TestDirHonorsEnv(t *testing.T) {
	d := t.TempDir()
	t.Setenv("SAFE_INSTALL_CACHE_DIR", d)
	if Dir() != d || Sub(Registry) != filepath.Join(d, "registry") {
		t.Fatalf("Dir = %q, Sub = %q", Dir(), Sub(Registry))
	}
}

func TestUsageAndClean(t *testing.T) {
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	file(t, filepath.Join(Sub(Registry), "a.json"), 100, 0)
	file(t, filepath.Join(Sub(Scan), "b.json"), 10, 0)
	u := Usage()
	if u[Registry] != 100 || u[Scan] != 10 || u[Org] != 0 {
		t.Fatalf("usage = %v", u)
	}
	if err := Clean(Registry); err != nil {
		t.Fatal(err)
	}
	if u := Usage(); u[Registry] != 0 || u[Scan] != 10 {
		t.Fatalf("after clean registry: %v", u)
	}
	if err := Clean(); err != nil {
		t.Fatal(err)
	}
	if u := Usage(); u[Scan] != 0 {
		t.Fatalf("after clean all: %v", u)
	}
}

func TestPruneRemovesOldestFirst(t *testing.T) {
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	file(t, filepath.Join(Sub(Registry), "old.json"), 400, 3*time.Hour)
	file(t, filepath.Join(Sub(Scan), "mid.json"), 400, 2*time.Hour)
	file(t, filepath.Join(Sub(Registry), "new.json"), 400, time.Hour)
	removed, err := Prune(1000) // 1200 > 1000: prune to 80% (800)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 400 {
		t.Fatalf("removed %d bytes, want 400", removed)
	}
	if _, err := os.Stat(filepath.Join(Sub(Registry), "old.json")); !os.IsNotExist(err) {
		t.Fatal("the oldest file survived")
	}
	for _, p := range []string{filepath.Join(Sub(Scan), "mid.json"), filepath.Join(Sub(Registry), "new.json")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", p, err)
		}
	}
	if removed, _ := Prune(1000); removed != 0 {
		t.Fatalf("under the cap but removed %d", removed)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"": DefaultMax, "500MB": 500 << 20, "2GB": 2 << 30, "100KB": 100 << 10, "1048576": 1 << 20} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"lots", "-1MB", "5TBB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}
