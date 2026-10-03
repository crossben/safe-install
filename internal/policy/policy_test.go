package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMergesGlobalAndProject(t *testing.T) {
	global, proj := t.TempDir(), t.TempDir()
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", global)
	write(t, filepath.Join(global, "config.json"), `{
		"minReleaseAge": "7d", "failOn": "medium",
		"minReleaseAgeExclude": ["typescript"],
		"allowScripts": {"esbuild": {"version": "0.25.0", "hash": "sha256-g"}, "sharp": {"version": "1", "hash": "sha256-s"}}}`)
	write(t, filepath.Join(proj, FileName), `{
		"minReleaseAge": "48h",
		"minReleaseAgeExclude": ["@types/*"],
		"allowScripts": {"esbuild": {"version": "0.25.10", "hash": "sha256-p"}}}`)

	p, err := Load(proj)
	if err != nil {
		t.Fatal(err)
	}
	if p.MinReleaseAge != "48h" || p.FailOn != "medium" {
		t.Errorf("scalars: %+v", p)
	}
	if got := p.AllowScripts["esbuild"].Hash; got != "sha256-p" {
		t.Errorf("project approval should win, got %q", got)
	}
	if p.AllowScripts["sharp"].Hash != "sha256-s" {
		t.Error("global approval lost")
	}
	if !p.Excluded("@types/node") || !p.Excluded("typescript") || p.Excluded("react") {
		t.Errorf("exclusions: %v", p.MinReleaseAgeExclude)
	}
}

func TestLoadWithoutFiles(t *testing.T) {
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	p, err := Load(t.TempDir())
	if err != nil || p.AllowScripts == nil {
		t.Fatalf("Load = %+v, %v", p, err)
	}
}

func TestInvalidFileNamesThePath(t *testing.T) {
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), `{"allowScripts": [}`)
	_, err := Load(proj)
	if err == nil || !strings.Contains(err.Error(), FileName) {
		t.Fatalf("err = %v, want it to name %s", err, FileName)
	}
}

func TestApproveAndRevokeKeepOtherFields(t *testing.T) {
	proj := t.TempDir()
	path := filepath.Join(proj, FileName)
	write(t, path, `{"minReleaseAge": "3d", "allowScripts": {"sharp": {"version": "1", "hash": "sha256-s"}}}`)

	if err := Approve(path, "esbuild", Approval{Version: "0.25.10", Hash: "sha256-e"}); err != nil {
		t.Fatal(err)
	}
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.MinReleaseAge != "3d" || f.AllowScripts["sharp"].Hash != "sha256-s" || f.AllowScripts["esbuild"].Hash != "sha256-e" {
		t.Fatalf("after approve: %+v", f)
	}
	if f.AllowScripts["esbuild"].At == "" {
		t.Error("approval date not recorded")
	}

	removed, err := Revoke(path, "esbuild")
	if err != nil || !removed {
		t.Fatalf("revoke: %v, %v", removed, err)
	}
	f, _ = Read(path)
	if _, ok := f.AllowScripts["esbuild"]; ok {
		t.Fatal("esbuild still approved")
	}
	if removed, _ := Revoke(path, "nope"); removed {
		t.Fatal("revoking an unknown package reported success")
	}
}

func TestApproveCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", FileName)
	if err := Approve(path, "a", Approval{Version: "1", Hash: "h"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
