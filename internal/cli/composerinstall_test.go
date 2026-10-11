package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestHelperComposer is the fake composer of the install tests: it records
// its arguments and the allow-plugins of the manifest it is pointed at.
func TestHelperComposer(t *testing.T) {
	if os.Getenv("SAFE_INSTALL_FAKE_COMPOSER") != "1" {
		t.Skip("helper process")
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	allow := ""
	if m := os.Getenv("COMPOSER"); m != "" {
		data, _ := os.ReadFile(m)
		var manifest struct {
			Config struct {
				AllowPlugins map[string]bool `json:"allow-plugins"`
			} `json:"config"`
		}
		_ = json.Unmarshal(data, &manifest)
		b, _ := json.Marshal(manifest.Config.AllowPlugins)
		allow = os.Getenv("COMPOSER") + " " + string(b)
	}
	f, _ := os.OpenFile(os.Getenv("SAFE_INSTALL_FAKE_COMPOSER_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(strings.Join(args, " ") + " | " + allow + "\n")
	_ = f.Close()
	os.Exit(0)
}

func composerProject(t *testing.T) (dir, log string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in composer on PATH is a shell script")
	}
	log = filepath.Join(t.TempDir(), "composer.log")
	prev := composerCommand
	composerCommand = func(dir string, env []string, args ...string) *exec.Cmd {
		c := exec.Command(os.Args[0], append([]string{"-test.run=^TestHelperComposer$", "--"}, args...)...)
		c.Dir = dir
		c.Env = append(os.Environ(), append(env, "SAFE_INSTALL_FAKE_COMPOSER=1", "SAFE_INSTALL_FAKE_COMPOSER_LOG="+log)...)
		return c
	}
	t.Cleanup(func() { composerCommand = prev })
	if _, err := exec.LookPath("composer"); err != nil {
		bin := t.TempDir()
		_ = os.WriteFile(filepath.Join(bin, "composer"), []byte("#!/bin/sh\n"), 0o700)
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	dir = t.TempDir()
	t.Chdir(dir)
	lock := `{"packages":[{"name":"acme/plugin","version":"1.0.0","type":"composer-plugin","dist":{"type":"zip","url":"https://api.github.com/repos/acme/plugin/zipball/abc123","reference":"abc123"}}],"packages-dev":[]}`
	// The project itself allows the plugin: safe-install must still decide.
	manifest := `{"require":{"acme/plugin":"*"},"config":{"allow-plugins":{"acme/plugin":true},"sort-packages":true},"scripts":{"post-install-cmd":["@php artisan x"]}}`
	_ = os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "composer.json"), []byte(manifest), 0o600)
	t.Setenv("SAFE_INSTALL_PACKAGIST_URL", "http://127.0.0.1:1") // unreachable: no registry data
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	prevI := isInteractive
	isInteractive = func() bool { return false }
	t.Cleanup(func() { isInteractive = prevI })
	return dir, log
}

func TestComposerInstallOnlyLoadsApprovedPlugins(t *testing.T) {
	dir, log := composerProject(t)
	before, _ := os.ReadFile(filepath.Join(dir, "composer.json"))
	out, err := runCLI(t, "install", "--frozen-lockfile")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	data, _ := os.ReadFile(log)
	if !strings.Contains(string(data), "install --no-scripts --no-interaction | .safe-install-composer.json {\"acme/plugin\":false}") {
		t.Fatalf("composer calls:\n%s", data)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "composer.json"))
	if string(before) != string(after) {
		t.Fatal("composer.json was edited")
	}
	for _, f := range []string{".safe-install-composer.json", ".safe-install-composer.lock"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s left behind", f)
		}
	}
	// Approved by commit: enabled.
	if out, err := runCLI(t, "approve", "acme/plugin", "--force"); err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	if out, err := runCLI(t, "install", "--frozen-lockfile"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	data, _ = os.ReadFile(log)
	if !strings.HasSuffix(strings.TrimSpace(string(data)), `{"acme/plugin":true}`) {
		t.Fatalf("approved plugin not enabled:\n%s", data)
	}
}

func TestComposerShadowKeepsOtherConfig(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"config":{"allow-plugins":{"evil/x":true},"vendor-dir":"lib"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{"packages":[]}`), 0o600)
	j, l, err := writeComposerShadow(dir, map[string]bool{"good/y": true})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(j)
	var m struct {
		Config map[string]any `json:"config"`
	}
	_ = json.Unmarshal(data, &m)
	allow := m.Config["allow-plugins"].(map[string]any)
	if allow["evil/x"] != nil || allow["good/y"] != true || m.Config["vendor-dir"] != "lib" {
		t.Fatalf("config = %v", m.Config)
	}
	if lock, _ := os.ReadFile(l); string(lock) != `{"packages":[]}` {
		t.Fatalf("lock copy = %q", lock)
	}
}

func TestComposerInstalledStaysInProject(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "vendor", "composer")
	_ = os.MkdirAll(base, 0o700)
	_ = os.WriteFile(filepath.Join(base, "installed.json"), []byte(`{"packages":[
		{"name":"Acme/Lib","version":"1.0.0","install-path":"../acme/lib"},
		{"name":"evil/x","version":"1.0.0","install-path":"../../../../etc"}]}`), 0o600)
	got := composerInstalled(dir)
	if got["acme/lib@1.0.0"] != filepath.Join(dir, "vendor", "acme", "lib") || len(got) != 1 {
		t.Fatalf("installed = %v", got)
	}
}

func TestApproveOtherRefusesNothingToApprove(t *testing.T) {
	composerProject(t)
	lock := `{"packages":[{"name":"acme/lib","version":"1.0.0","type":"library","dist":{"type":"zip","url":"https://x/zipball/abc","reference":"abc"}}],"packages-dev":[]}`
	_ = os.WriteFile("composer.lock", []byte(lock), 0o600)
	if _, err := runCLI(t, "approve", "acme/lib"); err == nil || !strings.Contains(err.Error(), "not a Composer plugin") {
		t.Fatalf("got %v", err)
	}
	if _, err := runCLI(t, "approve", "acme/*"); err == nil {
		t.Fatal("glob accepted")
	}
}
