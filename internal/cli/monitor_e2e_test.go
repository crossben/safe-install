//go:build linux

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sneakyProject: a dependency whose innocent-looking postinstall runs a file
// that appends to ~/.bashrc, then writes a marker. HOME is a temp dir.
func sneakyProject(t *testing.T) (home, marker string) {
	t.Helper()
	for _, bin := range []string{"npm", "strace"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	root := t.TempDir()
	home = filepath.Join(root, "home")
	marker = filepath.Join(root, "after")
	src, proj := filepath.Join(root, "sneaky-dep"), filepath.Join(root, "proj")
	mustMkdir(t, home)
	mustMkdir(t, src)
	mustMkdir(t, proj)
	mustWriteJSON(t, filepath.Join(src, "package.json"), map[string]any{
		// Nested `npm run` inherits the monitor's script shell: it must still work, and still be watched.
		"name": "sneaky-dep", "version": "1.0.0", "scripts": map[string]string{"postinstall": "npm run setup", "setup": "node setup.js"},
	})
	setup := `const fs = require('fs'), path = require('path'), os = require('os');
fs.appendFileSync(path.join(os.homedir(), '.bashrc'), 'export PATH=$HOME/.local/evil:$PATH\n');
setTimeout(() => fs.writeFileSync(process.env.AFTER_MARKER, ''), 1500);
`
	if err := os.WriteFile(filepath.Join(src, "setup.js"), []byte(setup), 0o600); err != nil {
		t.Fatal(err)
	}
	pack := exec.Command("npm", "pack", "--silent", "--pack-destination", proj)
	pack.Dir = src
	if out, err := pack.CombinedOutput(); err != nil {
		t.Fatalf("npm pack: %v\n%s", err, out)
	}
	mustWriteJSON(t, filepath.Join(proj, "package.json"), map[string]any{
		"name": "proj", "version": "1.0.0", "dependencies": map[string]string{"sneaky-dep": "file:./sneaky-dep-1.0.0.tgz"},
	})
	fixtures := filepath.Join(root, "registry.json")
	if err := os.WriteFile(fixtures, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// npm keeps its cache under HOME; point it at the real one to stay fast and offline-safe.
	if cache, err := exec.Command("npm", "config", "get", "cache").Output(); err == nil {
		t.Setenv("npm_config_cache", strings.TrimSpace(string(cache)))
	}
	t.Setenv("HOME", home)
	t.Setenv("AFTER_MARKER", marker)
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", fixtures)
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", filepath.Join(root, "config"))
	t.Chdir(proj)
	return home, marker
}

func TestMonitorReports(t *testing.T) {
	home, marker := sneakyProject(t)
	out, err := runInstallCLI(t, "", false, "--yes", "--monitor")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	for _, want := range []string{"Runtime monitor", "sneaky-dep@1.0.0", "SI-MON-004", "~/.bashrc"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); err != nil {
		t.Error("report mode should let the script run")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("report mode should let the script finish")
	}
}

func TestMonitorKills(t *testing.T) {
	_, marker := sneakyProject(t)
	out, err := runInstallCLI(t, "", false, "--yes", "--monitor=kill")
	if err == nil {
		t.Fatalf("install succeeded although the script was killed:\n%s", out)
	}
	if !strings.Contains(out, "killed") {
		t.Errorf("no kill reported:\n%s", out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("script kept running after writing ~/.bashrc")
	}
}

func TestMonitorCIFails(t *testing.T) {
	sneakyProject(t)
	_, err := runInstallCLI(t, "", false, "--yes", "--ci", "--monitor")
	if code := exitCode(err); code != ExitPolicyFailure {
		t.Fatalf("exit = %d (%v), want %d", code, err, ExitPolicyFailure)
	}
}
