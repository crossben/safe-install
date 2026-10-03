package pm

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestNPMInstallCommand(t *testing.T) {
	cmd, err := npmAdapter{}.installCmd(context.Background(), "/proj", []string{"--ignore-scripts=false", "--no-audit"}, time.Time{})
	if err != nil {
		t.Skipf("npm not installed: %v", err)
	}

	// --ignore-scripts goes last so a user flag cannot switch scripts back on.
	want := []string{"install", "--ignore-scripts=false", "--no-audit", "--ignore-scripts"}
	if got := cmd.Args[1:]; !slices.Equal(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
	if cmd.Dir != "/proj" {
		t.Fatalf("dir = %q", cmd.Dir)
	}
	if !slices.Contains(cmd.Env, "npm_config_ignore_scripts=true") {
		t.Fatal("npm_config_ignore_scripts=true not set in env")
	}
}

func TestNPMInstallBefore(t *testing.T) {
	before := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	cmd, err := npmAdapter{}.installCmd(context.Background(), "/proj", nil, before)
	if err != nil {
		t.Skipf("npm not installed: %v", err)
	}
	want := []string{"install", "--before", "2026-09-30T12:00:00Z", "--ignore-scripts"}
	if got := cmd.Args[1:]; !slices.Equal(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

// Marker-writing lifecycle scripts, in the project and in a dependency.
const markerScript = `node -e "require('fs').writeFileSync(require('path').join(process.env.MARKER_DIR, process.env.npm_package_name + '-' + process.env.npm_lifecycle_event), '')"`

func newScriptedProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dep := filepath.Join(root, "dep-src")
	proj := filepath.Join(root, "proj")
	for _, d := range []string{dep, proj} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	scripts := `"scripts":{"preinstall":` + jsonString(markerScript) + `,"postinstall":` + jsonString(markerScript) + `}`
	write(t, filepath.Join(dep, "package.json"), `{"name":"evil-dep","version":"1.0.0",`+scripts+`}`)

	pack := exec.Command("npm", "pack", "--silent", "--pack-destination", proj)
	pack.Dir = dep
	if out, err := pack.CombinedOutput(); err != nil {
		t.Fatalf("npm pack: %v\n%s", err, out)
	}
	write(t, filepath.Join(proj, "package.json"),
		`{"name":"proj","version":"1.0.0","dependencies":{"evil-dep":"file:./evil-dep-1.0.0.tgz"},`+scripts+`}`)
	return proj
}

func TestNPMInstallNoScriptsE2E(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	ctx := context.Background()

	// Control: plain npm runs the scripts, so the markers prove something.
	control := newScriptedProject(t)
	markers := t.TempDir()
	t.Setenv("MARKER_DIR", markers)
	plain := exec.CommandContext(ctx, "npm", "install", "--no-audit", "--no-fund")
	plain.Dir = control
	if out, err := plain.CombinedOutput(); err != nil {
		t.Fatalf("control npm install: %v\n%s", err, out)
	}
	if n := countEntries(t, markers); n == 0 {
		t.Fatal("control: scripts did not run, test cannot prove anything")
	}

	proj := newScriptedProject(t)
	markers = t.TempDir()
	t.Setenv("MARKER_DIR", markers)
	opts := InstallOptions{Args: []string{"--no-audit", "--no-fund"}, Stdout: io.Discard, Stderr: io.Discard}
	if err := (npmAdapter{}).InstallNoScripts(ctx, proj, opts); err != nil {
		t.Fatalf("InstallNoScripts: %v", err)
	}
	if _, err := os.Stat(filepath.Join(proj, "node_modules", "evil-dep", "package.json")); err != nil {
		t.Fatalf("dependency not installed: %v", err)
	}
	if n := countEntries(t, markers); n != 0 {
		t.Fatalf("%d lifecycle script(s) ran", n)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func countEntries(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
