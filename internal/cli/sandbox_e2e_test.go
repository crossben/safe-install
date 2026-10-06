//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/sandbox"
)

// testPackageDir is this package's directory, captured before any test chdirs.
var testPackageDir, _ = os.Getwd()

// sandboxHome points HOME (and npm's cache) at a folder outside the temp
// directory, which the sandbox leaves writable on purpose.
func sandboxHome(t *testing.T) string {
	t.Helper()
	if sandbox.Check(false) != nil {
		t.Skipf("Landlock cannot sandbox files and TCP here: %v", sandbox.Check(false))
	}
	// Relative to the package directory captured at start: tests chdir into
	// temporary projects, which live under the (writable) temp folder.
	home, err := os.MkdirTemp(testPackageDir, ".sandbox-home-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("npm_config_cache", filepath.Join(home, ".npm"))
	return home
}

func TestSandboxBlocksSneakyScript(t *testing.T) {
	_, marker := sneakyProject(t) // must run first: it sets its own HOME
	home := sandboxHome(t)
	out, err := runInstallCLI(t, "", false, "--yes", "--sandbox")
	if err == nil {
		t.Fatalf("install succeeded although the sandbox should stop the script:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); !os.IsNotExist(err) {
		t.Fatalf("~/.bashrc was written despite the sandbox: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("script kept going after the blocked write")
	}
	if !strings.Contains(out, "sandbox") {
		t.Errorf("output does not mention the sandbox:\n%s", out)
	}
}

func TestSandboxLetsLegitimateScriptsRun(t *testing.T) {
	markers := installProject(t)
	sandboxHome(t)
	out, err := runInstallCLI(t, "", false, "--yes", "--sandbox")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); !slices.Equal(got, goodMarkers) {
		t.Fatalf("markers = %v, want %v\n%s", got, goodMarkers, out)
	}
}

func TestSandboxWithMonitor(t *testing.T) {
	sneakyProject(t)
	home := sandboxHome(t)
	out, _ := runInstallCLI(t, "", false, "--yes", "--sandbox", "--monitor")
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); !os.IsNotExist(err) {
		data, _ := os.ReadFile(filepath.Join(home, ".bashrc"))
		t.Fatalf("~/.bashrc was written (%q):\n%s", data, out)
	}
	if !strings.Contains(out, "SI-MON-004") {
		t.Errorf("the monitor should still report the blocked attempt:\n%s", out)
	}
}
