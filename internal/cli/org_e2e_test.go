package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func orgPolicyFile(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "org.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_INSTALL_ORG_POLICY", path)
}

func TestOrgBlockOverridesProjectApproval(t *testing.T) {
	markers := installProject(t)
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	// The project approves good-dep...
	if out, err := runInstallCLI(t, "n\ny\n", true); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	clearMarkers(t, markers)
	// ...but the organization blocks it.
	orgPolicyFile(t, `{"blockPackages": ["good-*"]}`)
	out, err := runInstallCLI(t, "", false)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if len(listMarkers(t, markers)) != 0 {
		t.Fatalf("a blocked package's scripts ran:\n%s", out)
	}
	if !strings.Contains(out, "SI-POL-001") || !strings.Contains(out, "good-dep@1.0.0") {
		t.Errorf("block not reported:\n%s", out)
	}
	if _, err := runInstallCLI(t, "", false, "--ci"); exitCode(err) != ExitPolicyFailure {
		t.Errorf("--ci exit = %d, want %d", exitCode(err), ExitPolicyFailure)
	}
}

func TestCheckFlagsOrgBlockedPackage(t *testing.T) {
	checkProject(t, 400*24*time.Hour, true)
	orgPolicyFile(t, `{"blockPackages": ["fresh"]}`)
	out, err := runCLIOut(t, "check")
	if exitCode(err) != ExitPolicyFailure || !strings.Contains(out, "SI-POL-001") {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, out)
	}
}

func TestOrgMinimumsApplyToCheck(t *testing.T) {
	checkProject(t, 2*time.Hour, true) // 2h old: fine for 1h, not for the org's 7d
	if err := os.WriteFile(".safe-install.json", []byte(`{"minReleaseAge": "1h"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	orgPolicyFile(t, `{"minReleaseAge": "7d"}`)
	out, err := runCLIOut(t, "check", "--fail-on", "medium")
	if exitCode(err) != ExitPolicyFailure || !strings.Contains(out, "SI-REC-001") {
		t.Fatalf("org minimum not applied: exit %d\n%s", exitCode(err), out)
	}
}

func TestOrgPolicyUnavailableStops(t *testing.T) {
	checkProject(t, 400*24*time.Hour, true)
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_ORG_POLICY", "http://127.0.0.1:1/policy.json")
	if _, err := runCLIOut(t, "check"); err == nil || !strings.Contains(err.Error(), "organization policy") {
		t.Fatalf("err = %v", err)
	}
}
