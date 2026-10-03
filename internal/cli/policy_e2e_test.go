package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/policy"
)

func clearMarkers(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

func readPolicy(t *testing.T) *policy.File {
	t.Helper()
	f, err := policy.Read(policy.FileName)
	if err != nil {
		t.Fatalf("reading %s: %v", policy.FileName, err)
	}
	return f
}

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestApprovalIsRemembered(t *testing.T) {
	markers := installProject(t)
	if out, err := runInstallCLI(t, "n\ny\n", true); err != nil {
		t.Fatalf("first install: %v\n%s", err, out)
	}
	if _, ok := readPolicy(t).AllowScripts["good-dep"]; !ok {
		t.Fatal("approval not saved")
	}
	clearMarkers(t, markers)

	// Not interactive: the saved approval alone lets good-dep run.
	out, err := runInstallCLI(t, "", false)
	if err != nil {
		t.Fatalf("second install: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); !slices.Equal(got, goodMarkers) {
		t.Fatalf("markers = %v, want %v\n%s", got, goodMarkers, out)
	}
}

func TestOnceIsNotRemembered(t *testing.T) {
	markers := installProject(t)
	if out, err := runInstallCLI(t, "n\no\n", true); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); !slices.Equal(got, goodMarkers) {
		t.Fatalf("markers = %v", got)
	}
	if _, err := os.Stat(policy.FileName); !os.IsNotExist(err) {
		t.Fatalf("policy file written for a one-time approval: %v", err)
	}
}

func TestChangedScriptNeedsReapproval(t *testing.T) {
	markers := installProject(t)
	if out, err := runInstallCLI(t, "n\ny\n", true); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	clearMarkers(t, markers)

	// Tamper with the file the approved postinstall runs.
	path := filepath.Join("node_modules", "good-dep", "marker.js")
	if err := os.WriteFile(path, []byte(markerFile+"// payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runInstallCLI(t, "", false)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); len(got) != 0 {
		t.Fatalf("changed scripts ran: %v", got)
	}
	if !strings.Contains(out, "SI-SCR-005") {
		t.Errorf("no SI-SCR-005 in output:\n%s", out)
	}
}

func TestApproveCommand(t *testing.T) {
	markers := installProject(t)
	if out, err := runInstallCLI(t, "", false); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	out, err := runCmd(t, "approve", "good-dep")
	if err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	if got := listMarkers(t, markers); !slices.Equal(got, goodMarkers) {
		t.Fatalf("approve did not run the scripts: %v\n%s", got, out)
	}
	if readPolicy(t).AllowScripts["good-dep"].Version != "1.0.0" {
		t.Fatal("approval not saved")
	}

	// High-risk scripts need --force.
	if _, err := runCmd(t, "approve", "evil-dep"); err == nil {
		t.Fatal("approving a blocking script without --force succeeded")
	}
	if _, ok := readPolicy(t).AllowScripts["evil-dep"]; ok {
		t.Fatal("evil-dep approved without --force")
	}
	if _, err := runCmd(t, "approve", "not-installed"); err == nil {
		t.Fatal("approving an unknown package succeeded")
	}

	if out, err := runCmd(t, "approve", "--revoke", "good-dep"); err != nil {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if _, ok := readPolicy(t).AllowScripts["good-dep"]; ok {
		t.Fatal("revoke left the approval")
	}
}

func TestScriptsCommand(t *testing.T) {
	installProject(t)
	if out, err := runInstallCLI(t, "n\ny\n", true); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	out, err := runCmd(t, "scripts")
	if err != nil {
		t.Fatalf("scripts: %v\n%s", err, out)
	}
	for _, want := range []string{"evil-dep@1.0.0", "not approved", "BLOCK", "good-dep@1.0.0", "approved"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestExplainCommand(t *testing.T) {
	out, err := runCmd(t, "explain", "si-scr-002")
	if err != nil || !strings.Contains(out, "downloads and executes") {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	if out, err := runCmd(t, "explain"); err != nil || !strings.Contains(out, "SI-REC-001") || !strings.Contains(out, "SI-INT-002") {
		t.Fatalf("explain list: %v\n%s", err, out)
	}
	if _, err := runCmd(t, "explain", "SI-NOPE"); err == nil {
		t.Fatal("unknown rule explained")
	}
}

func TestShellInit(t *testing.T) {
	for shell, want := range map[string]string{"bash": "npm()", "zsh": "pnpm()", "fish": "function yarn", "pwsh": "function bun"} {
		out, err := runCmd(t, "shell-init", shell)
		if err != nil || !strings.Contains(out, want) || !strings.Contains(out, "safe-install install") {
			t.Errorf("%s: %v\n%s", shell, err, out)
		}
	}
	if _, err := runCmd(t, "shell-init", "tcsh"); err == nil {
		t.Error("unknown shell accepted")
	}
}

func TestCheckUsesPolicy(t *testing.T) {
	tests := []struct {
		name, policy string
		args         []string
		want         int
	}{
		{"excluded package", `{"minReleaseAgeExclude": ["fre*"]}`, nil, ExitOK},
		{"policy min age", `{"minReleaseAge": "1h"}`, nil, ExitOK},
		{"flag beats policy", `{"minReleaseAge": "1h"}`, []string{"--min-age", "3d"}, ExitPolicyFailure},
		{"policy failOn", `{"failOn": "medium"}`, []string{"--fail-on", "low"}, ExitPolicyFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkProject(t, 2*time.Hour, true)
			if err := os.WriteFile(policy.FileName, []byte(tt.policy), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"check", "--fail-on", "low"}, tt.args...)
			if tt.name == "policy failOn" {
				args = []string{"check"}
			}
			_, err := runCLIOut(t, args...)
			if got := exitCode(err); got != tt.want {
				t.Fatalf("exit = %d (%v), want %d", got, err, tt.want)
			}
		})
	}
}

func TestAddCommand(t *testing.T) {
	markers := installProject(t)
	if out, err := runInstallCLI(t, "", false); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	// A third scripted package, added by path.
	src := filepath.Join(t.TempDir(), "new-dep")
	mustMkdir(t, src)
	mustWriteJSON(t, filepath.Join(src, "package.json"), map[string]any{"name": "new-dep", "version": "1.0.0", "scripts": map[string]string{"postinstall": markerJS}})
	pack := exec.Command("npm", "pack", "--silent", "--pack-destination", ".")
	pack.Dir = src
	if out, err := pack.CombinedOutput(); err != nil {
		t.Fatalf("npm pack: %v\n%s", err, out)
	}
	tarball := filepath.Join(src, "new-dep-1.0.0.tgz")

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(""))
	root.SetArgs([]string{"add", "--min-age", "0", "--yes", tarball})
	if err := root.Execute(); err != nil {
		t.Fatalf("add: %v\n%s", err, out.String())
	}
	data, err := os.ReadFile("package.json")
	if err != nil || !strings.Contains(string(data), "new-dep") {
		t.Fatalf("new-dep not added to package.json: %s", data)
	}
	got := listMarkers(t, markers)
	if !slices.Contains(got, "new-dep-postinstall") || slices.Contains(got, "evil-dep-postinstall") {
		t.Fatalf("markers = %v\n%s", got, out.String())
	}
}
