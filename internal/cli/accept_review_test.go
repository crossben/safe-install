package cli

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
)

// scriptsProject installs "evil@1.0.0" by hand with a postinstall script
// whose file evals dynamic code (SI-SCR-003, High).
func scriptsProject(t *testing.T) string {
	t.Helper()
	dir := scanProject(t, false)
	writeFile(t, filepath.Join(dir, "node_modules/evil/package.json"),
		`{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node setup.js"}}`)
	writeFile(t, filepath.Join(dir, "node_modules/evil/setup.js"), "eval(Buffer.from('cHJpbnQ=','base64').toString())\n")
	writeFile(t, filepath.Join(dir, "node_modules/evil/index.js"), "module.exports = 1\n")
	return dir
}

func handEditedScr(t *testing.T, dir string) {
	t.Helper()
	acc := map[string]any{"version": "1.0.0", "rule": "SI-SCR-003", "integrity": "sha512-evil", "reason": "x"}
	data, _ := json.Marshal(map[string]any{"acceptFindings": map[string]any{"evil": []any{acc}}})
	writeFile(t, filepath.Join(dir, policy.FileName), string(data))
}

func TestScriptsIgnoresHandEditedInstallScriptAcceptance(t *testing.T) {
	dir := scriptsProject(t)
	handEditedScr(t, dir)
	out, stderr, err := runCLIBoth(t, "scripts")
	if err != nil {
		t.Fatalf("scripts: %v", err)
	}
	if strings.Contains(out, "ACCEPTED") || !strings.Contains(out, "! SI-SCR-003") {
		t.Errorf("an install-script finding was accepted:\n%s", out)
	}
	if !strings.Contains(stderr+out, "not applied") {
		t.Errorf("no warning:\n%s\n%s", out, stderr)
	}
}

func TestAcceptFindingsEmptyEvidenceDoesNotMatch(t *testing.T) {
	p := &lockfile.Package{ID: "a@1", Name: "a", Version: "1", Integrity: "sha512-x"}
	pol := policyWith(t, "a", policy.Acceptance{Version: "1", Rule: "SI-REC-002", Integrity: "sha512-x", Reason: "r"})
	fs := []analyze.Finding{{Rule: "SI-REC-002", Severity: analyze.High}}
	var warned []string
	acceptFindings(p, "", fs, pol, "", func(s string) { warned = append(warned, s) })
	if fs[0].Accepted != nil {
		t.Fatal("a finding without evidence was accepted by an entry without evidence")
	}
	if len(warned) == 0 {
		t.Error("no warning")
	}
}

func policyWith(t *testing.T, pkg string, a policy.Acceptance) *policy.Policy {
	t.Helper()
	dir := t.TempDir()
	data, _ := json.Marshal(map[string]any{"acceptFindings": map[string]any{pkg: []any{a}}})
	writeFile(t, filepath.Join(dir, policy.FileName), string(data))
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	pol, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestAcceptRefusesInstallScriptRule(t *testing.T) {
	dir := scriptsProject(t)
	out, err := runAcceptCLI(t, true, "y\n", "evil@1.0.0", "SI-SCR-003", "--reason", "x")
	if err == nil || !strings.Contains(err.Error(), "approve") {
		t.Fatalf("want a refusal pointing at approve, got %v\n%s", err, out)
	}
	if got := projectFile(t, dir); got != "" {
		t.Errorf("wrote %s", got)
	}
}

func TestAcceptReadsConfirmationBounded(t *testing.T) {
	tslibProject(t, tslibOpts{})
	// An endless stream of "y" with no newline: the answer is "no", and the
	// read stops.
	out, err := runAcceptCLIReader(t, true, endlessY{}, "tslib@2.9.1", "SI-REC-002", "--reason", "ok")
	if err != nil || !strings.Contains(out, "Not accepted") {
		t.Fatalf("err %v\n%s", err, out)
	}
}

type endlessY struct{}

func (endlessY) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'y'
	}
	return len(p), nil
}

var _ io.Reader = endlessY{}

// An install-script package whose lockfile has no integrity is pinned to the
// registry's dist.integrity.
func TestScriptsAcceptancePinnedToRegistryIntegrity(t *testing.T) {
	dir := scriptsProject(t)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{
		"":{"name":"p","dependencies":{"evil":"1.0.0"}},
		"node_modules/evil":{"version":"1.0.0","resolved":"https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"}}}`)
	recent := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	reg := map[string]any{"evil": map[string]any{
		"name": "evil",
		"time": map[string]string{"0.9.0": longAgo, "1.0.0": recent},
		"versions": map[string]any{
			"0.9.0": map[string]any{"version": "0.9.0", "_npmUser": map[string]string{"name": "old"}, "maintainers": []map[string]string{{"name": "old"}}, "dist": map[string]string{"integrity": "sha512-old"}},
			"1.0.0": map[string]any{"version": "1.0.0", "_npmUser": map[string]string{"name": "newbie"}, "maintainers": []map[string]string{{"name": "old"}, {"name": "newbie"}}, "dist": map[string]string{"integrity": "sha512-reg"}},
		}}}
	data, _ := json.Marshal(reg)
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", writeRegistry(t, string(data)))
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	acc := map[string]any{"version": "1.0.0", "rule": "SI-REC-002", "integrity": "sha512-reg", "evidence": "publisher newbie", "reason": "known publisher"}
	d, _ := json.Marshal(map[string]any{"acceptFindings": map[string]any{"evil": []any{acc}}})
	writeFile(t, filepath.Join(dir, policy.FileName), string(d))
	out, stderr, err := runCLIBoth(t, "scripts", "--min-age", "0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "SI-REC-002") || !strings.Contains(out, "ACCEPTED (known publisher") {
		t.Errorf("registry-pinned acceptance not applied:\n%s\n%s", out, stderr)
	}
}

// lockProject installs one flagged package by hand under pkgDir (relative to
// the project) with the given lockfile.
func lockProject(t *testing.T, lockName, lock, pkgDir, name string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"p","version":"1.0.0","dependencies":{"`+name+`":"1.0.0"}}`)
	writeFile(t, filepath.Join(dir, lockName), lock)
	pd := filepath.Join(dir, filepath.FromSlash(pkgDir))
	writeFile(t, filepath.Join(pd, "package.json"), `{"name":"`+name+`","version":"1.0.0"}`)
	writeFile(t, filepath.Join(pd, "index.js"), evilJS)
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", writeRegistry(t, "{}"))
	t.Chdir(dir)
	return dir
}

func acceptThenScan(t *testing.T, dir, pkgDir, spec string) {
	t.Helper()
	if _, err := runCLIOut(t, "scan"); exitCode(err) != ExitPolicyFailure {
		t.Fatalf("before accept: exit %d (%v)", exitCode(err), err)
	}
	if out, err := runAcceptCLI(t, true, "y\n", spec, "SI-CODE-002", "--file", "index.js", "--reason", "reads its own key"); err != nil {
		t.Fatalf("accept: %v\n%s", err, out)
	}
	out, stderr, err := runCLIBoth(t, "scan", "--fail-on", "high")
	if err != nil || !strings.Contains(out, "ACCEPTED (reads its own key") {
		t.Fatalf("after accept: %v\n%s\n%s", err, out, stderr)
	}
	// The file changes: flagged again.
	writeFile(t, filepath.Join(dir, filepath.FromSlash(pkgDir), "index.js"), evilJS+"\n// changed\n")
	if _, err := runCLIOut(t, "scan"); exitCode(err) != ExitPolicyFailure {
		t.Fatalf("changed file: exit %d (%v)", exitCode(err), err)
	}
}

func TestAcceptThenScanPnpmScopedPackage(t *testing.T) {
	dir := lockProject(t, "pnpm-lock.yaml", `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@acme/evil':
        specifier: 1.0.0
        version: 1.0.0

packages:

  '@acme/evil@1.0.0':
    resolution: {integrity: sha512-acme}

snapshots:

  '@acme/evil@1.0.0': {}
`, "node_modules/.pnpm/@acme+evil@1.0.0/node_modules/@acme/evil", "@acme/evil")
	acceptThenScan(t, dir, "node_modules/.pnpm/@acme+evil@1.0.0/node_modules/@acme/evil", "@acme/evil@1.0.0")
}

func TestAcceptThenScanYarnV1Package(t *testing.T) {
	dir := lockProject(t, "yarn.lock", `# yarn lockfile v1


evil@1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/evil/-/evil-1.0.0.tgz#abc"
  integrity sha512-evil
`, "node_modules/evil", "evil")
	acceptThenScan(t, dir, "node_modules/evil", "evil@1.0.0")
}
