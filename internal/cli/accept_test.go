package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/policy"
)

// runAccept runs `safe-install accept args...` with the given stdin text and
// terminal state.
func runAcceptCLI(t *testing.T, tty bool, input string, args ...string) (out string, err error) {
	t.Helper()
	return runAcceptCLIReader(t, tty, strings.NewReader(input), args...)
}

func runAcceptCLIReader(t *testing.T, tty bool, in io.Reader, args ...string) (out string, err error) {
	t.Helper()
	prev := acceptTerminal
	acceptTerminal = func() bool { return tty }
	t.Cleanup(func() { acceptTerminal = prev })
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetIn(in)
	root.SetArgs(append([]string{"accept"}, args...))
	err = root.Execute()
	return buf.String(), err
}

func projectFile(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, policy.FileName))
	if err != nil {
		return ""
	}
	return string(data)
}

func TestParsePackageVersion(t *testing.T) {
	for in, want := range map[string][2]string{
		"tslib@2.9.1":           {"tslib", "2.9.1"},
		"@scope/name@1.2.3":     {"@scope/name", "1.2.3"},
		"@scope/name@1.0.0-b@1": {"@scope/name@1.0.0-b", "1"},
	} {
		n, v, err := parsePackageVersion(in)
		if err != nil || n != want[0] || v != want[1] {
			t.Errorf("%s -> %q %q %v", in, n, v, err)
		}
	}
	for _, bad := range []string{"tslib", "@scope/name", "tslib@", "@x"} {
		if _, _, err := parsePackageVersion(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestAcceptNoTTYRefusesAndWritesNothing(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	out, err := runAcceptCLI(t, false, "y\n", "tslib@2.9.1", "SI-REC-002", "--reason", "ok")
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("want terminal refusal, got %v\n%s", err, out)
	}
	if _, err := runAcceptCLI(t, false, "", "tslib@2.9.1", "SI-REC-002", "--revoke"); err == nil {
		t.Error("revoke must also need a terminal")
	}
	if got := projectFile(t, dir); got != "" {
		t.Errorf("wrote %s", got)
	}
}

func TestAcceptPackageLevelTslib(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	if _, err := runCLIOut(t, "check", "--fail-on", "high"); exitCode(err) != ExitPolicyFailure {
		t.Fatalf("flagged before accept: %v", err)
	}
	out, err := runAcceptCLI(t, true, "y\n", "tslib@2.9.1", "SI-REC-002", "--reason", "Microsoft's release account", "--expires", "90d")
	if err != nil {
		t.Fatalf("accept: %v\n%s", err, out)
	}
	for _, want := range []string{"publisher microsoft1es", "sha512-tslib291", "Accept? [y/N]", "commit .safe-install.json"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	file := projectFile(t, dir)
	for _, want := range []string{`"integrity": "sha512-tslib291"`, `"evidence": "publisher microsoft1es"`, `"rule": "SI-REC-002"`} {
		if !strings.Contains(file, want) {
			t.Errorf("file missing %q:\n%s", want, file)
		}
	}
	if strings.Contains(file, "90d") {
		t.Errorf("expiry not converted:\n%s", file)
	}
	if out, err := runCLIOut(t, "check", "--fail-on", "high"); err != nil {
		t.Fatalf("check after accept: %v\n%s", err, out)
	}
}

func TestAcceptAnswerNoWritesNothing(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	for _, in := range []string{"n\n", "\n", ""} {
		if _, err := runAcceptCLI(t, true, in, "tslib@2.9.1", "SI-REC-002", "--reason", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	if got := projectFile(t, dir); got != "" {
		t.Errorf("wrote %s", got)
	}
}

func TestAcceptCodeFindingWithFile(t *testing.T) {
	dir := scanProject(t, true)
	out, err := runAcceptCLI(t, true, "y\n", "evil@1.0.0", "SI-CODE-002", "--file", "index.js", "--reason", "test key")
	if err != nil {
		t.Fatalf("accept: %v\n%s", err, out)
	}
	if !strings.Contains(out, "id_rsa") || !strings.Contains(out, ">") {
		t.Errorf("flagged lines not shown:\n%s", out)
	}
	hash, _ := sha256File(filepath.Join(dir, "node_modules/evil"), "index.js")
	if file := projectFile(t, dir); !strings.Contains(file, hash) || !strings.Contains(file, `"file": "index.js"`) {
		t.Errorf("hash not written:\n%s", file)
	}
	// index.js is accepted; lib/other.js is still flagged.
	if _, err := runCLIOut(t, "scan", "--fail-on", "high"); exitCode(err) != ExitPolicyFailure {
		t.Fatalf("the other file must still fail: %v", err)
	}
	if _, err := runAcceptCLI(t, true, "y\n", "evil@1.0.0", "SI-CODE-002", "--file", "lib/other.js", "--reason", "same"); err != nil {
		t.Fatal(err)
	}
	if out, err := runCLIOut(t, "scan", "--fail-on", "high"); err != nil {
		t.Fatalf("scan after accepting both: %v\n%s", err, out)
	}
}

func TestAcceptRefusals(t *testing.T) {
	dir := scanProject(t, false)
	for name, args := range map[string][]string{
		"rule not in file":     {"evil@1.0.0", "SI-CODE-001", "--file", "index.js", "--reason", "x"},
		"file without finding": {"evil@1.0.0", "SI-CODE-002", "--file", "package.json", "--reason", "x"},
		"version not locked":   {"evil@9.9.9", "SI-CODE-002", "--file", "index.js", "--reason", "x"},
		"no reason":            {"evil@1.0.0", "SI-CODE-002", "--file", "index.js"},
		"file escapes package": {"evil@1.0.0", "SI-CODE-002", "--file", "../../package.json", "--reason", "x"},
	} {
		if out, err := runAcceptCLI(t, true, "y\n", args...); err == nil {
			t.Errorf("%s: should refuse\n%s", name, out)
		}
	}
	if got := projectFile(t, dir); got != "" {
		t.Errorf("wrote %s", got)
	}
}

func TestAcceptRuleNotFoundPackageLevel(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	if _, err := runAcceptCLI(t, true, "y\n", "tslib@2.9.1", "SI-TYPO-001", "--reason", "x"); err == nil {
		t.Error("should refuse a rule the package does not trigger")
	}
	if got := projectFile(t, dir); got != "" {
		t.Errorf("wrote %s", got)
	}
}

func TestAcceptNeverBlockOrMalware(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	// A block finding: blocked by policy.
	writeFile(t, filepath.Join(dir, policy.FileName), `{"blockPackages":["tslib"]}`)
	before := projectFile(t, dir)
	if _, err := runAcceptCLI(t, true, "y\n", "tslib@2.9.1", "SI-POL-001", "--reason", "x", "--force"); err == nil {
		t.Error("block finding accepted")
	}
	// A malware advisory.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-2026-1"}]}]}`))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_OSV_URL", srv.URL)
	writeFile(t, filepath.Join(dir, policy.FileName), "{}")
	_, err := runAcceptCLI(t, true, "y\n", "tslib@2.9.1", "SI-VUL-001", "--reason", "x", "--force")
	if err == nil || !strings.Contains(err.Error(), "malware") {
		t.Errorf("malware accepted or wrong error: %v", err)
	}
	if got := strings.TrimSpace(projectFile(t, dir)); got != "{}" || before == "" {
		t.Errorf("file changed: %s", got)
	}
}

func TestAcceptOrgDisallowRefuses(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	org := filepath.Join(t.TempDir(), "org.json")
	writeFile(t, org, `{"disallowAccept":["SI-REC-*"]}`)
	t.Setenv("SAFE_INSTALL_ORG_POLICY", org)
	_, err := runAcceptCLI(t, true, "y\n", "tslib@2.9.1", "SI-REC-002", "--reason", "x")
	if err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("want org refusal, got %v", err)
	}
	if got := projectFile(t, dir); got != "" {
		t.Errorf("wrote %s", got)
	}
}

func TestAcceptRevokeOnlyThatVersion(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	writeFile(t, filepath.Join(dir, policy.FileName), `{"acceptFindings":{"tslib":[
		{"version":"2.9.1","rule":"SI-REC-002","integrity":"a","evidence":"e","reason":"r"},
		{"version":"2.9.0","rule":"SI-REC-002","integrity":"b","evidence":"e","reason":"r"}]}}`)
	out, err := runAcceptCLI(t, true, "", "tslib@2.9.1", "SI-REC-002", "--revoke")
	if err != nil {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	file := projectFile(t, dir)
	if strings.Contains(file, `"2.9.1"`) || !strings.Contains(file, `"2.9.0"`) {
		t.Errorf("wrong entries left:\n%s", file)
	}
	if _, err := runAcceptCLI(t, true, "", "tslib@2.9.1", "SI-REC-002", "--revoke"); err == nil {
		t.Error("revoking a missing entry should fail")
	}
}

func TestAcceptGlobalAndScoped(t *testing.T) {
	scanProject(t, false)
	gp, _ := policy.GlobalPath()
	out, err := runAcceptCLI(t, true, "y\n", "evil@1.0.0", "SI-CODE-002", "--file", "index.js", "--reason", "x", "--global")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if data, _ := os.ReadFile(gp); !strings.Contains(string(data), "SI-CODE-002") {
		t.Errorf("global file: %s", data)
	}
}
