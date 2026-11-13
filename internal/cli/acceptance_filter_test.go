package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
)

func polWith(pkg string, accs ...policy.Acceptance) *policy.Policy {
	return &policy.Policy{File: policy.File{AcceptFindings: map[string][]policy.Acceptance{pkg: accs}}}
}

func pkgDirWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func codeReport(file string, sev analyze.Severity) *analyze.Report {
	p := &lockfile.Package{ID: "vite@8.3.8", Name: "vite", Version: "8.3.8", Integrity: "sha512-v"}
	fs := []analyze.Finding{{Rule: "SI-CODE-001", Severity: sev, Message: file + " runs a downloader", File: file}}
	res := analyze.Result{Package: p, Findings: fs}
	res.Score, res.Level = analyze.Score(fs)
	return &analyze.Report{Results: []analyze.Result{res}}
}

func apply(rep *analyze.Report, pol *policy.Policy, dir string) string {
	var warn bytes.Buffer
	applyAcceptances(rep, pol, func(string) string { return dir }, &warn)
	return warn.String()
}

func TestApplyCodeAcceptanceNeedsFileAndHash(t *testing.T) {
	dir := pkgDirWith(t, map[string]string{"dist/node.js": "evil()", "dist/other.js": "evil()"})
	hash, err := sha256File(dir, "dist/node.js")
	if err != nil {
		t.Fatal(err)
	}
	acc := policy.Acceptance{Version: "8.3.8", Rule: "SI-CODE-001", File: "dist/node.js", Hash: hash, Reason: "registry read only", By: "ben"}

	rep := codeReport("dist/node.js", analyze.High)
	if warn := apply(rep, polWith("vite", acc), dir); warn != "" {
		t.Errorf("warning for a good acceptance: %q", warn)
	}
	got := rep.Results[0]
	if got.Findings[0].Accepted == nil || got.Findings[0].Accepted.Reason != "registry read only" {
		t.Fatalf("not accepted: %+v", got.Findings[0])
	}
	if got.Level != analyze.LevelNone || got.Score != 0 || rep.Worst() != analyze.LevelNone {
		t.Errorf("score/level still count the accepted finding: %d %v", got.Score, got.Level)
	}

	// The file changed after the review.
	if err := os.WriteFile(filepath.Join(dir, "dist/node.js"), []byte("evil(); worse()"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep = codeReport("dist/node.js", analyze.High)
	warn := apply(rep, polWith("vite", acc), dir)
	if rep.Results[0].Findings[0].Accepted != nil || rep.Results[0].Level != analyze.LevelHigh {
		t.Errorf("changed file still accepted")
	}
	if !strings.Contains(warn, "hash mismatch") || !strings.Contains(warn, "vite@8.3.8 SI-CODE-001 dist/node.js") {
		t.Errorf("warning = %q", warn)
	}

	// Another file of the same package.
	rep = codeReport("dist/other.js", analyze.High)
	apply(rep, polWith("vite", acc), dir)
	if rep.Results[0].Findings[0].Accepted != nil {
		t.Error("an acceptance for one file covers another")
	}

	// Another version.
	acc.Version = "8.3.7"
	rep = codeReport("dist/node.js", analyze.High)
	apply(rep, polWith("vite", acc), dir)
	if rep.Results[0].Findings[0].Accepted != nil {
		t.Error("an acceptance for one version covers another")
	}
}

func TestApplyCodeAcceptanceWithoutInstalledFileUsesScannerHash(t *testing.T) {
	acc := policy.Acceptance{Version: "8.3.8", Rule: "SI-CODE-001", File: "a.js", Hash: "sha256:aaa", Reason: "ok"}
	rep := codeReport("a.js", analyze.High)
	rep.Results[0].Findings[0].FileHash = "sha256:aaa"
	applyAcceptances(rep, polWith("vite", acc), nil, nil)
	if rep.Results[0].Findings[0].Accepted == nil {
		t.Fatal("deep scan hash did not match")
	}
	rep = codeReport("a.js", analyze.High)
	rep.Results[0].Findings[0].FileHash = "sha256:bbb"
	var warn bytes.Buffer
	applyAcceptances(rep, polWith("vite", acc), nil, &warn)
	if rep.Results[0].Findings[0].Accepted != nil || !strings.Contains(warn.String(), "hash mismatch") {
		t.Errorf("accepted %v, warning %q", rep.Results[0].Findings[0].Accepted, warn.String())
	}
	rep = codeReport("a.js", analyze.High) // no hash at all: nothing to compare
	applyAcceptances(rep, polWith("vite", acc), nil, &warn)
	if rep.Results[0].Findings[0].Accepted != nil {
		t.Error("accepted without any content to compare")
	}
}

func TestApplyExpiredAcceptanceSaysSo(t *testing.T) {
	dir := pkgDirWith(t, map[string]string{"a.js": "x"})
	hash, _ := sha256File(dir, "a.js")
	acc := policy.Acceptance{Version: "8.3.8", Rule: "SI-CODE-001", File: "a.js", Hash: hash, Reason: "ok", Expires: "2026-01-01"}
	rep := codeReport("a.js", analyze.High)
	warn := apply(rep, polWith("vite", acc), dir)
	if rep.Results[0].Findings[0].Accepted != nil || !strings.Contains(warn, "expired on 2026-01-01") {
		t.Errorf("accepted %v, warning %q", rep.Results[0].Findings[0].Accepted, warn)
	}
}

func TestApplyNeverAcceptsBlockOrForbidden(t *testing.T) {
	dir := pkgDirWith(t, map[string]string{"a.js": "x"})
	hash, _ := sha256File(dir, "a.js")
	acc := policy.Acceptance{Version: "8.3.8", Rule: "SI-CODE-001", File: "a.js", Hash: hash, Reason: "ok"}

	rep := codeReport("a.js", analyze.Block)
	warn := apply(rep, polWith("vite", acc), dir)
	if rep.Results[0].Findings[0].Accepted != nil || rep.Results[0].Level != analyze.LevelBlock || !strings.Contains(warn, "cannot be accepted") {
		t.Errorf("block finding accepted (%q)", warn)
	}

	pol := polWith("vite", acc)
	pol.DisallowAccept = []string{"SI-CODE-*"}
	rep = codeReport("a.js", analyze.High)
	warn = apply(rep, pol, dir)
	if rep.Results[0].Findings[0].Accepted != nil || !strings.Contains(warn, "organization policy forbids") {
		t.Errorf("forbidden rule accepted (%q)", warn)
	}
}

func pkgReport(version, integrity, evidence string, rule string, sev analyze.Severity) *analyze.Report {
	p := &lockfile.Package{ID: "tslib@" + version, Name: "tslib", Version: version, Integrity: integrity}
	fs := []analyze.Finding{{Rule: rule, Severity: sev, Message: "published by someone", Evidence: evidence}}
	res := analyze.Result{Package: p, Findings: fs}
	res.Score, res.Level = analyze.Score(fs)
	return &analyze.Report{Results: []analyze.Result{res}}
}

func TestApplyPackageLevelAcceptance(t *testing.T) {
	acc := policy.Acceptance{Version: "2.9.1", Rule: "SI-REC-002", Integrity: "sha512-a", Evidence: "publisher microsoft1es", Reason: "Microsoft"}
	for _, tt := range []struct {
		name, ver, integrity, evidence, warn string
		accepted                             bool
	}{
		{"match", "2.9.1", "sha512-a", "publisher microsoft1es", "", true},
		{"other integrity", "2.9.1", "sha512-b", "publisher microsoft1es", "integrity mismatch", false},
		{"other evidence", "2.9.1", "sha512-a", "publisher someone-else", "evidence changed", false},
		{"other version", "2.9.2", "sha512-a", "publisher microsoft1es", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rep := pkgReport(tt.ver, tt.integrity, tt.evidence, "SI-REC-002", analyze.High)
			var warn bytes.Buffer
			applyAcceptances(rep, polWith("tslib", acc), nil, &warn)
			if got := rep.Results[0].Findings[0].Accepted != nil; got != tt.accepted {
				t.Errorf("accepted = %v, want %v", got, tt.accepted)
			}
			if !strings.Contains(warn.String(), tt.warn) || (tt.warn == "" && warn.Len() > 0) {
				t.Errorf("warning = %q, want %q", warn.String(), tt.warn)
			}
		})
	}
}

func TestApplyPackageLevelUsesRegistryIntegrityWhenLockfileHasNone(t *testing.T) {
	acc := policy.Acceptance{Version: "2.9.1", Rule: "SI-REC-002", Integrity: "sha512-reg", Evidence: "e", Reason: "r"}
	rep := pkgReport("2.9.1", "", "e", "SI-REC-002", analyze.High)
	applyAcceptances(rep, polWith("tslib", acc), nil, nil)
	if rep.Results[0].Findings[0].Accepted != nil {
		t.Fatal("accepted with nothing to pin to")
	}
	rep = pkgReport("2.9.1", "", "e", "SI-REC-002", analyze.High)
	rep.Results[0].RegistryIntegrity = "sha512-reg"
	applyAcceptances(rep, polWith("tslib", acc), nil, nil)
	if rep.Results[0].Findings[0].Accepted == nil {
		t.Fatal("registry integrity not used")
	}
}

func TestApplyNeverAcceptsMalwareOrHighVulns(t *testing.T) {
	acc := policy.Acceptance{Version: "2.9.1", Rule: "SI-VUL-001", Integrity: "sha512-a", Evidence: "MAL-1", Reason: "r"}
	rep := pkgReport("2.9.1", "sha512-a", "MAL-1", "SI-VUL-001", analyze.Block)
	applyAcceptances(rep, polWith("tslib", acc), nil, nil)
	if rep.Results[0].Findings[0].Accepted != nil || rep.Results[0].Level != analyze.LevelBlock {
		t.Error("malware advisory accepted")
	}
	// A recorded entry passed `accept --force`, so a high vulnerability
	// applies, and its malware sibling still does not even with force.
	rep = pkgReport("2.9.1", "sha512-a", "GHSA-1", "SI-VUL-001", analyze.High)
	acc.Evidence = "GHSA-1"
	applyAcceptances(rep, polWith("tslib", acc), nil, nil)
	if rep.Results[0].Findings[0].Accepted == nil || rep.Results[0].Level != analyze.LevelNone {
		t.Error("a high-severity vulnerability with a recorded (forced) acceptance was not applied")
	}
	acc.Evidence = "MAL-1"
	for _, f := range []analyze.Finding{{Rule: "SI-VUL-001", Severity: analyze.Block}, {Rule: "SI-INT-001", Severity: analyze.Block}} {
		if ok, _ := analyze.Acceptable(f, true); ok {
			t.Errorf("%s at block is acceptable even with force", f.Rule)
		}
	}
	rep = pkgReport("2.9.1", "sha512-a", "MAL-1", "SI-VUL-001", analyze.Medium)
	applyAcceptances(rep, polWith("tslib", acc), nil, nil)
	if rep.Results[0].Findings[0].Accepted == nil {
		t.Error("a medium vulnerability could not be accepted")
	}
}

func TestSeveralEvidencesOfOneRule(t *testing.T) {
	a1 := policy.Acceptance{Version: "2.9.1", Rule: "SI-REC-002", Integrity: "sha512-a", Evidence: "publisher x", Reason: "r"}
	a2 := policy.Acceptance{Version: "2.9.1", Rule: "SI-REC-002", Integrity: "sha512-a", Evidence: "maintainers added: y", Reason: "r"}
	p := &lockfile.Package{ID: "tslib@2.9.1", Name: "tslib", Version: "2.9.1", Integrity: "sha512-a"}
	fs := []analyze.Finding{
		{Rule: "SI-REC-002", Severity: analyze.High, Evidence: "publisher x"},
		{Rule: "SI-REC-002", Severity: analyze.Low, Evidence: "maintainers added: y"},
	}
	rep := &analyze.Report{Results: []analyze.Result{{Package: p, Findings: fs}}}
	applyAcceptances(rep, polWith("tslib", a1, a2), nil, nil)
	if fs[0].Accepted == nil || fs[1].Accepted == nil || rep.Worst() != analyze.LevelNone {
		t.Errorf("findings = %+v, worst %v", fs, rep.Worst())
	}
}

func TestStaleAcceptances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, policy.FileName)
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if err := policy.AcceptFinding(path, "vite", policy.Acceptance{Version: v, Rule: "SI-CODE-001", File: "a.js", Reason: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	pol := &policy.Policy{ProjectPath: path}
	got := staleAcceptances(pol, func(pkg, ver string) bool { return ver == "1.1.0" })
	if len(got) != 1 || got[0] != "vite@1.0.0" {
		t.Errorf("stale = %v", got)
	}
}
