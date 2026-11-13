package policy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcceptanceExpired(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name, expires string
		want          bool
	}{
		{"no expiry", "", false},
		{"future date", "2027-05-12", false},
		{"today", "2026-11-12", false},
		{"yesterday", "2026-11-11", true},
		{"invalid format", "not-a-date", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Acceptance{Expires: tt.expires}).Expired(now); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAcceptanceValidate(t *testing.T) {
	for _, tt := range []struct {
		name string
		acc  Acceptance
		err  string
	}{
		{"valid", Acceptance{Rule: "SI-CODE-001", Reason: "safe"}, ""},
		{"missing rule", Acceptance{Reason: "safe"}, "rule required"},
		{"missing reason", Acceptance{Rule: "SI-CODE-001"}, "reason required"},
		{"bad expiry", Acceptance{Rule: "R", Reason: "x", Expires: "soon"}, "invalid expires"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.acc.Validate()
			if (err != nil) != (tt.err != "") || (err != nil && !strings.Contains(err.Error(), tt.err)) {
				t.Errorf("Validate() = %v, want %q", err, tt.err)
			}
		})
	}
}

func TestAcceptFindingDurationExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	err := AcceptFinding(path, "vite", Acceptance{Version: "8.3.8", Rule: "SI-CODE-001", File: "a.js", Hash: "sha256:a", Reason: "ok", Expires: "90d"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	acc := f.AcceptFindings["vite"][0]
	want := time.Now().UTC().Add(90 * 24 * time.Hour).Format("2006-01-02")
	if acc.Expires != want {
		t.Errorf("Expires = %q, want the date %q", acc.Expires, want)
	}
	if acc.Expired(time.Now()) {
		t.Error("a 90d acceptance counts as expired")
	}
	if acc.At != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("At = %q", acc.At)
	}
	for _, bad := range []Acceptance{
		{Version: "1", Rule: "R", Reason: ""},
		{Version: "1", Rule: "", Reason: "x"},
		{Version: "1", Rule: "R", Reason: "x", Expires: "nope"},
	} {
		if AcceptFinding(path, "vite", bad) == nil {
			t.Errorf("AcceptFinding(%+v) = nil, want an error", bad)
		}
	}
	if err := AcceptFinding(path, "x", Acceptance{Version: "1", Rule: "R", Reason: "x", Expires: "12h"}); err != nil {
		t.Errorf("12h: %v", err)
	}
}

func TestAcceptFindingReplacesSameKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	base := Acceptance{Version: "1.0.0", Rule: "SI-CODE-001", File: "a.js", Hash: "sha256:old", Reason: "r1"}
	other := Acceptance{Version: "1.0.0", Rule: "SI-CODE-001", File: "b.js", Hash: "sha256:b", Reason: "r"}
	must(t, AcceptFinding(path, "p", base))
	must(t, AcceptFinding(path, "p", other))
	base.Hash, base.Reason = "sha256:new", "r2"
	must(t, AcceptFinding(path, "p", base))
	f, _ := Read(path)
	if len(f.AcceptFindings["p"]) != 2 {
		t.Fatalf("entries = %+v, want 2", f.AcceptFindings["p"])
	}
	if got := f.AcceptFindings["p"][0]; got.Hash != "sha256:new" || got.Reason != "r2" {
		t.Errorf("not replaced: %+v", got)
	}
	// Package-level: one entry per evidence.
	must(t, AcceptFinding(path, "t", Acceptance{Version: "1", Rule: "SI-REC-002", Integrity: "sha512-a", Evidence: "publisher x", Reason: "r"}))
	must(t, AcceptFinding(path, "t", Acceptance{Version: "1", Rule: "SI-REC-002", Integrity: "sha512-a", Evidence: "maintainers added: y", Reason: "r"}))
	must(t, AcceptFinding(path, "t", Acceptance{Version: "1", Rule: "SI-REC-002", Integrity: "sha512-b", Evidence: "publisher x", Reason: "r2"}))
	f, _ = Read(path)
	if len(f.AcceptFindings["t"]) != 2 || f.AcceptFindings["t"][0].Integrity != "sha512-b" {
		t.Errorf("package-level entries = %+v", f.AcceptFindings["t"])
	}
}

func TestRevokeFindingMatchesVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	must(t, AcceptFinding(path, "vite", Acceptance{Version: "8.3.8", Rule: "SI-CODE-001", File: "a.js", Reason: "r"}))
	must(t, AcceptFinding(path, "vite", Acceptance{Version: "8.3.9", Rule: "SI-CODE-001", File: "a.js", Reason: "r"}))
	ok, err := RevokeFinding(path, "vite", "8.3.7", "SI-CODE-001", "a.js")
	if err != nil || ok {
		t.Fatalf("revoking an unknown version = %v, %v", ok, err)
	}
	ok, err = RevokeFinding(path, "vite", "8.3.8", "SI-CODE-001", "a.js")
	if err != nil || !ok {
		t.Fatalf("revoke = %v, %v", ok, err)
	}
	f, _ := Read(path)
	if len(f.AcceptFindings["vite"]) != 1 || f.AcceptFindings["vite"][0].Version != "8.3.9" {
		t.Errorf("remaining = %+v", f.AcceptFindings["vite"])
	}
	ok, _ = RevokeFinding(path, "vite", "8.3.9", "SI-CODE-001", "a.js")
	f, _ = Read(path)
	if !ok || len(f.AcceptFindings) != 0 {
		t.Errorf("last revoke: ok %v, %+v", ok, f.AcceptFindings)
	}
}

func TestFindAcceptance(t *testing.T) {
	p := &Policy{File: File{AcceptFindings: map[string][]Acceptance{
		"vite": {
			{Version: "8.3.8", Rule: "SI-CODE-001", File: "a.js", Hash: "sha256:a", Reason: "code"},
			{Version: "8.3.8", Rule: "SI-REC-002", Integrity: "sha512-x", Evidence: "publisher x", Reason: "pkg"},
		},
	}}}
	for _, tt := range []struct {
		ver, rule, file string
		want            string
	}{
		{"8.3.8", "SI-CODE-001", "a.js", "code"},
		{"8.3.8", "SI-REC-002", "", "pkg"},
		{"8.3.7", "SI-CODE-001", "a.js", ""},
		{"8.3.8", "SI-CODE-001", "b.js", ""},
		{"8.3.8", "SI-CODE-002", "a.js", ""},
	} {
		acc, ok := p.FindAcceptance("vite", tt.ver, tt.rule, tt.file)
		if ok != (tt.want != "") || acc.Reason != tt.want {
			t.Errorf("FindAcceptance(%v) = %+v, %v", tt, acc, ok)
		}
	}
	if _, ok := p.FindAcceptance("other", "8.3.8", "SI-CODE-001", "a.js"); ok {
		t.Error("another package matched")
	}
}

func TestDisallowAcceptCannotBeWeakened(t *testing.T) {
	isolate(t)
	org := filepath.Join(t.TempDir(), "org.json")
	write(t, org, `{"disallowAccept": ["SI-REC-*", "SI-CODE-002"]}`)
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), `{"orgPolicy": "`+filepath.ToSlash(org)+`", "disallowAccept": [], "acceptFindings": {"p": [{"version":"1","rule":"SI-REC-002","reason":"x"}]}}`)
	p, err := Load(proj)
	if err != nil {
		t.Fatal(err)
	}
	for rule, want := range map[string]bool{"SI-REC-002": true, "SI-REC-001": true, "SI-CODE-002": true, "SI-CODE-001": false} {
		if got := p.AcceptForbidden(rule); got != want {
			t.Errorf("AcceptForbidden(%s) = %v, want %v", rule, got, want)
		}
	}
	all := &Policy{File: File{DisallowAccept: []string{"*"}}}
	if !all.AcceptForbidden("SI-CODE-001") {
		t.Error(`"*" does not forbid everything`)
	}
	if (&Policy{}).AcceptForbidden("SI-CODE-001") {
		t.Error("nothing is forbidden by default")
	}
}

func TestOrgAcceptancesInherited(t *testing.T) {
	isolate(t)
	org := filepath.Join(t.TempDir(), "org.json")
	write(t, org, `{"acceptFindings": {"tslib": [{"version":"2.9.1","rule":"SI-REC-002","integrity":"sha512-a","evidence":"publisher x","reason":"org reviewed"}]}}`)
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), `{"orgPolicy": "`+filepath.ToSlash(org)+`"}`)
	p, err := Load(proj)
	if err != nil {
		t.Fatal(err)
	}
	if acc, ok := p.FindAcceptance("tslib", "2.9.1", "SI-REC-002", ""); !ok || acc.Reason != "org reviewed" {
		t.Errorf("org acceptance not inherited: %+v %v", acc, ok)
	}
}

func TestPruneStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	must(t, AcceptFinding(path, "vite", Acceptance{Version: "8.3.7", Rule: "SI-CODE-001", File: "a.js", Reason: "r"}))
	must(t, AcceptFinding(path, "vite", Acceptance{Version: "8.3.8", Rule: "SI-CODE-001", File: "a.js", Reason: "r"}))
	must(t, AcceptFinding(path, "gone", Acceptance{Version: "1.0.0", Rule: "SI-CODE-001", File: "a.js", Reason: "r"}))
	n, err := PruneStale(path, func(pkg, ver string) bool { return pkg == "vite" && ver == "8.3.8" })
	if err != nil || n != 2 {
		t.Fatalf("PruneStale = %d, %v", n, err)
	}
	f, _ := Read(path)
	if len(f.AcceptFindings) != 1 || len(f.AcceptFindings["vite"]) != 1 || f.AcceptFindings["vite"][0].Version != "8.3.8" {
		t.Errorf("remaining = %+v", f.AcceptFindings)
	}
	if n, _ := PruneStale(path, func(string, string) bool { return true }); n != 0 {
		t.Errorf("nothing stale, pruned %d", n)
	}
}

func TestPruneAcceptancesExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	must(t, AcceptFinding(path, "a", Acceptance{Version: "1", Rule: "R", File: "x", Reason: "r", Expires: "2026-01-01"}))
	must(t, AcceptFinding(path, "b", Acceptance{Version: "1", Rule: "R", File: "x", Reason: "r", Expires: "2999-01-01"}))
	must(t, AcceptFinding(path, "c", Acceptance{Version: "1", Rule: "R", File: "x", Reason: "r"}))
	n, err := PruneAcceptances(path)
	if err != nil || n != 1 {
		t.Fatalf("PruneAcceptances = %d, %v", n, err)
	}
	f, _ := Read(path)
	if len(f.AcceptFindings) != 2 || f.AcceptFindings["a"] != nil {
		t.Errorf("remaining = %+v", f.AcceptFindings)
	}
}

func TestAcceptFindingsOverlay(t *testing.T) {
	p := &Policy{File: File{AcceptFindings: map[string][]Acceptance{}}}
	p.overlay(&File{AcceptFindings: map[string][]Acceptance{"vite": {{Rule: "SI-CODE-001", Reason: "org"}}}})
	p.overlay(&File{AcceptFindings: map[string][]Acceptance{"vite": {{Rule: "SI-CODE-002", Reason: "project"}}}})
	if len(p.AcceptFindings["vite"]) != 2 {
		t.Errorf("after overlay: %+v", p.AcceptFindings["vite"])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
