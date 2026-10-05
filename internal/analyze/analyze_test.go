package analyze

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/osv"
	"github.com/crossben/safe-install/internal/popularity"
	"github.com/crossben/safe-install/internal/registry"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

type fakeFetcher struct {
	docs  map[string]*registry.Packument
	calls atomic.Int32
}

func (f *fakeFetcher) Packument(_ context.Context, name string) (*registry.Packument, error) {
	f.calls.Add(1)
	if d, ok := f.docs[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("%s: %w", name, registry.ErrNotFound)
}

type ver struct {
	v, user    string
	age        time.Duration
	maint      []string
	deprecate  string
	integrity  string
	trusted    bool // published by a trusted publisher (CI via OIDC)
	provenance bool
	scripts    bool // has a postinstall script
}

func doc(name string, vs ...ver) *registry.Packument {
	p := &registry.Packument{Name: name, Versions: map[string]registry.VersionMeta{}, Time: map[string]time.Time{}}
	for _, v := range vs {
		m := registry.VersionMeta{Version: v.v, NpmUser: registry.Person{Name: v.user}}
		for _, n := range v.maint {
			m.Maintainers = append(m.Maintainers, registry.Person{Name: n})
		}
		m.Deprecated = registry.FlexString(v.deprecate)
		m.Dist.Integrity = v.integrity
		if v.trusted {
			m.NpmUser = registry.Person{Name: "GitHub Actions", TrustedPublisher: &registry.TrustedPublisher{ID: "github"}}
		}
		if v.scripts {
			m.Scripts = map[string]string{"postinstall": "node install.js"}
		}
		if v.provenance {
			m.Dist.Attestations = &registry.Attestations{Provenance: &registry.Provenance{PredicateType: "https://slsa.dev/provenance/v1"}}
		}
		p.Versions[v.v] = m
		p.Time[v.v] = now.Add(-v.age)
	}
	return p
}

func graph(pkgs ...*lockfile.Package) *lockfile.Graph {
	g := &lockfile.Graph{Format: lockfile.NPMv3, Packages: map[string]*lockfile.Package{}}
	for _, p := range pkgs {
		p.ID = p.Name + "@" + p.Version
		g.Packages[p.ID] = p
	}
	return g
}

const day = 24 * time.Hour

func run(t *testing.T, f *fakeFetcher, pkgs ...*lockfile.Package) *Report {
	t.Helper()
	return Analyze(context.Background(), graph(pkgs...), f, Config{
		Now: now, MinReleaseAge: 72 * time.Hour, RegistryHosts: []string{"registry.npmjs.org"},
	})
}

func result(t *testing.T, r *Report, id string) Result {
	t.Helper()
	for _, res := range r.Results {
		if res.Package.ID == id {
			return res
		}
	}
	t.Fatalf("no result for %s", id)
	return Result{}
}

func hasRule(res Result, rule string, sev Severity) bool {
	for _, f := range res.Findings {
		if f.Rule == rule && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestRules(t *testing.T) {
	old := ver{v: "1.0.0", user: "alice", age: 400 * day, maint: []string{"alice"}, integrity: "sha512-old"}
	f := &fakeFetcher{docs: map[string]*registry.Packument{
		"fresh":      doc("fresh", old, ver{v: "1.1.0", user: "alice", age: 5 * time.Hour, maint: []string{"alice"}}),
		"newpub":     doc("newpub", old, ver{v: "1.1.0", user: "mallory", age: 30 * day, maint: []string{"alice", "mallory"}}),
		"deprecated": doc("deprecated", ver{v: "1.0.0", user: "a", age: 400 * day, deprecate: "use x"}),
		"clean":      doc("clean", old),
		"tampered":   doc("tampered", old),
	}}
	r := run(t, f,
		&lockfile.Package{Name: "fresh", Version: "1.1.0"},
		&lockfile.Package{Name: "newpub", Version: "1.1.0"},
		&lockfile.Package{Name: "deprecated", Version: "1.0.0"},
		&lockfile.Package{Name: "clean", Version: "1.0.0", Integrity: "sha512-old", Resolved: "https://registry.npmjs.org/clean/-/clean-1.0.0.tgz"},
		&lockfile.Package{Name: "tampered", Version: "1.0.0", Integrity: "sha512-evil", Resolved: "https://evil.example/tampered.tgz"},
		&lockfile.Package{Name: "clean", Version: "9.9.9"},
	)

	if res := result(t, r, "fresh@1.1.0"); !hasRule(res, "SI-REC-001", Medium) || res.Level != LevelMedium {
		t.Errorf("fresh: %+v", res)
	}
	res := result(t, r, "newpub@1.1.0")
	if !hasRule(res, "SI-REC-002", High) || !hasRule(res, "SI-REC-002", Low) || res.Level != LevelHigh {
		t.Errorf("newpub: %+v", res)
	}
	if res := result(t, r, "deprecated@1.0.0"); !hasRule(res, "SI-DEP-001", Low) || res.Level != LevelLow {
		t.Errorf("deprecated: %+v", res)
	}
	if res := result(t, r, "clean@1.0.0"); len(res.Findings) != 0 || res.Level != LevelNone {
		t.Errorf("clean: %+v", res)
	}
	res = result(t, r, "tampered@1.0.0")
	if !hasRule(res, "SI-INT-001", Block) || !hasRule(res, "SI-INT-002", High) || res.Level != LevelBlock || res.Score != 100 {
		t.Errorf("tampered: %+v", res)
	}
	if res := result(t, r, "clean@9.9.9"); !hasRule(res, "SI-DEP-001", Low) {
		t.Errorf("missing version: %+v", res)
	}
	// One fetch per package name, even with two versions of "clean".
	if n := f.calls.Load(); n != 5 {
		t.Errorf("fetches = %d, want 5", n)
	}
}

func TestPublisherSignals(t *testing.T) {
	human := ver{v: "1.0.0", user: "alice", age: 200 * day, maint: []string{"alice"}}
	ci := ver{v: "1.1.0", age: 100 * day, maint: []string{"alice"}, trusted: true, provenance: true}
	f := &fakeFetcher{docs: map[string]*registry.Packument{
		// Moving to trusted publishing is an improvement, not a new publisher.
		"tomoved": doc("tomoved", human, ver{v: "1.1.0", age: 10 * day, maint: []string{"alice"}, trusted: true, provenance: true}),
		// Provenance dropped: CI-published before, a token-published release now.
		"dropped": doc("dropped", human, ci, ver{v: "1.2.0", user: "alice", age: 10 * day, maint: []string{"alice"}}),
		// Old releases are outside the window: no publisher signals.
		"old": doc("old", human, ver{v: "1.1.0", user: "mallory", age: 120 * day, maint: []string{"alice", "mallory"}}),
	}}
	r := run(t, f,
		&lockfile.Package{Name: "tomoved", Version: "1.1.0"},
		&lockfile.Package{Name: "dropped", Version: "1.2.0"},
		&lockfile.Package{Name: "old", Version: "1.1.0"},
	)
	if res := result(t, r, "tomoved@1.1.0"); len(res.Findings) != 0 {
		t.Errorf("tomoved: %+v", res.Findings)
	}
	res := result(t, r, "dropped@1.2.0")
	if !hasRule(res, "SI-REC-002", High) || !strings.Contains(res.Findings[0].Message, "provenance") {
		t.Errorf("dropped: %+v", res.Findings)
	}
	if res := result(t, r, "old@1.1.0"); len(res.Findings) != 0 {
		t.Errorf("old: %+v", res.Findings)
	}
}

func TestIntegrityComparesSameAlgorithmOnly(t *testing.T) {
	f := &fakeFetcher{docs: map[string]*registry.Packument{
		"a": doc("a", ver{v: "1.0.0", age: 400 * day, integrity: "sha512-new"}),
	}}
	// Old lockfiles may hold only a sha1; that is not a mismatch with a sha512.
	r := run(t, f, &lockfile.Package{Name: "a", Version: "1.0.0", Integrity: "sha1-xyz"})
	if res := result(t, r, "a@1.0.0"); len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
}

func TestYarnMirrorIsTheNPMRegistry(t *testing.T) {
	f := &fakeFetcher{docs: map[string]*registry.Packument{"a": doc("a", ver{v: "1.0.0", age: 400 * day})}}
	r := run(t, f, &lockfile.Package{Name: "a", Version: "1.0.0", Resolved: "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc"})
	if res := result(t, r, "a@1.0.0"); len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
}

type brokenFetcher struct{}

func (brokenFetcher) Packument(context.Context, string) (*registry.Packument, error) {
	return nil, errors.New("connection refused")
}

func TestFetchErrorsAreReported(t *testing.T) {
	r := Analyze(context.Background(), graph(&lockfile.Package{Name: "x", Version: "1.0.0"}), brokenFetcher{}, Config{Now: now})
	res := result(t, r, "x@1.0.0")
	if res.Err == nil || r.Failed() != 1 {
		t.Fatalf("err = %v, failed = %d", res.Err, r.Failed())
	}
}

// Malicious packages are usually unpublished: a 404 is a finding, and OSV
// must still be asked.
func TestUnpublishedPackageStillChecked(t *testing.T) {
	vulns := fakeOSV{{Name: "snapshot-vks", Version: "1.0.0"}: {{ID: "MAL-2025-47103"}}}
	r := Analyze(context.Background(), graph(&lockfile.Package{Name: "snapshot-vks", Version: "1.0.0"}), &fakeFetcher{}, Config{Now: now, OSV: vulns})
	res := result(t, r, "snapshot-vks@1.0.0")
	if res.Err != nil || r.Failed() != 0 {
		t.Fatalf("404 treated as a failure: %v", res.Err)
	}
	if !hasRule(res, "SI-VUL-001", Block) || !hasRule(res, "SI-DEP-001", Low) || res.Level != LevelBlock {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestNonRegistryPackagesAreSkipped(t *testing.T) {
	f := &fakeFetcher{}
	r := run(t, f,
		&lockfile.Package{Name: "local", Version: "file:../local"},
		&lockfile.Package{Name: "tarball", Version: "1.0.0", Resolved: "file:tarball-1.0.0.tgz"},
		&lockfile.Package{Name: "gitdep", Version: "1.0.0", Resolved: "git+ssh://git@github.com/a/b.git#abc"},
	)
	if f.calls.Load() != 0 || len(r.Results) != 0 || r.Skipped != 3 {
		t.Fatalf("calls=%d results=%d skipped=%d", f.calls.Load(), len(r.Results), r.Skipped)
	}
}

func TestReleaseAgeDisabled(t *testing.T) {
	f := &fakeFetcher{docs: map[string]*registry.Packument{"a": doc("a", ver{v: "1.0.0", age: time.Hour})}}
	r := Analyze(context.Background(), graph(&lockfile.Package{Name: "a", Version: "1.0.0"}), f, Config{Now: now})
	if res := result(t, r, "a@1.0.0"); len(res.Findings) != 0 {
		t.Fatalf("findings with MinReleaseAge=0: %+v", res.Findings)
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"low": LevelLow, "MEDIUM": LevelMedium, "high": LevelHigh, "block": LevelBlock, "none": LevelNone} {
		if got, err := ParseLevel(in); err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseLevel("severe"); err == nil || !strings.Contains(err.Error(), "severe") {
		t.Errorf("expected error, got %v", err)
	}
}

func TestReleaseAgeExclude(t *testing.T) {
	f := &fakeFetcher{docs: map[string]*registry.Packument{
		"typescript": doc("typescript", ver{v: "6.0.0", age: time.Hour}),
		"react":      doc("react", ver{v: "20.0.0", age: time.Hour}),
	}}
	r := Analyze(context.Background(), graph(
		&lockfile.Package{Name: "typescript", Version: "6.0.0"},
		&lockfile.Package{Name: "react", Version: "20.0.0"},
	), f, Config{Now: now, MinReleaseAge: 72 * time.Hour, Exclude: func(n string) bool { return n == "typescript" }})
	if res := result(t, r, "typescript@6.0.0"); len(res.Findings) != 0 {
		t.Errorf("excluded package flagged: %+v", res.Findings)
	}
	if res := result(t, r, "react@20.0.0"); !hasRule(res, "SI-REC-001", Medium) {
		t.Errorf("react not flagged: %+v", res.Findings)
	}
}

func TestEveryRuleIsExplained(t *testing.T) {
	ids := []string{"SI-SCR-001", "SI-SCR-002", "SI-SCR-003", "SI-SCR-004", "SI-SCR-005",
		"SI-CODE-001", "SI-CODE-002", "SI-CODE-003"}
	for _, r := range Rules {
		ids = append(ids, r.ID())
	}
	for _, id := range ids {
		e, ok := Explain(id)
		if !ok || e.Title == "" || e.Why == "" || e.Fix == "" {
			t.Errorf("%s: missing explanation %+v", id, e)
		}
	}
	if _, ok := Explain("si-rec-001"); !ok {
		t.Error("Explain should ignore case")
	}
	if _, ok := Explain("SI-NOPE"); ok {
		t.Error("unknown rule explained")
	}
}

type fakeOSV map[osv.Package][]osv.Vuln

func (f fakeOSV) Lookup(_ context.Context, pkgs []osv.Package) (map[osv.Package][]osv.Vuln, error) {
	out := map[osv.Package][]osv.Vuln{}
	for _, p := range pkgs {
		if v, ok := f[p]; ok {
			out[p] = v
		}
	}
	return out, nil
}

type failingOSV struct{}

func (failingOSV) Lookup(context.Context, []osv.Package) (map[osv.Package][]osv.Vuln, error) {
	return nil, errors.New("osv down")
}

type fakeDownloads struct {
	counts map[string]int
	asked  []string
}

func (f *fakeDownloads) Weekly(_ context.Context, names []string) (map[string]int, error) {
	f.asked = append(f.asked, names...)
	out := map[string]int{}
	for _, n := range names {
		if c, ok := f.counts[n]; ok {
			out[n] = c
		}
	}
	return out, nil
}

func withScripts(v ver) ver { v.scripts = true; return v }

func TestPopularityVulnRules(t *testing.T) {
	old := ver{v: "1.0.0", age: 400 * day}
	f := &fakeFetcher{docs: map[string]*registry.Packument{
		"lodahs":      doc("lodahs", old),
		"tiny-native": doc("tiny-native", withScripts(old)),
		"busy-native": doc("busy-native", withScripts(old)),
		"esbuild":     doc("esbuild", withScripts(old)),
		"lodash":      doc("lodash", old),
		"evil":        doc("evil", old),
	}}
	dl := &fakeDownloads{counts: map[string]int{"tiny-native": 12, "busy-native": 50000}}
	vulns := fakeOSV{
		{Name: "lodash", Version: "1.0.0"}: {{ID: "GHSA-a", Summary: "Prototype Pollution", Severity: "CRITICAL"}, {ID: "GHSA-b", Summary: "ReDoS", Severity: "MODERATE"}},
		{Name: "evil", Version: "1.0.0"}:   {{ID: "MAL-2025-1", Summary: "known malicious package"}},
	}
	var pkgs []*lockfile.Package
	for name := range f.docs {
		pkgs = append(pkgs, &lockfile.Package{Name: name, Version: "1.0.0"})
	}
	r := Analyze(context.Background(), graph(pkgs...), f, Config{
		Now: now, Popular: popularity.Default(), Downloads: dl, OSV: vulns,
	})

	if res := result(t, r, "lodahs@1.0.0"); !hasRule(res, "SI-POP-001", High) {
		t.Errorf("typosquat: %+v", res.Findings)
	}
	if res := result(t, r, "tiny-native@1.0.0"); !hasRule(res, "SI-POP-002", Medium) {
		t.Errorf("unpopular with scripts: %+v", res.Findings)
	}
	if res := result(t, r, "busy-native@1.0.0"); len(res.Findings) != 0 {
		t.Errorf("busy-native: %+v", res.Findings)
	}
	if res := result(t, r, "esbuild@1.0.0"); len(res.Findings) != 0 {
		t.Errorf("popular package with scripts: %+v", res.Findings)
	}
	// Only unpopular packages with install scripts are looked up.
	sort.Strings(dl.asked)
	if want := []string{"busy-native", "tiny-native"}; !slices.Equal(dl.asked, want) {
		t.Errorf("downloads asked for %v, want %v", dl.asked, want)
	}
	res := result(t, r, "lodash@1.0.0")
	if !hasRule(res, "SI-VUL-001", High) || !hasRule(res, "SI-VUL-001", Low) {
		t.Errorf("advisories (critical->high, moderate->low): %+v", res.Findings)
	}
	if res := result(t, r, "evil@1.0.0"); !hasRule(res, "SI-VUL-001", Block) || res.Level != LevelBlock {
		t.Errorf("malicious: %+v", res)
	}
}

func TestOSVFailureIsAWarning(t *testing.T) {
	f := &fakeFetcher{docs: map[string]*registry.Packument{"a": doc("a", ver{v: "1.0.0", age: 400 * day})}}
	r := Analyze(context.Background(), graph(&lockfile.Package{Name: "a", Version: "1.0.0"}), f, Config{Now: now, OSV: failingOSV{}})
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "osv down") {
		t.Fatalf("warnings = %v", r.Warnings)
	}
	if r.Failed() != 0 {
		t.Fatal("an OSV outage must not count as unchecked packages")
	}
}

func TestPrivateRegistryHostsAreTheRegistry(t *testing.T) {
	f := &fakeFetcher{docs: map[string]*registry.Packument{
		"@corp/ui": doc("@corp/ui", ver{v: "1.0.0", age: 400 * day}),
		"left-pad": doc("left-pad", ver{v: "1.0.0", age: 400 * day}),
	}}
	r := Analyze(context.Background(), graph(
		&lockfile.Package{Name: "@corp/ui", Version: "1.0.0", Resolved: "https://npm.corp.example.com/npm/@corp/ui/-/ui-1.0.0.tgz"},
		&lockfile.Package{Name: "left-pad", Version: "1.0.0", Resolved: "https://evil.example.net/left-pad-1.0.0.tgz"},
	), f, Config{Now: now, RegistryHosts: []string{"registry.npmjs.org", "npm.corp.example.com"}})
	if res := result(t, r, "@corp/ui@1.0.0"); len(res.Findings) != 0 {
		t.Errorf("private registry flagged: %+v", res.Findings)
	}
	if res := result(t, r, "left-pad@1.0.0"); !hasRule(res, "SI-INT-002", High) {
		t.Errorf("foreign host not flagged: %+v", res.Findings)
	}
}

// Many findings of one rule say one thing: only the worst counts. Different
// rules still add up.
func TestScoreCountsEachRuleOnce(t *testing.T) {
	vulns := []Finding{
		{Rule: "SI-VUL-001", Severity: Medium}, {Rule: "SI-VUL-001", Severity: Medium}, {Rule: "SI-VUL-001", Severity: Low},
	}
	if score, level := Score(vulns); score != 30 || level != LevelMedium {
		t.Errorf("three advisories: score %d level %s, want 30 medium", score, level)
	}
	mixed := append(vulns, Finding{Rule: "SI-REC-001", Severity: Medium})
	if score, level := Score(mixed); score != 60 || level != LevelHigh {
		t.Errorf("advisories + fresh release: score %d level %s, want 60 high", score, level)
	}
	if _, level := Score([]Finding{{Rule: "SI-VUL-001", Severity: Medium}, {Rule: "SI-VUL-001", Severity: Block}}); level != LevelBlock {
		t.Errorf("a blocking finding must still block, got %s", level)
	}
}
