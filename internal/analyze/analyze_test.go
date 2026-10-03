package analyze

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/lockfile"
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
		Now: now, MinReleaseAge: 72 * time.Hour, RegistryURL: registry.DefaultURL,
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

func TestFetchErrorsAreReported(t *testing.T) {
	r := run(t, &fakeFetcher{}, &lockfile.Package{Name: "gone", Version: "1.0.0"})
	res := result(t, r, "gone@1.0.0")
	if !errors.Is(res.Err, registry.ErrNotFound) {
		t.Fatalf("err = %v", res.Err)
	}
	if r.Failed() != 1 {
		t.Fatalf("Failed() = %d", r.Failed())
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
	ids := []string{"SI-SCR-001", "SI-SCR-002", "SI-SCR-003", "SI-SCR-004", "SI-SCR-005"}
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
