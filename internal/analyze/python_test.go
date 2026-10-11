package analyze

import (
	"context"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/registry"
)

func pyInput(files []lockfile.File, resolved string) *Input {
	meta := registry.VersionMeta{Version: "1.0", Files: []registry.DistFile{
		{Name: "pkg-1.0-py3-none-any.whl", SHA256: "aa", URL: "https://files.pythonhosted.org/pkg-1.0-py3-none-any.whl"},
		{Name: "pkg-1.0.tar.gz", SHA256: "bb", Sdist: true},
	}}
	return &Input{
		Package: &lockfile.Package{ID: "pkg@1.0", Name: "pkg", Version: "1.0", Resolved: resolved, Files: files, Ecosystem: ecosystem.PyPI},
		Meta:    &meta,
		Doc:     &registry.Packument{Versions: map[string]registry.VersionMeta{"1.0": meta}, Time: map[string]time.Time{}},
		Config:  Config{RegistryHosts: []string{"pypi.org", "files.pythonhosted.org"}},
	}
}

func TestPythonIntegrity(t *testing.T) {
	ok := pyInput([]lockfile.File{{Name: "pkg-1.0.tar.gz", Hash: "sha256:BB"}}, "https://pypi.org/simple")
	if f := (integrityRule{}).Check(ok); len(f) != 0 {
		t.Fatalf("matching hash flagged: %v", f)
	}
	bad := pyInput([]lockfile.File{{Name: "pkg-1.0-py3-none-any.whl", Hash: "sha256:ee"}}, "")
	if f := (integrityRule{}).Check(bad); len(f) != 1 || f[0].Severity != Block {
		t.Fatalf("swapped wheel not blocked: %v", f)
	}
	anon := pyInput([]lockfile.File{{Hash: "sha256:ff"}}, "") // requirements.txt: hash only
	if f := (integrityRule{}).Check(anon); len(f) != 1 {
		t.Fatalf("unknown hash not flagged: %v", f)
	}
}

func TestPythonFileURLsMustComeFromTheIndex(t *testing.T) {
	in := pyInput([]lockfile.File{{URL: "https://evil.example/pkg-1.0-py3-none-any.whl", Hash: "sha256:aa"}}, "https://pypi.org/simple")
	if f := (sourceRule{}).Check(in); len(f) != 1 || f[0].Severity != High {
		t.Fatalf("file from another host not flagged: %v", f)
	}
	in = pyInput([]lockfile.File{{URL: "https://files.pythonhosted.org/x.whl", Hash: "sha256:aa"}}, "https://pypi.org/simple")
	if f := (sourceRule{}).Check(in); len(f) != 0 {
		t.Fatalf("PyPI file flagged: %v", f)
	}
}

func TestYankedWording(t *testing.T) {
	in := pyInput(nil, "")
	in.Meta.Yanked, in.Meta.Deprecated = true, "broken build"
	if f := (deprecatedRule{}).Check(in); len(f) != 1 || f[0].Message != "yanked: broken build" {
		t.Fatalf("got %v", f)
	}
}

type fakeProvenance map[string]map[string]bool

func (f fakeProvenance) Provenance(_ context.Context, name string) (map[string]bool, error) {
	return f[name], nil
}

// The axios pattern on PyPI: earlier releases published by CI with
// attestations, the newest one without.
func TestPyPIProvenanceDropped(t *testing.T) {
	now := time.Now()
	file := func(name string) registry.DistFile { return registry.DistFile{Name: name, SHA256: name} }
	doc := &registry.Packument{
		Versions: map[string]registry.VersionMeta{
			"1.0": {Version: "1.0", Files: []registry.DistFile{file("pkg-1.0.tar.gz")}},
			"1.1": {Version: "1.1", Files: []registry.DistFile{file("pkg-1.1.tar.gz")}},
		},
		Time: map[string]time.Time{"1.0": now.AddDate(0, -2, 0), "1.1": now.Add(-time.Hour)},
	}
	meta := doc.Versions["1.1"]
	in := &Input{Package: &lockfile.Package{ID: "pkg@1.1", Name: "pkg", Version: "1.1", Ecosystem: ecosystem.PyPI},
		Doc: doc, Meta: &meta, Downloads: -1}
	cfg := Config{Now: now, Provenance: fakeProvenance{"pkg": {"pkg-1.0.tar.gz": true, "pkg-1.1.tar.gz": false}}}
	in.Config = cfg
	if w := markProvenance(context.Background(), []*Input{in}, cfg); len(w) != 0 {
		t.Fatal(w)
	}
	f := (publisherRule{}).Check(in)
	if len(f) != 1 || f[0].Severity != High {
		t.Fatalf("provenance drop not flagged: %v", f)
	}
	// Attested release: nothing to report.
	cfg.Provenance = fakeProvenance{"pkg": {"pkg-1.0.tar.gz": true, "pkg-1.1.tar.gz": true}}
	in.Config = cfg
	markProvenance(context.Background(), []*Input{in}, cfg)
	if f := (publisherRule{}).Check(in); len(f) != 0 {
		t.Fatalf("attested release flagged: %v", f)
	}
}

func TestNoWheelMeansBuildCode(t *testing.T) {
	in := pyInput(nil, "")
	if f := (buildRule{}).Check(in); len(f) != 0 {
		t.Fatalf("package with a wheel flagged: %v", f)
	}
	in.Meta.Files = []registry.DistFile{{Name: "pkg-1.0.tar.gz", Sdist: true}}
	if f := (buildRule{}).Check(in); len(f) != 1 || f[0].Rule != "SI-BLD-001" {
		t.Fatalf("sdist-only package: %v", f)
	}
}
