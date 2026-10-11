package analyze

import (
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
