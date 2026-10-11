package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
)

// TestHelperUV is not a test: it is the fake uv the install tests run (see
// fakeUV). It records its arguments and refuses to build docopt when told
// not to, with uv's real error message.
func TestHelperUV(t *testing.T) {
	if os.Getenv("SAFE_INSTALL_FAKE_UV") != "1" {
		t.Skip("helper process")
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	f, _ := os.OpenFile(os.Getenv("SAFE_INSTALL_FAKE_UV_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	_, _ = fmt.Fprintf(f, "%s | %s\n", strings.Join(args, " "), os.Getenv("UV_NO_BUILD_PACKAGE"))
	_ = f.Close()
	if args[0] == "sync" && slices.Contains(strings.Fields(os.Getenv("UV_NO_BUILD_PACKAGE")), "docopt") {
		_, _ = fmt.Fprintln(os.Stderr, "error: Distribution `docopt==0.6.2 @ registry+https://pypi.org/simple` can't be installed because it is marked as `--no-build` but has no binary distribution")
		os.Exit(1)
	}
	os.Exit(0)
}

func fakeUV(t *testing.T) string {
	t.Helper()
	log := filepath.Join(t.TempDir(), "uv.log")
	prev := uvCommand
	uvCommand = func(dir string, env []string, args ...string) *exec.Cmd {
		c := exec.Command(os.Args[0], append([]string{"-test.run=^TestHelperUV$", "--"}, args...)...)
		c.Dir = dir
		c.Env = append(os.Environ(), append(env, "SAFE_INSTALL_FAKE_UV=1", "SAFE_INSTALL_FAKE_UV_LOG="+log)...)
		return c
	}
	t.Cleanup(func() { uvCommand = prev })
	return log
}

const docoptSHA = "49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491"

func uvProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	lock := `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "docopt" }, { name = "six" }]

[[package]]
name = "docopt"
version = "0.6.2"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/docopt-0.6.2.tar.gz", hash = "sha256:` + docoptSHA + `" }

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:aa" }]
`
	for name, body := range map[string]string{"uv.lock": lock, "pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A PyPI with nothing to say about docopt (old, not yanked), and no sdist
	// download needed: --deep results come from its cache in other tests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/docopt/json" {
			b, _ := json.Marshal(map[string]any{"info": map[string]string{"name": "docopt"}, "releases": map[string]any{"0.6.2": []map[string]any{{
				"filename": "docopt-0.6.2.tar.gz", "url": "", "digests": map[string]string{"sha256": docoptSHA},
				"packagetype": "sdist", "upload_time_iso_8601": "2014-06-16T11:18:57Z",
			}}}})
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SAFE_INSTALL_PYPI_URL", srv.URL)
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	if _, err := exec.LookPath("uv"); err != nil {
		// runPythonInstall checks uv is installed; give it something to find.
		bin := t.TempDir()
		_ = os.WriteFile(filepath.Join(bin, "uv"), []byte("#!/bin/sh\n"), 0o700)
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	return dir
}

func TestPythonInstallNeedsApprovalToBuild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in uv on PATH is a shell script")
	}
	if testing.Short() {
		t.Skip("runs the test binary as a fake uv")
	}
	log := fakeUV(t)
	uvProject(t)
	prev := isInteractive
	isInteractive = func() bool { return false }
	t.Cleanup(func() { isInteractive = prev })

	// Not approved: docopt stays in the deny-list, uv refuses, nothing installed.
	if _, err := runCLI(t, "install", "--frozen-lockfile"); err == nil || !strings.Contains(err.Error(), "docopt was not approved") {
		t.Fatalf("got %v", err)
	}
	// --yes: medium risk, approved for this run: docopt leaves the deny-list.
	if out, err := runCLI(t, "install", "--frozen-lockfile", "--yes"); err != nil {
		t.Fatalf("--yes: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "sync --locked | ") || strings.Contains(last, "docopt") || !strings.Contains(last, "six") {
		t.Fatalf("last uv call %q: docopt should be allowed to build, six still denied", last)
	}
}

func TestPythonApprovalIsPinnedToTheSdist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in uv on PATH is a shell script")
	}
	if testing.Short() {
		t.Skip("runs the test binary as a fake uv")
	}
	fakeUV(t)
	dir := uvProject(t)
	prev := isInteractive
	isInteractive = func() bool { return false }
	t.Cleanup(func() { isInteractive = prev })
	path := filepath.Join(dir, ".safe-install.json")

	if err := policy.Approve(path, "docopt", policy.Approval{Version: "0.6.2", Hash: "sha256:" + docoptSHA}); err != nil {
		t.Fatal(err)
	}
	if out, err := runCLI(t, "install", "--frozen-lockfile"); err != nil {
		t.Fatalf("approved sdist refused: %v\n%s", err, out)
	}
	// Another sdist under the same name and version is not the one reviewed.
	if err := policy.Approve(path, "docopt", policy.Approval{Version: "0.6.2", Hash: "sha256:" + strings.Repeat("0", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "install", "--frozen-lockfile"); err == nil {
		t.Fatal("an approval for a different sdist let it build")
	}
}

func TestDenyListAndUVError(t *testing.T) {
	g, err := lockfile.Parse("uv.lock", []byte(`version = 1
[[package]]
name = "a"
version = "1"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://x/a-1.tar.gz", hash = "sha256:aa" }
[[package]]
name = "b"
version = "1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://x/b-1-py3-none-any.whl", hash = "sha256:bb" }]
`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := g.Packages["a@1"]
	if sha, ok := sdistOnly(a); !ok || sha != "aa" {
		t.Fatalf("sdistOnly(a) = %q, %v", sha, ok)
	}
	if _, ok := sdistOnly(g.Packages["b@1"]); ok {
		t.Fatal("b has a wheel")
	}
	builds := map[string]*pyBuild{"a": {pkg: a, approved: true}}
	if got := denyList(g, builds); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("deny = %v", got)
	}
	m := uvNoBuild.FindStringSubmatch("error: Distribution `Zope.Interface==6.0 @ registry+https://pypi.org/simple` can't be installed because it is marked as `--no-build` but has no binary distribution")
	if m == nil || m[1] != "Zope.Interface" {
		t.Fatalf("uv error not parsed: %v", m)
	}
}

func TestSnapshotRestore(t *testing.T) {
	dir := t.TempDir()
	existing, missing := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	_ = os.WriteFile(existing, []byte("before"), 0o600)
	s := snapshot(existing, missing)
	_ = os.WriteFile(existing, []byte("after"), 0o600)
	_ = os.WriteFile(missing, []byte("created"), 0o600)
	s.restore()
	if data, _ := os.ReadFile(existing); string(data) != "before" {
		t.Fatalf("not restored: %q", data)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("a file that did not exist was left behind")
	}
}

func TestPthOwnership(t *testing.T) {
	dir := t.TempDir()
	site := filepath.Join(dir, ".venv", "lib", "python3.12", "site-packages")
	write := func(rel, body string) {
		p := filepath.Join(site, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, []byte(body), 0o600)
	}
	write("evil-1.0.dist-info/RECORD", "evil.pth,sha256=x,10\nevil/__init__.py,,\n")
	write("evil.pth", "import os; exec(__import__('base64').b64decode('cHJpbnQ='))\n")
	write("app-0.1.0.dist-info/RECORD", "_app.pth,,\n")
	write("_app.pth", "import _app_editable\n")
	write("_virtualenv.pth", "import _virtualenv\n")
	write("dropped.pth", "import sneaky\n")
	got := map[string]string{}
	for _, f := range pthFindings(dir, "app") {
		got[strings.Fields(f.Message)[0]+" "+f.Severity.String()] = f.Message
	}
	want := []string{"evil high", "an medium"} // "an unknown package" dropped.pth
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %q in %v", w, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("project's own and uv's _virtualenv.pth must be skipped: %v", got)
	}
}

func TestPythonIndexHosts(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://pypi.corp.example/simple\"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("--extra-index-url https://mirror.example/simple\nsix==1.16.0\n"), 0o600)
	env := map[string]string{"UV_INDEX": "other=https://other.example/simple", "PIP_INDEX_URL": "https://pip.example/simple"}
	hosts := pythonIndexHosts(dir, func(k string) string { return env[k] })
	for _, h := range []string{"pypi.corp.example", "mirror.example", "other.example", "pip.example"} {
		if !slices.Contains(hosts, h) {
			t.Errorf("missing %s in %v", h, hosts)
		}
	}
	g := &lockfile.Graph{Packages: map[string]*lockfile.Package{
		"a@1": {ID: "a@1", Name: "a", Version: "1", Resolved: "https://pypi.corp.example/simple"},
		"b@1": {ID: "b@1", Name: "b", Version: "1", Resolved: "https://pypi.org/simple"},
		"c@1": {ID: "c@1", Name: "c", Version: "1", Resolved: "https://unknown.example/simple"},
	}}
	n, seen := otherIndexPackages(g, hosts)
	if n != 1 || !slices.Equal(seen, []string{"pypi.corp.example"}) || g.Packages["c@1"].Resolved != "https://unknown.example/simple" {
		t.Fatalf("n=%d seen=%v c=%q (an unconfigured host must stay visible to SI-INT-002)", n, seen, g.Packages["c@1"].Resolved)
	}
}
