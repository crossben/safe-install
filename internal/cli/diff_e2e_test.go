package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func lockWith(pkgs ...string) string {
	entries := []string{`"":{"name":"p"}`}
	for _, name := range pkgs {
		entries = append(entries, `"node_modules/`+name+`":{"version":"1.0.0","resolved":"https://registry.npmjs.org/`+name+`/-/`+name+`-1.0.0.tgz"}`)
	}
	return `{"lockfileVersion":3,"packages":{` + strings.Join(entries, ",") + `}}`
}

// diffRepo makes a git repo whose committed lockfile has "old-dep", then adds
// "new-dep" in the working tree. The project lives in a subdirectory.
func diffRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	proj := filepath.Join(repo, "web")
	mustMkdir(t, proj)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(proj, "package.json"), []byte(`{"name":"p","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "no lockfile yet")
	git("tag", "before-lockfile")
	if err := os.WriteFile(filepath.Join(proj, "package-lock.json"), []byte(lockWith("old-dep")), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "lockfile")
	if err := os.WriteFile(filepath.Join(proj, "package-lock.json"), []byte(lockWith("old-dep", "new-dep")), 0o600); err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	doc := func(name string) map[string]any {
		return map[string]any{"name": name, "time": map[string]string{"1.0.0": old},
			"versions": map[string]any{"1.0.0": map[string]any{"version": "1.0.0"}}}
	}
	fixtures := filepath.Join(t.TempDir(), "registry.json")
	data, _ := json.Marshal(map[string]any{"old-dep": doc("old-dep"), "new-dep": doc("new-dep")})
	if err := os.WriteFile(fixtures, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", fixtures)
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Chdir(proj)
	return proj
}

func checkedIDs(t *testing.T, args ...string) []string {
	t.Helper()
	out, err := runCLIOut(t, append([]string{"check", "--format", "json"}, args...)...)
	if err != nil {
		t.Fatalf("check %v: %v\n%s", args, err, out)
	}
	var rep struct {
		Diff *struct {
			Base string `json:"base"`
		} `json:"diff"`
		Packages []struct {
			ID string `json:"id"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	var ids []string
	for _, p := range rep.Packages {
		ids = append(ids, p.ID)
	}
	slices.Sort(ids)
	if len(args) > 0 && (rep.Diff == nil || rep.Diff.Base == "") {
		t.Errorf("diff metadata missing for %v", args)
	}
	return ids
}

func TestCheckDiffAgainstGitRef(t *testing.T) {
	diffRepo(t)
	if got := checkedIDs(t, "--diff", "HEAD"); !slices.Equal(got, []string{"new-dep@1.0.0"}) {
		t.Fatalf("--diff HEAD checked %v", got)
	}
	// The lockfile did not exist yet: everything is new.
	if got := checkedIDs(t, "--diff", "before-lockfile"); len(got) != 2 {
		t.Fatalf("--diff before-lockfile checked %v", got)
	}
	if got := checkedIDs(t); len(got) != 2 {
		t.Fatalf("no --diff checked %v", got)
	}
}

func TestCheckDiffAgainstFile(t *testing.T) {
	diffRepo(t)
	base := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(base, []byte(lockWith("old-dep")), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := checkedIDs(t, "--diff", base); !slices.Equal(got, []string{"new-dep@1.0.0"}) {
		t.Fatalf("--diff <file> checked %v", got)
	}
}

func TestCheckDiffTextSaysWhatWasCompared(t *testing.T) {
	diffRepo(t)
	out, err := runCLIOut(t, "check", "--diff", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 new or changed package") || !strings.Contains(out, "vs HEAD") {
		t.Fatalf("text report:\n%s", out)
	}
}

func TestCheckDiffBadRef(t *testing.T) {
	diffRepo(t)
	for _, ref := range []string{"no-such-branch", "--output=/tmp/x"} {
		if _, err := runCLIOut(t, "check", "--diff", ref); exitCode(err) != ExitToolError {
			t.Errorf("--diff %q: exit %d (%v), want %d", ref, exitCode(err), err, ExitToolError)
		}
	}
}
