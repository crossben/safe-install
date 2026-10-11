package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A uv project checked against a fake PyPI: a yanked version, a fresh
// release, a typosquat and a tampered hash, all from one lockfile.
func TestCheckPythonProject(t *testing.T) {
	now := time.Now().UTC()
	doc := func(name, version string, uploaded time.Time, yanked bool, sha string) string {
		b, _ := json.Marshal(map[string]any{
			"info": map[string]string{"name": name},
			"releases": map[string]any{version: []map[string]any{{
				"filename": name + "-" + version + "-py3-none-any.whl", "url": "https://files.pythonhosted.org/" + name + ".whl",
				"digests": map[string]string{"sha256": sha}, "packagetype": "bdist_wheel",
				"upload_time_iso_8601": uploaded.Format(time.RFC3339), "yanked": yanked, "yanked_reason": "broken",
			}}},
		})
		return string(b)
	}
	docs := map[string]string{
		"/pypi/oldpkg/json":   doc("oldpkg", "1.0.0", now.AddDate(-1, 0, 0), true, "aa"),
		"/pypi/freshpkg/json": doc("freshpkg", "2.0.0", now.Add(-2*time.Hour), false, "bb"),
		"/pypi/reqeusts/json": doc("reqeusts", "2.0.0", now.AddDate(-1, 0, 0), false, "cc"),
		"/pypi/swapped/json":  doc("swapped", "1.0.0", now.AddDate(-1, 0, 0), false, "dd"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_PYPI_URL", srv.URL)
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())

	dir := t.TempDir()
	t.Chdir(dir)
	pkg := func(name, version, sha string) string {
		return `
[[package]]
name = "` + name + `"
version = "` + version + `"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/` + name + `.whl", hash = "sha256:` + sha + `" }]
`
	}
	lock := `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "oldpkg" }, { name = "freshpkg" }, { name = "reqeusts" }, { name = "swapped" }]
` + pkg("oldpkg", "1.0.0", "aa") + pkg("freshpkg", "2.0.0", "bb") + pkg("reqeusts", "2.0.0", "cc") + pkg("swapped", "1.0.0", "ee")
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCLIOut(t, "check", "--format", "json", "--fail-on", "none")
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	var rep struct {
		Format   string `json:"format"`
		Packages []struct {
			ID       string `json:"id"`
			Findings []struct{ Rule, Message string }
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := map[string]string{}
	for _, p := range rep.Packages {
		var rules []string
		for _, f := range p.Findings {
			rules = append(rules, f.Rule)
		}
		got[p.ID] = strings.Join(rules, ",")
	}
	want := map[string]string{
		"oldpkg@1.0.0":   "SI-DEP-001",
		"freshpkg@2.0.0": "SI-REC-001",
		"reqeusts@2.0.0": "SI-POP-001",
		"swapped@1.0.0":  "SI-INT-001",
	}
	if rep.Format != "uv" {
		t.Errorf("format %q", rep.Format)
	}
	for id, rules := range want {
		if got[id] != rules {
			t.Errorf("%s: findings %q, want %q (all: %v)", id, got[id], rules, got)
		}
	}
}
