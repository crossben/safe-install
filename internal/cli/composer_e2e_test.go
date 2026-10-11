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

func TestCheckComposerProject(t *testing.T) {
	old := time.Now().AddDate(-1, 0, 0).Format(time.RFC3339)
	meta := func(name string, entries ...map[string]any) []byte {
		b, _ := json.Marshal(map[string]any{"minified": "composer/2.0", "packages": map[string]any{name: entries}})
		return b
	}
	docs := map[string][]byte{
		"/p2/acme/lib.json":     meta("acme/lib", map[string]any{"version": "1.0.0", "published-time": old, "dist": map[string]string{"reference": "aaaa"}}),
		"/p2/acme/old.json":     meta("acme/old", map[string]any{"version": "v2.0.0", "published-time": old, "abandoned": "acme/new", "dist": map[string]string{"reference": "bbbb"}}),
		"/p2/acme/plugin.json":  meta("acme/plugin", map[string]any{"version": "1.0.0", "published-time": old, "type": "composer-plugin", "dist": map[string]string{"reference": "cccc"}}),
		"/p2/acme/swapped.json": meta("acme/swapped", map[string]any{"version": "1.0.0", "published-time": old, "dist": map[string]string{"reference": "dddd"}}),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := docs[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_PACKAGIST_URL", srv.URL)
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	dir := t.TempDir()
	t.Chdir(dir)
	pkg := func(name, version, ref, typ string) map[string]any {
		return map[string]any{"name": name, "version": version, "type": typ,
			"dist": map[string]string{"type": "zip", "url": "https://api.github.com/repos/x/y/zipball/" + ref, "reference": ref}}
	}
	lock, _ := json.Marshal(map[string]any{"packages": []any{
		pkg("acme/lib", "1.0.0", "aaaa", "library"),
		pkg("acme/old", "v2.0.0", "bbbb", "library"),
		pkg("acme/plugin", "1.0.0", "cccc", "composer-plugin"),
		pkg("acme/swapped", "1.0.0", "eeee", "library"),
	}, "packages-dev": []any{}})
	_ = os.WriteFile(filepath.Join(dir, "composer.lock"), lock, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"require":{"php":">=8.2","acme/lib":"*","acme/old":"*","acme/plugin":"*","acme/swapped":"*"}}`), 0o600)

	out, err := runCLIOut(t, "check", "--format", "json", "--fail-on", "none")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var rep struct {
		Skipped  int `json:"skipped"`
		Packages []struct {
			ID       string `json:"id"`
			Findings []struct{ Rule string }
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
		"acme/lib@1.0.0":     "",
		"acme/old@v2.0.0":    "SI-DEP-001", // v-prefixed and checked, not skipped
		"acme/plugin@1.0.0":  "SI-PLG-001",
		"acme/swapped@1.0.0": "SI-INT-001",
	}
	for id, w := range want {
		if r, ok := got[id]; !ok || r != w {
			t.Errorf("%s: %q (present %v), want %q", id, r, ok, w)
		}
	}
	if rep.Skipped != 0 {
		t.Errorf("%d skipped", rep.Skipped)
	}
}
