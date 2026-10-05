package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// A project on an authenticated private registry: check uses .npmrc for the
// registry and token, and does not flag its tarballs as foreign (SI-INT-002).
func privateRegistryProject(t *testing.T, token string) string {
	t.Helper()
	published := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"name":"@corp/ui","time":{"1.0.0":"` + published + `"},
			"versions":{"1.0.0":{"version":"1.0.0","dist":{"integrity":"sha512-ok"}}}}`))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	host := strings.TrimPrefix(srv.URL, "http:")
	files := map[string]string{
		".npmrc":       "@corp:registry=" + srv.URL + "/\n" + host + "/:_authToken=${CORP_TOKEN}\n",
		"package.json": `{"name":"p","version":"1.0.0","dependencies":{"@corp/ui":"1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{
			"":{"name":"p","dependencies":{"@corp/ui":"1.0.0"}},
			"node_modules/@corp/ui":{"version":"1.0.0","resolved":"` + srv.URL + `/@corp/ui/-/ui-1.0.0.tgz","integrity":"sha512-ok"}}}`,
	}
	for name, content := range files {
		if err := os.WriteFile(dir+"/"+name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CORP_TOKEN", token)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NPM_CONFIG_USERCONFIG", "")
	t.Setenv("npm_config_registry", "")
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", "")
	t.Setenv("SAFE_INSTALL_OSV_URL", "off")
	t.Setenv("SAFE_INSTALL_DOWNLOADS_URL", "off")
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Chdir(dir)
	return dir
}

func TestCheckPrivateRegistry(t *testing.T) {
	privateRegistryProject(t, "s3cret")
	out, err := runCLIOut(t, "check", "--fail-on", "low")
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if strings.Contains(out, "SI-INT-002") {
		t.Fatalf("private registry flagged as foreign:\n%s", out)
	}
}

func TestCheckPrivateRegistryWrongToken(t *testing.T) {
	privateRegistryProject(t, "wrong")
	out, err := runCLIOut(t, "check")
	if code := exitCode(err); code != ExitToolError {
		t.Fatalf("exit = %d (%v), want %d\n%s", code, err, ExitToolError, out)
	}
	if !strings.Contains(out, ".npmrc") || strings.Contains(out, "wrong") {
		t.Fatalf("want an .npmrc hint and no token in the output:\n%s", out)
	}
}
