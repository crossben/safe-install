package npmrc

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// env returns a lookup over m only: tests never see the real environment.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load(t.TempDir(), env(map[string]string{"HOME": t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	if c.RegistryFor("react") != DefaultRegistry || c.AuthFor(DefaultRegistry+"/react") != "" {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestProjectAndUserFiles(t *testing.T) {
	home, proj := t.TempDir(), t.TempDir()
	write(t, filepath.Join(home, ".npmrc"), `
; user settings
registry=https://user.example.com/npm/
//user.example.com/npm/:_authToken=user-token
@acme:registry=https://user-acme.example.com/
`)
	write(t, filepath.Join(proj, ".npmrc"), `
# project wins
registry = "https://npm.corp.example.com/repository/npm/"
@acme:registry=https://acme.example.com/npm
//npm.corp.example.com/repository/npm/:_authToken=${NPM_TOKEN}
//acme.example.com/npm/:_auth=`+base64.StdEncoding.EncodeToString([]byte("bob:s3cret"))+`
`)
	c, err := Load(proj, env(map[string]string{"HOME": home, "NPM_TOKEN": "proj-token"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RegistryFor("react"); got != "https://npm.corp.example.com/repository/npm" {
		t.Errorf("default registry = %q", got)
	}
	if got := c.RegistryFor("@acme/ui"); got != "https://acme.example.com/npm" {
		t.Errorf("scoped registry = %q", got)
	}
	if got := c.AuthFor("https://npm.corp.example.com/repository/npm/react"); got != "Bearer proj-token" {
		t.Errorf("token auth = %q", got)
	}
	if got := c.AuthFor("https://acme.example.com/npm/@acme%2Fui"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("bob:s3cret")) {
		t.Errorf("basic auth = %q", got)
	}
	// The user file's token still applies to its own host.
	if got := c.AuthFor("https://user.example.com/npm/x"); got != "Bearer user-token" {
		t.Errorf("user token = %q", got)
	}
}

func TestTokensNeverLeak(t *testing.T) {
	proj := t.TempDir()
	write(t, filepath.Join(proj, ".npmrc"), `
registry=https://reg.example.com/
//reg.example.com/:_authToken=secret
//reg.example.com/private/:_authToken=narrow
`)
	c, err := Load(proj, env(map[string]string{"HOME": t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"https://reg.example.com.evil.net/x", // look-alike host
		"https://evil.net/reg.example.com/x", // host in the path
		"https://api.osv.dev/v1/querybatch",  // other services
		"http://other.example.com/",          // unrelated
		"https://registry.npmjs.org/react",   // the public registry
	} {
		if got := c.AuthFor(u); got != "" {
			t.Errorf("AuthFor(%q) = %q, want none", u, got)
		}
	}
	if got := c.AuthFor("https://reg.example.com/private/pkg"); got != "Bearer narrow" {
		t.Errorf("longest prefix should win, got %q", got)
	}
	if got := c.AuthFor("https://reg.example.com/pkg"); got != "Bearer secret" {
		t.Errorf("host token = %q", got)
	}
}

func TestUsernamePassword(t *testing.T) {
	proj := t.TempDir()
	write(t, filepath.Join(proj, ".npmrc"), `
//reg.example.com/:username=alice
//reg.example.com/:_password=`+base64.StdEncoding.EncodeToString([]byte("pa:ss"))+`
`)
	c, err := Load(proj, env(map[string]string{"HOME": t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pa:ss"))
	if got := c.AuthFor("https://reg.example.com/x"); got != want {
		t.Errorf("AuthFor = %q, want %q", got, want)
	}
}

func TestEnvOverridesAndUserConfigPath(t *testing.T) {
	proj, other := t.TempDir(), t.TempDir()
	write(t, filepath.Join(other, "custom-npmrc"), "//env.example.com/:_authToken=from-userconfig\n")
	write(t, filepath.Join(proj, ".npmrc"), "registry=https://proj.example.com/\n")
	c, err := Load(proj, env(map[string]string{
		"HOME":                  t.TempDir(),
		"NPM_CONFIG_USERCONFIG": filepath.Join(other, "custom-npmrc"),
		"npm_config_registry":   "https://env.example.com/",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RegistryFor("x"); got != "https://env.example.com" {
		t.Errorf("env registry = %q", got)
	}
	if got := c.AuthFor("https://env.example.com/x"); got != "Bearer from-userconfig" {
		t.Errorf("userconfig auth = %q", got)
	}
}

func TestYarnrc(t *testing.T) {
	proj := t.TempDir()
	write(t, filepath.Join(proj, ".yarnrc.yml"), `
npmRegistryServer: "https://yarn.example.com/npm"
npmAuthToken: "${YARN_TOKEN}"
npmScopes:
  acme:
    npmRegistryServer: "https://acme.example.com"
    npmAuthToken: scoped-token
npmRegistries:
  "//extra.example.com":
    npmAuthToken: extra-token
`)
	c, err := Load(proj, env(map[string]string{"HOME": t.TempDir(), "YARN_TOKEN": "yt"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.RegistryFor("x") != "https://yarn.example.com/npm" || c.RegistryFor("@acme/a") != "https://acme.example.com" {
		t.Errorf("registries: %q %q", c.RegistryFor("x"), c.RegistryFor("@acme/a"))
	}
	for u, want := range map[string]string{
		"https://yarn.example.com/npm/x":     "Bearer yt",
		"https://acme.example.com/@acme%2Fa": "Bearer scoped-token",
		"https://extra.example.com/x":        "Bearer extra-token",
		"https://registry.npmjs.org/x":       "",
	} {
		if got := c.AuthFor(u); got != want {
			t.Errorf("AuthFor(%q) = %q, want %q", u, got, want)
		}
	}
}

func TestHosts(t *testing.T) {
	proj := t.TempDir()
	write(t, filepath.Join(proj, ".npmrc"), "registry=https://a.example.com/\n@s:registry=https://b.example.com:8443/x/\n")
	c, err := Load(proj, env(map[string]string{"HOME": t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	got := c.Hosts()
	for _, want := range []string{"a.example.com", "b.example.com"} {
		if !slices.Contains(got, want) {
			t.Errorf("Hosts() = %v, missing %s", got, want)
		}
	}
}

func TestMissingEnvExpandsEmpty(t *testing.T) {
	proj := t.TempDir()
	write(t, filepath.Join(proj, ".npmrc"), "//reg.example.com/:_authToken=${UNSET_TOKEN}\n")
	c, err := Load(proj, env(map[string]string{"HOME": t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.AuthFor("https://reg.example.com/x"); got != "" {
		t.Errorf("empty token should send no header, got %q", got)
	}
}
