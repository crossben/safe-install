package policy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const orgJSON = `{
  "minReleaseAge": "7d",
  "failOn": "medium",
  "blockPackages": ["event-stream", "@evil/*"],
  "allowScripts": {"esbuild": {"trust": "provenance", "repository": "https://github.com/evanw/esbuild"}}
}`

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_CACHE_DIR", t.TempDir())
	t.Setenv("SAFE_INSTALL_ORG_POLICY", "")
	t.Setenv("SAFE_INSTALL_ORG_POLICY_TOKEN", "")
}

func TestOrgPolicyFromFile(t *testing.T) {
	isolate(t)
	org := filepath.Join(t.TempDir(), "org.json")
	write(t, org, orgJSON)
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), `{
		"orgPolicy": "`+filepath.ToSlash(org)+`",
		"minReleaseAge": "1h",
		"failOn": "block",
		"allowScripts": {"event-stream": {"hash": "sha256-x"}, "sharp": {"hash": "sha256-s"}}
	}`)
	p, err := Load(proj)
	if err != nil {
		t.Fatal(err)
	}
	// The project cannot weaken the organization's minimums.
	if p.MinReleaseAge != "7d" || p.FailOn != "medium" {
		t.Errorf("minimums: minReleaseAge %q failOn %q", p.MinReleaseAge, p.FailOn)
	}
	if !p.Blocked("event-stream") || !p.Blocked("@evil/x") || p.Blocked("sharp") {
		t.Errorf("blocks wrong")
	}
	// Org approvals apply; the project's own approvals too.
	if _, _, ok := p.Lookup("esbuild"); !ok {
		t.Error("org approval missing")
	}
	if _, _, ok := p.Lookup("sharp"); !ok {
		t.Error("project approval missing")
	}
	if p.Org == "" {
		t.Error("org source not recorded")
	}
}

func TestStricterProjectSettingsStay(t *testing.T) {
	isolate(t)
	org := filepath.Join(t.TempDir(), "org.json")
	write(t, org, orgJSON)
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), `{"orgPolicy": "`+filepath.ToSlash(org)+`", "minReleaseAge": "30d", "failOn": "low"}`)
	p, err := Load(proj)
	if err != nil {
		t.Fatal(err)
	}
	if p.MinReleaseAge != "30d" || p.FailOn != "low" {
		t.Errorf("stricter project settings lost: %q %q", p.MinReleaseAge, p.FailOn)
	}
}

func TestOrgPolicyOverHTTP(t *testing.T) {
	isolate(t)
	var hits atomic.Int32
	up := atomic.Bool{}
	up.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !up.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if r.Header.Get("Authorization") != "Bearer org-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(orgJSON))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_ORG_POLICY", srv.URL+"/policy.json")
	t.Setenv("SAFE_INSTALL_ORG_POLICY_TOKEN", "org-token")

	p, err := Load(t.TempDir())
	if err != nil || !p.Blocked("event-stream") {
		t.Fatalf("Load: %v blocked=%v", err, p != nil && p.Blocked("event-stream"))
	}
	// Unreachable later: the cached copy is used, with a warning.
	up.Store(false)
	p, err = Load(t.TempDir())
	if err != nil || !p.Blocked("event-stream") || !strings.Contains(p.OrgWarning, "cached") {
		t.Fatalf("cache fallback: %v %+v", err, p)
	}
}

func TestOrgPolicyFailsClosed(t *testing.T) {
	isolate(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_ORG_POLICY", srv.URL+"/policy.json")
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "organization policy") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("SAFE_INSTALL_ORG_POLICY", "http://example.com/policy.json")
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http to a remote host accepted: %v", err)
	}
}

func TestTokenOnlyToOrgHost(t *testing.T) {
	isolate(t)
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Authorization")
		http.Redirect(w, r, "https://other.example/policy.json", http.StatusFound)
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_ORG_POLICY", srv.URL+"/policy.json")
	t.Setenv("SAFE_INSTALL_ORG_POLICY_TOKEN", "org-token")
	_, _ = Load(t.TempDir()) // the redirect target is unreachable; only the token's destination matters
	if auth := <-got; auth != "Bearer org-token" {
		t.Fatalf("org host got %q", auth)
	}
}

// A project file (which anyone can change, e.g. in a pull request) must not be
// able to send the org token to a server of its choosing.
func TestProjectChosenOrgURLNeverGetsToken(t *testing.T) {
	isolate(t)
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte(orgJSON))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_ORG_POLICY_TOKEN", "org-token")
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), `{"orgPolicy": "`+srv.URL+`/evil.json"}`)
	if _, err := Load(proj); err != nil {
		t.Fatal(err)
	}
	if auth := <-got; auth != "" {
		t.Fatalf("project-chosen URL received Authorization %q", auth)
	}
}

// The user's own config is trusted: it gets the token, and it wins over the project.
func TestUserConfigOrgURLGetsTokenAndWins(t *testing.T) {
	isolate(t)
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path + " " + r.Header.Get("Authorization")
		_, _ = w.Write([]byte(orgJSON))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_ORG_POLICY_TOKEN", "org-token")
	cfg := t.TempDir()
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", cfg)
	write(t, filepath.Join(cfg, "config.json"), `{"orgPolicy": "`+srv.URL+`/org.json"}`)
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), `{"orgPolicy": "`+srv.URL+`/project.json"}`)
	if _, err := Load(proj); err != nil {
		t.Fatal(err)
	}
	if req := <-got; req != "/org.json Bearer org-token" {
		t.Fatalf("request = %q, want the user's URL with the token", req)
	}
}
