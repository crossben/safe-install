package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/report"
)

// checkProject writes a one-dependency npm project and a registry fixture in
// which "fresh@1.0.0" was published publishedAgo ago.
func checkProject(t *testing.T, publishedAgo time.Duration, withFixture bool) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"package.json": `{"name":"p","version":"1.0.0","dependencies":{"fresh":"1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{
			"":{"name":"p","dependencies":{"fresh":"1.0.0"}},
			"node_modules/fresh":{"version":"1.0.0","resolved":"https://registry.npmjs.org/fresh/-/fresh-1.0.0.tgz","integrity":"sha512-ok"}}}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixtures := filepath.Join(t.TempDir(), "registry.json")
	doc := map[string]any{}
	if withFixture {
		doc["fresh"] = map[string]any{
			"name":     "fresh",
			"time":     map[string]string{"1.0.0": time.Now().Add(-publishedAgo).UTC().Format(time.RFC3339)},
			"versions": map[string]any{"1.0.0": map[string]any{"version": "1.0.0", "dist": map[string]string{"integrity": "sha512-ok"}}},
		}
	}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(fixtures, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", fixtures)
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Chdir(dir)
}

func runCLIOut(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), err
}

func exitCode(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if err != nil {
		return ExitToolError
	}
	return ExitOK
}

func TestCheckJSON(t *testing.T) {
	checkProject(t, 2*time.Hour, true)
	out, err := runCLIOut(t, "check", "--format", "json")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	var rep struct {
		Format   string `json:"format"`
		Packages []struct {
			ID       string `json:"id"`
			Level    string `json:"level"`
			Findings []struct {
				Rule     string `json:"rule"`
				Severity string `json:"severity"`
			} `json:"findings"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if rep.Format != "npm" || len(rep.Packages) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	p := rep.Packages[0]
	if p.ID != "fresh@1.0.0" || p.Level != "medium" || len(p.Findings) != 1 || p.Findings[0].Rule != "SI-REC-001" || p.Findings[0].Severity != "medium" {
		t.Fatalf("package = %+v", p)
	}
}

func TestCheckExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		ago     time.Duration
		fixture bool
		args    []string
		want    int
	}{
		{"medium finding passes default fail-on high", 2 * time.Hour, true, nil, ExitOK},
		{"medium finding fails fail-on medium", 2 * time.Hour, true, []string{"--fail-on", "medium"}, ExitPolicyFailure},
		{"old release is clean", 400 * 24 * time.Hour, true, []string{"--fail-on", "low"}, ExitOK},
		{"min-age 0 disables the age rule", 2 * time.Hour, true, []string{"--fail-on", "low", "--min-age", "0"}, ExitOK},
		{"min-age in days", 2 * 24 * time.Hour, true, []string{"--fail-on", "low", "--min-age", "1d"}, ExitOK},
		{"missing from the registry is a finding", 0, false, []string{"--fail-on", "low"}, ExitPolicyFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkProject(t, tt.ago, tt.fixture)
			_, err := runCLIOut(t, append([]string{"check"}, tt.args...)...)
			if got := exitCode(err); got != tt.want {
				t.Fatalf("exit = %d (%v), want %d", got, err, tt.want)
			}
		})
	}
}

func TestCheckTextReport(t *testing.T) {
	checkProject(t, 2*time.Hour, true)
	out, err := runCLIOut(t, "check")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fresh@1.0.0", "SI-REC-001", "published 2h ago", "1 medium"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q:\n%s", want, out)
		}
	}
}

func TestParseMinAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"72h": 72 * time.Hour, "3d": 72 * time.Hour, "0": 0, "90m": 90 * time.Minute} {
		if got, err := parseMinAge(in); err != nil || got != want {
			t.Errorf("parseMinAge(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"-1h", "soon", "1w"} {
		if _, err := parseMinAge(bad); err == nil {
			t.Errorf("parseMinAge(%q): expected error", bad)
		}
	}
}

func TestCheckFlagsMaliciousPackageFromOSV(t *testing.T) {
	checkProject(t, 400*24*time.Hour, true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-2026-1"}]}]}`))
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_OSV_URL", srv.URL)

	out, err := runCLIOut(t, "check")
	if code := exitCode(err); code != ExitPolicyFailure {
		t.Fatalf("exit = %d (%v), want %d\n%s", code, err, ExitPolicyFailure, out)
	}
	if !strings.Contains(out, "known malicious package (MAL-2026-1)") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestCheckOSVOutageIsAWarning(t *testing.T) {
	checkProject(t, 400*24*time.Hour, true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	t.Setenv("SAFE_INSTALL_OSV_URL", srv.URL)

	out, err := runCLIOut(t, "check")
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "known-vulnerability check skipped") {
		t.Fatalf("no warning:\n%s", out)
	}
}

func TestCheckSARIF(t *testing.T) {
	checkProject(t, 2*time.Hour, true)
	out, err := runCLIOut(t, "check", "--format", "sarif")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Version != "2.1.0" || len(doc.Runs[0].Results) != 1 || doc.Runs[0].Results[0].RuleID != "SI-REC-001" {
		t.Fatalf("sarif: %v\n%s", err, out)
	}
}

func TestCheckSARIFFileAlongsideText(t *testing.T) {
	checkProject(t, 2*time.Hour, true)
	path := filepath.Join(t.TempDir(), "out.sarif")
	out, err := runCLIOut(t, "check", "--sarif-file", path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "SI-REC-001") {
		t.Fatalf("text report missing:\n%s", out)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"version": "2.1.0"`) {
		t.Fatalf("sarif file: %v\n%s", err, data)
	}
}

func TestCheckSummaryFile(t *testing.T) {
	checkProject(t, 2*time.Hour, true)
	path := filepath.Join(t.TempDir(), "summary.md")
	if _, err := runCLIOut(t, "check", "--fail-on", "none", "--summary-file", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(data), report.MarkdownMarker) || !strings.Contains(string(data), "`SI-REC-001`") {
		t.Fatalf("summary: %v\n%s", err, data)
	}
}
