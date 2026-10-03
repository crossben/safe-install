package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{"unreachable metadata is a tool error", 0, false, nil, ExitToolError},
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
