package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func whyFixture(t *testing.T) {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "lockfile", "testdata", "basic", "npm"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Chdir(dir)
}

func TestWhyText(t *testing.T) {
	whyFixture(t)
	out, err := runCLIOut(t, "why", "ms")
	if err != nil {
		t.Fatalf("why: %v\n%s", err, out)
	}
	for _, want := range []string{
		"ms@2.0.0",
		"your project › debug@2.6.9 › ms@2.0.0",
		"ms@2.1.3  (direct)",
		"your project › ms@2.1.3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	out, err = runCLIOut(t, "why", "is-number")
	if err != nil || !strings.Contains(out, "is-number@6.0.0  (dev)") || !strings.Contains(out, "is-odd@3.0.1 › is-number@6.0.0") {
		t.Errorf("dev chain: %v\n%s", err, out)
	}
}

func TestWhyJSON(t *testing.T) {
	whyFixture(t)
	out, err := runCLIOut(t, "why", "ms@2.0.0", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var got []struct {
		ID     string     `json:"id"`
		Direct bool       `json:"direct"`
		Dev    bool       `json:"dev"`
		Total  int        `json:"total"`
		Paths  [][]string `json:"paths"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if len(got) != 1 || got[0].ID != "ms@2.0.0" || got[0].Total != 1 || strings.Join(got[0].Paths[0], ">") != "debug@2.6.9>ms@2.0.0" {
		t.Fatalf("got %+v", got)
	}
}

func TestWhyUnknownPackage(t *testing.T) {
	whyFixture(t)
	_, err := runCLIOut(t, "why", "left-pad")
	if code := exitCode(err); code != ExitPolicyFailure || !strings.Contains(err.Error(), "not in") {
		t.Fatalf("exit %d: %v", code, err)
	}
}
