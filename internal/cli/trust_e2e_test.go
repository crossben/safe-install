package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/policy"
)

// provenanceServer answers npm attestation requests with an SLSA statement
// naming *repo (changeable during a test).
func provenanceServer(t *testing.T, repo *atomic.Value) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/-/npm/v1/attestations/") || repo.Load().(string) == "" {
			http.NotFound(w, r)
			return
		}
		payload, _ := json.Marshal(map[string]any{"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": map[string]any{"buildDefinition": map[string]any{"externalParameters": map[string]any{
				"workflow": map[string]any{"repository": repo.Load().(string)}}}}})
		_ = json.NewEncoder(w).Encode(map[string]any{"attestations": []any{map[string]any{
			"bundle": map[string]any{"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(payload)}}}}})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("npm_config_registry", srv.URL)
}

func TestTrustProvenance(t *testing.T) {
	markers := installProject(t)
	var repo atomic.Value
	repo.Store("https://github.com/good/dep")
	provenanceServer(t, &repo)

	if out, err := runInstallCLI(t, "", false); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if out, err := runCmd(t, "approve", "good-dep", "--trust", "provenance"); err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	if a := readPolicy(t).AllowScripts["good-dep"]; a.Trust != policy.TrustProvenance || a.Repository != "https://github.com/good/dep" {
		t.Fatalf("approval = %+v", a)
	}

	// The scripts change in a new build from the same repository: still trusted.
	clearMarkers(t, markers)
	if err := os.WriteFile(filepath.Join("node_modules", "good-dep", "marker.js"), []byte(markerFile+"// v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runInstallCLI(t, "", false)
	if err != nil || !slices.Equal(listMarkers(t, markers), goodMarkers) {
		t.Fatalf("same-repository build not run: %v %v\n%s", err, listMarkers(t, markers), out)
	}

	// Provenance now points elsewhere (a fork, a stolen token): not trusted.
	clearMarkers(t, markers)
	repo.Store("https://github.com/attacker/dep")
	out, _ = runInstallCLI(t, "", false)
	if len(listMarkers(t, markers)) != 0 || !strings.Contains(out, "trusts builds from https://github.com/good/dep") {
		t.Fatalf("other-repository build ran or was not explained: %v\n%s", listMarkers(t, markers), out)
	}
}

func TestApproveWithoutProvenanceFails(t *testing.T) {
	installProject(t)
	var repo atomic.Value
	repo.Store("")
	provenanceServer(t, &repo)
	if out, err := runInstallCLI(t, "", false); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if _, err := runCmd(t, "approve", "good-dep", "--trust", "provenance"); err == nil || !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("err = %v", err)
	}
	if _, err := runCmd(t, "approve", "good-*"); err == nil || !strings.Contains(err.Error(), "--trust provenance") {
		t.Fatalf("glob without provenance: %v", err)
	}
}

func TestApproveExpires(t *testing.T) {
	markers := installProject(t)
	if out, err := runInstallCLI(t, "", false); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if out, err := runCmd(t, "approve", "good-dep", "--expires", "90d", "--no-run"); err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	want := time.Now().UTC().AddDate(0, 0, 90).Format("2006-01-02")
	if got := readPolicy(t).AllowScripts["good-dep"].Expires; got != want {
		t.Fatalf("expires = %q, want %q", got, want)
	}
	// Force it into the past: the approval no longer applies.
	f := readPolicy(t)
	a := f.AllowScripts["good-dep"]
	a.Expires = "2020-01-01"
	if err := policy.Approve(policy.FileName, "good-dep", a); err != nil {
		t.Fatal(err)
	}
	out, _ := runInstallCLI(t, "", false)
	if len(listMarkers(t, markers)) != 0 || !strings.Contains(out, "approval expired") {
		t.Fatalf("expired approval used: %v\n%s", listMarkers(t, markers), out)
	}
}
