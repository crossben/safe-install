package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// attestationsJSON mirrors the registry's response: a publish attestation and
// an SLSA provenance statement, each a base64 DSSE payload.
func attestationsJSON(repo string) []byte {
	stmt := func(predicateType string, predicate any) map[string]any {
		payload, _ := json.Marshal(map[string]any{"predicateType": predicateType, "predicate": predicate})
		return map[string]any{"bundle": map[string]any{"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(payload)}}}
	}
	out, _ := json.Marshal(map[string]any{"attestations": []any{
		stmt("https://github.com/npm/attestation/tree/main/specs/publish/v0.1", map[string]any{"name": "x"}),
		stmt("https://slsa.dev/provenance/v1", map[string]any{"buildDefinition": map[string]any{
			"externalParameters": map[string]any{"workflow": map[string]any{
				"repository": repo, "ref": "refs/heads/main", "path": ".github/workflows/publish.yml"}}}}),
	}})
	return out
}

func TestProvenanceRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/-/npm/v1/attestations/esbuild@0.28.2":
			_, _ = w.Write(attestationsJSON("https://github.com/evanw/esbuild"))
		case "/-/npm/v1/attestations/@scope%2Fpkg@1.0.0":
			_, _ = w.Write(attestationsJSON("https://github.com/scope/pkg"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	ctx := context.Background()
	for _, tt := range []struct{ name, version, want string }{
		{"esbuild", "0.28.2", "https://github.com/evanw/esbuild"},
		{"@scope/pkg", "1.0.0", "https://github.com/scope/pkg"},
		{"no-provenance", "1.0.0", ""},
	} {
		got, err := c.ProvenanceRepo(ctx, tt.name, tt.version)
		if err != nil || got != tt.want {
			t.Errorf("ProvenanceRepo(%s@%s) = %q, %v; want %q", tt.name, tt.version, got, err, tt.want)
		}
	}
}
