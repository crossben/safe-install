package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func fakeOSV(t *testing.T, details *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []Query `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			var results []map[string]any
			for _, q := range req.Queries {
				switch q.Package.Name {
				case "lodash":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-1"}, {"id": "GHSA-2"}}})
				case "evil":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "MAL-2025-1"}}})
				default:
					results = append(results, map[string]any{})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/GHSA-1":
			details.Add(1)
			_, _ = w.Write([]byte(`{"id":"GHSA-1","summary":"Prototype Pollution","database_specific":{"severity":"HIGH"}}`))
		case "/v1/vulns/GHSA-2":
			details.Add(1)
			_, _ = w.Write([]byte(`{"id":"GHSA-2","summary":"ReDoS","database_specific":{"severity":"MODERATE"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLookup(t *testing.T) {
	var details atomic.Int32
	c := &Client{BaseURL: fakeOSV(t, &details).URL}
	got, err := c.Lookup(context.Background(), []Package{
		{"lodash", "4.17.15"}, {"evil", "1.0.0"}, {"react", "18.3.1"}, {"lodash", "4.17.15"},
	})
	if err != nil {
		t.Fatal(err)
	}
	lodash := got[Package{"lodash", "4.17.15"}]
	if len(lodash) != 2 || lodash[0].ID != "GHSA-1" || lodash[0].Severity != "HIGH" || lodash[0].Summary != "Prototype Pollution" {
		t.Fatalf("lodash = %+v", lodash)
	}
	evil := got[Package{"evil", "1.0.0"}]
	if len(evil) != 1 || !evil[0].Malicious() {
		t.Fatalf("evil = %+v", evil)
	}
	if len(got[Package{"react", "18.3.1"}]) != 0 {
		t.Fatal("react has vulns")
	}
	// Details fetched once per advisory; MAL entries need none.
	if details.Load() != 2 {
		t.Fatalf("detail fetches = %d, want 2", details.Load())
	}
}

func TestLookupBatches(t *testing.T) {
	var details atomic.Int32
	var batches atomic.Int32
	inner := fakeOSV(t, &details)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			batches.Add(1)
		}
		proxy, _ := http.NewRequest(r.Method, inner.URL+r.URL.Path, r.Body)
		resp, err := http.DefaultClient.Do(proxy)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer srv.Close()

	pkgs := make([]Package, 2500)
	for i := range pkgs {
		pkgs[i] = Package{Name: "p", Version: fmt.Sprint(i)}
	}
	if _, err := (&Client{BaseURL: srv.URL}).Lookup(context.Background(), pkgs); err != nil {
		t.Fatal(err)
	}
	if batches.Load() != 3 {
		t.Fatalf("batches = %d, want 3", batches.Load())
	}
}

func TestLookupError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := (&Client{BaseURL: srv.URL}).Lookup(context.Background(), []Package{{"a", "1"}}); err == nil {
		t.Fatal("expected error")
	}
}
