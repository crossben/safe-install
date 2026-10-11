package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// testdata/pypi/requests.json is PyPI's real document for requests, trimmed
// to three releases: 2.0.0, 2.32.0 (really yanked) and 2.32.3.
func TestPyPIDocument(t *testing.T) {
	body, err := os.ReadFile("testdata/pypi/requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	p := &PyPI{Client: &Client{}, BaseURL: srv.URL}
	doc, err := p.Packument(context.Background(), "Requests")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/pypi/requests/json" {
		t.Fatalf("requested %v (name must be normalized)", paths)
	}
	ok := doc.Versions["2.32.3"]
	if ok.Yanked || len(ok.Files) != 2 || len(ok.Files[0].SHA256) != 64 || doc.Published("2.32.3").IsZero() {
		t.Fatalf("2.32.3 = %+v", ok)
	}
	yanked := doc.Versions["2.32.0"]
	if !yanked.Yanked || !strings.Contains(string(yanked.Deprecated), "CVE-2024-35195") {
		t.Fatalf("2.32.0 should be yanked with PyPI's reason: %+v", yanked)
	}
	if !doc.Published("2.0.0").Before(doc.Published("2.32.3")) {
		t.Fatal("publish times out of order")
	}
}

func TestPyPIRejectsNonProjects(t *testing.T) {
	for _, body := range []string{`{}`, `not json`, `{"info":{}}`} {
		if _, err := decodePyPI([]byte(body)); err == nil {
			t.Errorf("accepted %q", body)
		}
	}
}
