package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Real Packagist metadata: swiftmailer is abandoned in favor of
// symfony/mailer; monolog is current.
func TestPackagistDocuments(t *testing.T) {
	serve := func(file string) *httptest.Server {
		body, err := os.ReadFile("testdata/packagist/" + file)
		if err != nil {
			t.Fatal(err)
		}
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	}
	srv := serve("swiftmailer.json")
	defer srv.Close()
	doc, err := (&Packagist{Client: &Client{}, BaseURL: srv.URL}).Packument(context.Background(), "SwiftMailer/SwiftMailer")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Versions) < 50 {
		t.Fatalf("only %d versions: minified metadata not expanded", len(doc.Versions))
	}
	for v, m := range doc.Versions {
		if !m.Abandoned || string(m.Deprecated) != "symfony/mailer" {
			t.Fatalf("%s not abandoned in favor of symfony/mailer (inherited through minification): %+v", v, m)
		}
		if m.Ref == "" || doc.Published(v).IsZero() {
			t.Fatalf("%s: ref %q time %v", v, m.Ref, doc.Published(v))
		}
	}
	srv2 := serve("monolog.json")
	defer srv2.Close()
	mono, err := (&Packagist{Client: &Client{}, BaseURL: srv2.URL}).Packument(context.Background(), "monolog/monolog")
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := mono.Versions["3.7.0"]; !ok || m.Abandoned || len(m.Ref) != 40 {
		t.Fatalf("monolog 3.7.0 = %+v", m)
	}
}

func TestExpandMinified(t *testing.T) {
	raw := func(s string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	out := expandMinified([]map[string]json.RawMessage{
		raw(`{"version":"2.0","type":"composer-plugin","abandoned":true}`),
		raw(`{"version":"1.0","abandoned":"__unset"}`),
	})
	if string(out[1]["type"]) != `"composer-plugin"` || out[1]["abandoned"] != nil || string(out[0]["abandoned"]) != "true" {
		t.Fatalf("expanded: %v", out)
	}
}

func TestPackagistRejectsBadNames(t *testing.T) {
	p := &Packagist{Client: &Client{}, BaseURL: "http://127.0.0.1:1"}
	for _, n := range []string{"monolog", "a/b/c", "a/../b", "/x", "a/b?x"} {
		if _, err := p.Packument(context.Background(), n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}
