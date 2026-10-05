package registry

import (
	"context"
	"crypto/sha1" // #nosec G505 -- testing legacy sha1 SRI support
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/npmrc"
)

func sri512(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

func TestVerifyIntegrity(t *testing.T) {
	data := []byte("tarball bytes")
	s1 := sha1.Sum(data) // #nosec G401 -- legacy SRI
	legacy := "sha1-" + base64.StdEncoding.EncodeToString(s1[:])
	tests := []struct {
		sri  string
		want error
	}{
		{sri512(data), nil},
		{legacy, nil},
		{legacy + " " + sri512(data), nil}, // strongest wins
		{legacy + " " + sri512([]byte("other")), ErrIntegrity}, // strongest mismatches
		{sri512([]byte("other")), ErrIntegrity},
		{"", ErrNoIntegrity},
		{"md5-abc", ErrNoIntegrity},
	}
	for _, tt := range tests {
		if err := VerifyIntegrity(data, tt.sri); !errors.Is(err, tt.want) {
			t.Errorf("VerifyIntegrity(%q) = %v, want %v", tt.sri, err, tt.want)
		}
	}
}

func TestTarballDownload(t *testing.T) {
	body := []byte("pretend tgz")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/missing.tgz":
			http.NotFound(w, r)
		case r.Header.Get("Authorization") != "Bearer tok":
			http.Error(w, "nope", http.StatusUnauthorized)
		default:
			_, _ = w.Write(body)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(strings.TrimPrefix(srv.URL, "http:")+"/:_authToken=tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := npmrc.Load(dir, func(k string) string { return map[string]string{"HOME": t.TempDir()}[k] })
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{Config: cfg}
	got, err := c.Tarball(context.Background(), srv.URL+"/pkg/-/pkg-1.0.0.tgz")
	if err != nil || string(got) != string(body) {
		t.Fatalf("Tarball = %q, %v", got, err)
	}
	if _, err := c.Tarball(context.Background(), srv.URL+"/missing.tgz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	anon := &Client{}
	if _, err := anon.Tarball(context.Background(), srv.URL+"/pkg.tgz"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("no credentials: %v", err)
	}
}

func TestTarballSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 2048))
	}))
	defer srv.Close()
	c := &Client{MaxTarball: 1024}
	if _, err := c.Tarball(context.Background(), srv.URL+"/big.tgz"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
}
