package registry

import (
	"context"
	"crypto/sha1" // #nosec G505 -- only to verify legacy sha1 SRI from old lockfiles
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

// defaultMaxTarball bounds a downloaded package tarball.
const defaultMaxTarball = 100 << 20

// Integrity errors.
var (
	ErrIntegrity   = errors.New("tarball does not match its integrity hash")
	ErrNoIntegrity = errors.New("no supported integrity hash to verify against")
)

// Tarball downloads a package tarball with the credentials configured for its URL.
func (c *Client) Tarball(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "safe-install")
	if c.Config != nil {
		if auth := c.Config.AuthFor(url); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading tarball: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", url, ErrNotFound)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%s: %w (%s)", url, ErrUnauthorized, resp.Status)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: registry returned %s", url, resp.Status)
	}
	limit := c.MaxTarball
	if limit <= 0 {
		limit = defaultMaxTarball
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("downloading tarball: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: tarball larger than %d bytes", url, limit)
	}
	return data, nil
}

// VerifyIntegrity checks data against the strongest supported hash of an SRI
// string ("sha512-… sha1-…").
func VerifyIntegrity(data []byte, sri string) error {
	algos := []struct {
		name string
		new  func() hash.Hash
	}{
		{"sha512", sha512.New}, {"sha384", sha512.New384}, {"sha256", sha256.New}, {"sha1", sha1.New},
	}
	digests := map[string]string{}
	for _, part := range strings.Fields(sri) {
		if algo, sum, ok := strings.Cut(part, "-"); ok {
			digests[algo] = sum
		}
	}
	for _, a := range algos {
		want, ok := digests[a.name]
		if !ok {
			continue
		}
		expected, err := base64.StdEncoding.DecodeString(want)
		if err != nil {
			return fmt.Errorf("%w: malformed %s digest", ErrIntegrity, a.name)
		}
		h := a.new()
		h.Write(data)
		if subtle.ConstantTimeCompare(h.Sum(nil), expected) != 1 {
			return fmt.Errorf("%w (%s)", ErrIntegrity, a.name)
		}
		return nil
	}
	return ErrNoIntegrity
}
