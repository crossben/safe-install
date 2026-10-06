package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/crossben/safe-install/internal/cache"
)

// maxOrgPolicy bounds a fetched organization policy.
const maxOrgPolicy = 1 << 20

// orgSource picks the organization policy: $SAFE_INSTALL_ORG_POLICY, then the
// user's config, then the project file. trusted is false for a project file:
// anyone can change one (a pull request), so it never receives the org token.
func orgSource(project, global *File) (src string, trusted bool) {
	if s := os.Getenv("SAFE_INSTALL_ORG_POLICY"); s != "" {
		return s, true
	}
	if global != nil && global.OrgPolicy != "" {
		return global.OrgPolicy, true
	}
	if project != nil && project.OrgPolicy != "" {
		return project.OrgPolicy, false
	}
	return "", false
}

// loadOrg reads the organization policy from a path or URL. A URL that
// cannot be fetched falls back to the last cached copy (warning); with no
// cache it is an error: the organization's rules are never silently skipped.
func loadOrg(src string, trusted bool) (f *File, warning string, err error) {
	if !strings.Contains(src, "://") {
		f, err := Read(src)
		if err != nil {
			return nil, "", fmt.Errorf("organization policy %s: %w", src, err)
		}
		return f, "", nil
	}
	u, err := url.Parse(src)
	if err != nil {
		return nil, "", fmt.Errorf("organization policy %s: %w", src, err)
	}
	// https only; plain http just for a policy served on this machine.
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return nil, "", fmt.Errorf("organization policy %s: must be an https URL", src)
	}
	cache := orgCachePath(src)
	data, fetchErr := fetchOrg(u.String(), trusted)
	if fetchErr == nil {
		f, err := parseFile(data, src)
		if err != nil {
			return nil, "", err
		}
		if cache != "" && os.MkdirAll(filepath.Dir(cache), 0o750) == nil {
			_ = os.WriteFile(cache, data, 0o600) // best effort
		}
		return f, "", nil
	}
	if cache != "" {
		if data, err := os.ReadFile(cache); err == nil { // #nosec G304 -- our cache file
			if f, err := parseFile(data, src); err == nil {
				return f, fmt.Sprintf("using the cached organization policy (%v)", fetchErr), nil
			}
		}
	}
	return nil, "", fmt.Errorf("organization policy %s is unavailable and not cached: %w", src, fetchErr)
}

func fetchOrg(rawURL string, sendToken bool) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "safe-install")
	// Only for a trusted source, and only to this host: Go drops Authorization
	// on a redirect to another one.
	if tok := os.Getenv("SAFE_INSTALL_ORG_POLICY_TOKEN"); tok != "" && sendToken {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxOrgPolicy+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxOrgPolicy {
		return nil, fmt.Errorf("larger than %d bytes", maxOrgPolicy)
	}
	return data, nil
}

func parseFile(data []byte, src string) (*File, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("organization policy %s: %w", src, err)
	}
	if f.AllowScripts == nil {
		f.AllowScripts = map[string]Approval{}
	}
	return &f, nil
}

func orgCachePath(src string) string {
	dir := cache.Sub(cache.Org)
	if dir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(src))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// enforce keeps the organization's minimums: the effective minReleaseAge is
// at least the org's, and failOn at least as strict.
func (p *Policy) enforce(org *File) {
	if org.MinReleaseAge != "" {
		if d, ok := duration(p.MinReleaseAge); !ok || d < mustDuration(org.MinReleaseAge) {
			p.MinReleaseAge = org.MinReleaseAge
		}
	}
	if org.FailOn != "" && failRank(p.FailOn) > failRank(org.FailOn) {
		p.FailOn = org.FailOn
	}
}

// failRank orders failOn by strictness: low fails on the most.
func failRank(level string) int {
	switch strings.ToLower(level) {
	case "low":
		return 1
	case "medium":
		return 2
	case "", "high":
		return 3 // "" is the default, high
	case "block":
		return 4
	}
	return 5 // none: never fails
}

// duration parses "72h", "3d" or "0".
func duration(s string) (time.Duration, bool) {
	if s == "" {
		return 72 * time.Hour, true // the default
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		return time.Duration(n) * 24 * time.Hour, err == nil && n >= 0
	}
	d, err := time.ParseDuration(s)
	return d, err == nil && d >= 0
}

func mustDuration(s string) time.Duration {
	d, _ := duration(s)
	return d
}

// Blocked reports whether name matches a blockPackages glob.
func (p *Policy) Blocked(name string) bool {
	for _, g := range p.blocks {
		if ok, _ := path.Match(g, name); ok || g == name {
			return true
		}
	}
	return false
}
