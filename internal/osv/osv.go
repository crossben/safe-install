// Package osv looks up known vulnerabilities and malicious packages in the
// OSV database (https://osv.dev), which includes the OpenSSF malicious
// packages feed (MAL-* entries).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultURL is the public OSV API.
const DefaultURL = "https://api.osv.dev"

// batchLimit is the most queries OSV accepts per querybatch request.
const batchLimit = 1000

// Package is an npm package version to look up.
type Package struct {
	Name, Version string
}

// Query is one OSV batch query.
type Query struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// Vuln is one advisory affecting a package version.
type Vuln struct {
	ID       string
	Summary  string
	Severity string // GitHub advisory severity: LOW, MODERATE, HIGH, CRITICAL; "" if unknown
}

// Malicious reports whether the entry is a known malicious package.
func (v Vuln) Malicious() bool { return strings.HasPrefix(v.ID, "MAL-") }

// Client queries the OSV API.
type Client struct {
	BaseURL string       // default DefaultURL
	HTTP    *http.Client // default: 30s timeout
}

// Lookup returns the advisories for each package (absent when none).
func (c *Client) Lookup(ctx context.Context, pkgs []Package) (map[Package][]Vuln, error) {
	uniq := map[Package]bool{}
	var list []Package
	for _, p := range pkgs {
		if !uniq[p] {
			uniq[p] = true
			list = append(list, p)
		}
	}

	ids := map[Package][]string{}
	for start := 0; start < len(list); start += batchLimit {
		batch := list[start:min(start+batchLimit, len(list))]
		req := struct {
			Queries []Query `json:"queries"`
		}{}
		for _, p := range batch {
			var q Query
			q.Package.Name, q.Package.Ecosystem, q.Version = p.Name, "npm", p.Version
			req.Queries = append(req.Queries, q)
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != len(batch) {
			return nil, fmt.Errorf("osv: %d results for %d queries", len(resp.Results), len(batch))
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				ids[batch[i]] = append(ids[batch[i]], v.ID)
			}
		}
	}

	details, err := c.details(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := map[Package][]Vuln{}
	for p, vs := range ids {
		for _, id := range vs {
			out[p] = append(out[p], details[id])
		}
	}
	return out, nil
}

// details fetches summary and severity for each advisory once. Malicious
// package entries need no details: the ID says it all.
func (c *Client) details(ctx context.Context, ids map[Package][]string) (map[string]Vuln, error) {
	out := map[string]Vuln{}
	var todo []string
	for _, vs := range ids {
		for _, id := range vs {
			if _, seen := out[id]; seen {
				continue
			}
			out[id] = Vuln{ID: id, Summary: "known malicious package"}
			if !strings.HasPrefix(id, "MAL-") {
				todo = append(todo, id)
			}
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	sem := make(chan struct{}, 8)
	for _, id := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var d struct {
				Summary          string `json:"summary"`
				DatabaseSpecific struct {
					Severity string `json:"severity"`
				} `json:"database_specific"`
			}
			err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &d)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[id] = Vuln{ID: id, Summary: d.Summary, Severity: strings.ToUpper(d.DatabaseSpecific.Severity)}
		}()
	}
	wg.Wait()
	return out, firstErr
}

func (c *Client) do(ctx context.Context, method, path string, body, v any) error {
	base := c.BaseURL
	if base == "" {
		base = DefaultURL
	}
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "safe-install")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s %s: %s", method, path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}
