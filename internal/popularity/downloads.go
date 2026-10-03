package popularity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultDownloadsURL is npm's download-count API.
const DefaultDownloadsURL = "https://api.npmjs.org"

// bulkLimit is the most unscoped names npm's API accepts in one request.
const bulkLimit = 128

// Downloads fetches weekly download counts.
type Downloads struct {
	BaseURL string       // default DefaultDownloadsURL
	HTTP    *http.Client // default: 30s timeout
}

type point struct {
	Downloads int `json:"downloads"`
}

// Weekly returns last week's downloads per name; unknown names are absent.
// Unscoped names are fetched in bulk; scoped names one by one (the API
// does not batch them).
func (d *Downloads) Weekly(ctx context.Context, names []string) (map[string]int, error) {
	out := map[string]int{}
	var unscoped []string
	for _, n := range names {
		if strings.HasPrefix(n, "@") {
			if err := d.single(ctx, n, out); err != nil {
				return out, err
			}
		} else {
			unscoped = append(unscoped, n)
		}
	}
	for len(unscoped) > 0 {
		chunk := unscoped[:min(bulkLimit, len(unscoped))]
		unscoped = unscoped[len(chunk):]
		if len(chunk) == 1 { // a one-name "bulk" request answers in the single format
			if err := d.single(ctx, chunk[0], out); err != nil {
				return out, err
			}
			continue
		}
		var res map[string]*point
		if err := d.get(ctx, strings.Join(chunk, ","), &res); err != nil {
			return out, err
		}
		for n, p := range res {
			if p != nil {
				out[n] = p.Downloads
			}
		}
	}
	return out, nil
}

func (d *Downloads) single(ctx context.Context, name string, out map[string]int) error {
	var p point
	err := d.get(ctx, url.PathEscape(name), &p)
	if errors.Is(err, errNotFound) {
		return nil
	}
	if err == nil {
		out[name] = p.Downloads
	}
	return err
}

var errNotFound = errors.New("not found")

func (d *Downloads) get(ctx context.Context, path string, v any) error {
	base := d.BaseURL
	if base == "" {
		base = DefaultDownloadsURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/downloads/point/last-week/"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "safe-install")
	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download counts: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download counts: %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}
