package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/crossben/safe-install/internal/ecosystem"
)

// DefaultPackagistURL serves Composer's v2 metadata.
const DefaultPackagistURL = "https://repo.packagist.org"

// Packagist fetches Composer v2 metadata (/p2/vendor/name.json) and presents
// it in the packument shape the rules read: a version's publish time is when
// Packagist saw it (published-time; the tag's own date is the author's to
// set), abandoned packages are deprecated, and each version keeps the commit
// its dist points at.
type Packagist struct {
	*Client
	BaseURL string // default DefaultPackagistURL
}

// Packument fetches the metadata for "vendor/name".
func (p *Packagist) Packument(ctx context.Context, name string) (*Packument, error) {
	base := p.BaseURL
	if base == "" {
		base = DefaultPackagistURL
	}
	name = ecosystem.Normalize(ecosystem.Packagist, name)
	vendor, pkg, ok := strings.Cut(name, "/")
	if !ok || vendor == "" || pkg == "" || strings.ContainsAny(name, "?#\\") || strings.Contains(pkg, "/") {
		return nil, fmt.Errorf("%s: not a Composer package name", name)
	}
	u := strings.TrimSuffix(base, "/") + "/p2/" + vendor + "/" + pkg + ".json"
	return p.document(ctx, name, u, func(body []byte) (*Packument, error) { return decodePackagist(name, body) }, "application/json")
}

func decodePackagist(name string, body []byte) (*Packument, error) {
	var doc struct {
		Minified string                                  `json:"minified"`
		Packages map[string][]map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding Packagist metadata: %w", err)
	}
	versions, ok := doc.Packages[name]
	if !ok {
		return nil, fmt.Errorf("decoding Packagist metadata: no %s in the response", name)
	}
	if doc.Minified != "" {
		versions = expandMinified(versions)
	}
	p := &Packument{Name: name, Versions: map[string]VersionMeta{}, Time: map[string]time.Time{}}
	for _, raw := range versions {
		var v struct {
			Version       string          `json:"version"`
			Type          string          `json:"type"`
			Time          time.Time       `json:"time"`
			PublishedTime time.Time       `json:"published-time"`
			Abandoned     json.RawMessage `json:"abandoned"`
			Dist          struct {
				URL       string `json:"url"`
				Reference string `json:"reference"`
				Shasum    string `json:"shasum"`
			} `json:"dist"`
		}
		b, _ := json.Marshal(raw)
		if json.Unmarshal(b, &v) != nil || v.Version == "" {
			continue
		}
		m := VersionMeta{Version: v.Version, Ref: v.Dist.Reference, Plugin: v.Type == "composer-plugin"}
		m.Dist.Tarball, m.Dist.Shasum = v.Dist.URL, v.Dist.Shasum
		if abandoned, replacement := parseAbandoned(v.Abandoned); abandoned {
			m.Abandoned, m.Deprecated = true, FlexString(replacement)
		}
		p.Versions[v.Version] = m
		if !v.PublishedTime.IsZero() {
			p.Time[v.Version] = v.PublishedTime
		} else {
			p.Time[v.Version] = v.Time
		}
	}
	return p, nil
}

// expandMinified undoes Composer's metadata minification: each entry holds
// only what changed since the previous one, and "__unset" removes a key.
func expandMinified(in []map[string]json.RawMessage) []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, 0, len(in))
	var cur map[string]json.RawMessage
	for _, entry := range in {
		if cur == nil {
			cur = map[string]json.RawMessage{}
		} else {
			next := make(map[string]json.RawMessage, len(cur))
			for k, v := range cur {
				next[k] = v
			}
			cur = next
		}
		for k, v := range entry {
			if string(v) == `"__unset"` {
				delete(cur, k)
				continue
			}
			cur[k] = v
		}
		out = append(out, cur)
	}
	return out
}

// abandoned is false, true, or the name of a replacement package.
func parseAbandoned(raw json.RawMessage) (bool, string) {
	if len(raw) == 0 || string(raw) == "false" || string(raw) == "null" {
		return false, ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return true, s
	}
	return string(raw) == "true", ""
}
