package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crossben/safe-install/internal/ecosystem"
)

// DefaultPyPIURL is the Python Package Index.
const DefaultPyPIURL = "https://pypi.org"

// PyPI fetches PyPI's JSON API and presents each project in the packument
// shape the rules read: a version's publish time is its first file upload, a
// version whose every file is yanked is deprecated ("yanked: reason"), and
// the files with their hashes are kept for the integrity rules.
type PyPI struct {
	*Client        // HTTP, cache and offline behavior are shared with npm's client
	BaseURL string // default DefaultPyPIURL
}

// Packument fetches the project document for name.
func (p *PyPI) Packument(ctx context.Context, name string) (*Packument, error) {
	base := p.BaseURL
	if base == "" {
		base = DefaultPyPIURL
	}
	u := strings.TrimSuffix(base, "/") + "/pypi/" + url.PathEscape(ecosystem.Normalize(ecosystem.PyPI, name)) + "/json"
	return p.document(ctx, name, u, decodePyPI)
}

type pypiFile struct {
	Filename    string            `json:"filename"`
	URL         string            `json:"url"`
	Digests     map[string]string `json:"digests"`
	PackageType string            `json:"packagetype"`
	Uploaded    time.Time         `json:"upload_time_iso_8601"`
	Yanked      bool              `json:"yanked"`
	YankReason  string            `json:"yanked_reason"`
}

func decodePyPI(body []byte) (*Packument, error) {
	var doc struct {
		Info struct {
			Name string `json:"name"`
		} `json:"info"`
		Releases map[string][]pypiFile `json:"releases"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding PyPI project: %w", err)
	}
	if doc.Info.Name == "" {
		return nil, fmt.Errorf("decoding PyPI project: no name")
	}
	p := &Packument{
		Name:     ecosystem.Normalize(ecosystem.PyPI, doc.Info.Name),
		Versions: map[string]VersionMeta{},
		Time:     map[string]time.Time{},
	}
	for version, files := range doc.Releases {
		if len(files) == 0 {
			continue // a version with no files cannot be installed
		}
		m := VersionMeta{Version: version}
		yanked, reason := true, ""
		var first time.Time
		for _, f := range files {
			m.Files = append(m.Files, DistFile{
				Name: f.Filename, URL: f.URL, SHA256: strings.ToLower(f.Digests["sha256"]),
				Uploaded: f.Uploaded, Yanked: f.Yanked, Sdist: f.PackageType == "sdist",
			})
			if first.IsZero() || (!f.Uploaded.IsZero() && f.Uploaded.Before(first)) {
				first = f.Uploaded
			}
			if !f.Yanked {
				yanked = false
			} else if reason == "" {
				reason = f.YankReason
			}
		}
		if yanked {
			m.Deprecated = FlexString(reason)
			m.Yanked = true
		}
		p.Versions[version] = m
		p.Time[version] = first
	}
	return p, nil
}
