package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ProvenanceRepo returns the source repository recorded in a version's npm
// provenance (SLSA statement), or "" when the version has none. The registry
// verifies attestations at publish time; this reads them, it does not
// re-verify their Sigstore signatures.
func (c *Client) ProvenanceRepo(ctx context.Context, name, version string) (string, error) {
	base := c.BaseURL
	if c.Config != nil {
		base = c.Config.RegistryFor(name)
	}
	if base == "" {
		base = DefaultURL
	}
	u := strings.TrimSuffix(base, "/") + "/-/npm/v1/attestations/" + url.PathEscape(name) + "@" + url.PathEscape(version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "safe-install")
	if c.Config != nil {
		if auth := c.Config.AuthFor(u); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("provenance of %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("provenance of %s@%s: registry returned %s", name, version, resp.Status)
	}
	var doc struct {
		Attestations []struct {
			Bundle struct {
				DSSE struct {
					Payload string `json:"payload"`
				} `json:"dsseEnvelope"`
			} `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&doc); err != nil {
		return "", fmt.Errorf("provenance of %s@%s: %w", name, version, err)
	}
	for _, a := range doc.Attestations {
		raw, err := base64.StdEncoding.DecodeString(a.Bundle.DSSE.Payload)
		if err != nil {
			continue
		}
		var stmt struct {
			PredicateType string `json:"predicateType"`
			Predicate     struct {
				BuildDefinition struct {
					ExternalParameters struct {
						Workflow struct {
							Repository string `json:"repository"`
						} `json:"workflow"`
					} `json:"externalParameters"`
				} `json:"buildDefinition"`
			} `json:"predicate"`
		}
		if json.Unmarshal(raw, &stmt) != nil || !strings.HasPrefix(stmt.PredicateType, "https://slsa.dev/provenance/") {
			continue
		}
		if repo := stmt.Predicate.BuildDefinition.ExternalParameters.Workflow.Repository; repo != "" {
			return repo, nil
		}
	}
	return "", nil // no SLSA provenance among the attestations
}
