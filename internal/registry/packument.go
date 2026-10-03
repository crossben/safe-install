// Package registry fetches package metadata from an npm-compatible registry.
package registry

import (
	"encoding/json"
	"time"
)

// Packument is the registry document for one package (the parts we use).
type Packument struct {
	Name     string                 `json:"name"`
	DistTags map[string]string      `json:"dist-tags"`
	Versions map[string]VersionMeta `json:"versions"`

	// Publish time per version; non-version keys ("created", "modified") included.
	Time map[string]time.Time `json:"-"`
}

// VersionMeta is one version's manifest as published.
type VersionMeta struct {
	Version     string     `json:"version"`
	NpmUser     Person     `json:"_npmUser"`
	Maintainers []Person   `json:"maintainers"`
	Deprecated  FlexString `json:"deprecated"`
	Dist        struct {
		Integrity    string        `json:"integrity"`
		Shasum       string        `json:"shasum"`
		Tarball      string        `json:"tarball"`
		Attestations *Attestations `json:"attestations"`
	} `json:"dist"`
	Scripts map[string]string `json:"scripts"`
}

// Person is a registry user.
type Person struct {
	Name             string            `json:"name"`
	TrustedPublisher *TrustedPublisher `json:"trustedPublisher"` // set when published from CI via OIDC
}

// TrustedPublisher identifies an npm trusted-publishing (OIDC) publish.
type TrustedPublisher struct {
	ID string `json:"id"` // e.g. "github"
}

// Attestations are the registry's signed statements about a version.
type Attestations struct {
	Provenance *Provenance `json:"provenance"`
}

// Provenance marks a version built and published with a provenance statement.
type Provenance struct {
	PredicateType string `json:"predicateType"`
}

// HasProvenance reports whether the version was published with provenance.
func (m *VersionMeta) HasProvenance() bool {
	return m.Dist.Attestations != nil && m.Dist.Attestations.Provenance != nil
}

// Published returns when version was published, or the zero time.
func (p *Packument) Published(version string) time.Time {
	return p.Time[version]
}

// UnmarshalJSON tolerates non-timestamp entries in "time" (unpublished packages).
func (p *Packument) UnmarshalJSON(data []byte) error {
	type plain Packument
	var aux struct {
		*plain
		Time map[string]json.RawMessage `json:"time"`
	}
	aux.plain = (*plain)(p)
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.Time = make(map[string]time.Time, len(aux.Time))
	for k, raw := range aux.Time {
		var t time.Time
		if json.Unmarshal(raw, &t) == nil {
			p.Time[k] = t
		}
	}
	return nil
}

// FlexString accepts a string or any other JSON value (some old packages
// publish "deprecated": false); non-strings become "".
type FlexString string

// UnmarshalJSON keeps strings and ignores any other JSON value.
func (f *FlexString) UnmarshalJSON(data []byte) error {
	var s string
	if json.Unmarshal(data, &s) == nil {
		*f = FlexString(s)
	}
	return nil
}
