package analyze

import (
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/crossben/safe-install/internal/ecosystem"
)

// SI-REC-001: version younger than the minimum release age.
type recencyRule struct{}

func (recencyRule) ID() string { return "SI-REC-001" }

func (r recencyRule) Check(in *Input) []Finding {
	published := in.Doc.Published(in.Package.Version)
	if in.Config.MinReleaseAge <= 0 || published.IsZero() ||
		(in.Config.Exclude != nil && in.Config.Exclude(in.Package.Name)) {
		return nil
	}
	age := in.Config.Now.Sub(published)
	if age >= in.Config.MinReleaseAge {
		return nil
	}
	return []Finding{{r.ID(), Medium, fmt.Sprintf("published %s ago (minimum release age %s)",
		humanDuration(age), humanDuration(in.Config.MinReleaseAge))}}
}

// publisherWindow limits SI-REC-002 to recent releases: a takeover of an
// old version would have been found and unpublished by now.
const publisherWindow = 90 * 24 * time.Hour

// SI-REC-002: provenance dropped, a new human publisher, or maintainers
// added, on a recent release.
type publisherRule struct{ npmOnly }

func (publisherRule) ID() string { return "SI-REC-002" }

func (r publisherRule) Check(in *Input) []Finding {
	if in.Meta == nil {
		return nil
	}
	this := in.Doc.Published(in.Package.Version)
	if this.IsZero() || in.Config.Now.Sub(this) > publisherWindow {
		return nil
	}
	// Earlier versions, oldest first.
	type rel struct {
		v string
		t time.Time
	}
	var earlier []rel
	for v := range in.Doc.Versions {
		if t := in.Doc.Published(v); !t.IsZero() && t.Before(this) {
			earlier = append(earlier, rel{v, t})
		}
	}
	if len(earlier) == 0 {
		return nil
	}
	sort.Slice(earlier, func(i, j int) bool { return earlier[i].t.Before(earlier[j].t) })

	prev := earlier[len(earlier)-1].v
	prevMeta := in.Doc.Versions[prev]

	var out []Finding
	if prevMeta.HasProvenance() && !in.Meta.HasProvenance() {
		out = append(out, Finding{r.ID(), High,
			fmt.Sprintf("published without provenance, but %s had it (possible stolen token)", prev)})
	}
	// Trusted publishing (CI via OIDC) is never a "new publisher".
	if pub := in.Meta.NpmUser.Name; pub != "" && in.Meta.NpmUser.TrustedPublisher == nil {
		seen := false
		for _, e := range earlier {
			if in.Doc.Versions[e.v].NpmUser.Name == pub {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, Finding{r.ID(), High,
				fmt.Sprintf("published by %q, who never published an earlier version", pub)})
		}
	}

	var before []string
	for _, m := range prevMeta.Maintainers {
		before = append(before, m.Name)
	}
	var added []string
	for _, m := range in.Meta.Maintainers {
		if len(before) > 0 && !slices.Contains(before, m.Name) {
			added = append(added, m.Name)
		}
	}
	if len(added) > 0 {
		out = append(out, Finding{r.ID(), Low,
			fmt.Sprintf("maintainers added since %s: %s", prev, strings.Join(added, ", "))})
	}
	return out
}

// SI-DEP-001: deprecated, or the version is gone from the registry.
type deprecatedRule struct{}

func (deprecatedRule) ID() string { return "SI-DEP-001" }

func (r deprecatedRule) Check(in *Input) []Finding {
	if in.Meta == nil {
		return []Finding{{r.ID(), Low, "version not found in the registry (unpublished?)"}}
	}
	if in.Meta.Yanked {
		msg := "yanked"
		if reason := strings.TrimSpace(string(in.Meta.Deprecated)); reason != "" {
			msg += ": " + reason
		}
		return []Finding{{r.ID(), Low, msg}}
	}
	if msg := string(in.Meta.Deprecated); msg != "" {
		return []Finding{{r.ID(), Low, "deprecated: " + msg}}
	}
	return nil
}

// SI-INT-001: lockfile integrity differs from the registry's.
type integrityRule struct{}

func (integrityRule) ID() string { return "SI-INT-001" }

func (r integrityRule) Check(in *Input) []Finding {
	if len(in.Package.Files) > 0 {
		return r.checkFiles(in)
	}
	if in.Meta == nil || in.Package.Integrity == "" || in.Meta.Dist.Integrity == "" {
		return nil
	}
	want := sriByAlgo(in.Meta.Dist.Integrity)
	for algo, sum := range sriByAlgo(in.Package.Integrity) {
		if reg, ok := want[algo]; ok && reg != sum {
			return []Finding{{r.ID(), Block, fmt.Sprintf("lockfile %s hash does not match the registry's", algo)}}
		}
	}
	return nil
}

// checkFiles (Python): every hash the lockfile pins must be a file the
// registry has for this version. A hash it does not know is a file that did
// not come from there: tampered, or swapped.
func (r integrityRule) checkFiles(in *Input) []Finding {
	if in.Meta == nil || len(in.Meta.Files) == 0 {
		return nil
	}
	known := map[string]bool{}
	byName := map[string]string{}
	for _, f := range in.Meta.Files {
		known[f.SHA256] = true
		byName[f.Name] = f.SHA256
	}
	for _, f := range in.Package.Files {
		algo, sum, _ := strings.Cut(f.Hash, ":")
		if algo != "sha256" || known[strings.ToLower(sum)] {
			continue
		}
		what := "a file"
		if f.Name != "" {
			what = f.Name
			if _, listed := byName[f.Name]; !listed {
				what += " (not a file of this version)"
			}
		}
		return []Finding{{r.ID(), Block, fmt.Sprintf("lockfile sha256 for %s does not match any file the registry has", what)}}
	}
	return nil
}

// sriByAlgo splits an SRI string ("sha512-… sha1-…") into algo -> digest.
func sriByAlgo(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Fields(s) {
		if algo, sum, ok := strings.Cut(part, "-"); ok {
			out[algo] = sum
		}
	}
	return out
}

// SI-INT-002: tarball resolved from somewhere other than the registry.
type sourceRule struct{}

func (sourceRule) ID() string { return "SI-INT-002" }

func (r sourceRule) Check(in *Input) []Finding {
	if len(in.Config.RegistryHosts) == 0 {
		return nil
	}
	// The resolved index or tarball, and (Python) every file URL the lockfile
	// pins: uv downloads each file from its own URL.
	urls := []string{in.Package.Resolved}
	for _, f := range in.Package.Files {
		urls = append(urls, f.URL)
	}
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		got, err := url.Parse(raw)
		if err != nil || (got.Scheme != "http" && got.Scheme != "https") {
			continue
		}
		if !slices.ContainsFunc(in.Config.RegistryHosts, func(h string) bool { return sameRegistry(got.Hostname(), h) }) {
			return []Finding{{r.ID(), High, fmt.Sprintf("downloaded from %s, not a configured registry (%s)",
				got.Hostname(), strings.Join(in.Config.RegistryHosts, ", "))}}
		}
	}
	return nil
}

// registry.yarnpkg.com is a CNAME for the npm registry.
func sameRegistry(a, b string) bool {
	norm := func(h string) string {
		if h == "registry.yarnpkg.com" {
			return "registry.npmjs.org"
		}
		return h
	}
	return strings.EqualFold(norm(a), norm(b))
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

// SI-POP-001: name imitates a popular package.
type typosquatRule struct{}

func (typosquatRule) ID() string { return "SI-POP-001" }

func (r typosquatRule) Check(in *Input) []Finding {
	if in.Config.Popular == nil {
		return nil
	}
	if target, ok := in.Config.Popular.Typosquat(in.Package.Name); ok {
		return []Finding{{r.ID(), High, fmt.Sprintf("name looks like the popular package %q", target)}}
	}
	return nil
}

// unpopular is the weekly download count below which SI-POP-002 applies.
const unpopular = 1000

// SI-POP-002: rarely used package that runs install scripts.
type popularityRule struct{ npmOnly }

func (popularityRule) ID() string { return "SI-POP-002" }

func (r popularityRule) Check(in *Input) []Finding {
	if in.Meta == nil || in.Downloads < 0 || in.Downloads >= unpopular || !hasInstallScript(in.Meta) {
		return nil
	}
	return []Finding{{r.ID(), Medium, fmt.Sprintf("only %d downloads last week, and it runs install scripts", in.Downloads)}}
}

// SI-VUL-001: known advisories. Malicious-package entries block; ordinary
// vulnerabilities count one level lower than their advisory severity, since
// safe-install targets supply-chain attacks and `npm audit` covers the rest.
type vulnRule struct{}

func (vulnRule) ID() string { return "SI-VUL-001" }

func (r vulnRule) Check(in *Input) []Finding {
	var out []Finding
	for _, v := range in.Vulns {
		if v.Malicious() {
			out = append(out, Finding{r.ID(), Block, fmt.Sprintf("known malicious package (%s)", v.ID)})
			continue
		}
		sev := Low
		switch v.Severity {
		case "CRITICAL":
			sev = High
		case "HIGH":
			sev = Medium
		}
		msg := v.ID
		if v.Summary != "" {
			msg += ": " + v.Summary
		}
		if v.Severity != "" {
			msg += " (" + strings.ToLower(v.Severity) + ")"
		}
		out = append(out, Finding{r.ID(), sev, msg})
	}
	return out
}

// SI-POL-001: blocked by the organization's (or project's) policy.
type blockRule struct{}

func (blockRule) ID() string { return "SI-POL-001" }

func (r blockRule) Check(in *Input) []Finding {
	if in.Config.Blocked != nil && in.Config.Blocked(in.Package.Name) {
		return []Finding{{r.ID(), Block, "blocked by policy (blockPackages)"}}
	}
	return nil
}

// npmOnly scopes a rule whose data only npm provides.
type npmOnly struct{}

func (npmOnly) Ecosystems() []ecosystem.Ecosystem { return []ecosystem.Ecosystem{ecosystem.NPM} }
