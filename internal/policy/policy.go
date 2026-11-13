// Package policy reads and writes safe-install policy files: the project's
// .safe-install.json and the user's global config.json.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FileName is the project policy file, meant to be committed.
const FileName = ".safe-install.json"

// File is the policy file format.
type File struct {
	MinReleaseAge        string                  `json:"minReleaseAge,omitempty"`        // e.g. "72h", "3d", "0"
	MinReleaseAgeExclude []string                `json:"minReleaseAgeExclude,omitempty"` // package name globs
	FailOn               string                  `json:"failOn,omitempty"`               // check threshold
	AllowScripts         map[string]Approval     `json:"allowScripts,omitempty"`         // by package name
	AcceptFindings       map[string][]Acceptance `json:"acceptFindings,omitempty"`       // by package name
	BlockPackages        []string                `json:"blockPackages,omitempty"`        // name globs never installed or run
	DisallowAccept       []string                `json:"disallowAccept,omitempty"`       // rule ID globs that may not be accepted ("*" forbids all); organization policy
	OrgPolicy            string                  `json:"orgPolicy,omitempty"`            // organization policy: path or https URL
}

// Trust modes for an approval.
const (
	TrustHash       = "hash"       // only scripts hashing to Hash (default)
	TrustProvenance = "provenance" // also any version built by Repository's CI (npm provenance)
)

// Approval lets packages run their install scripts. Its key in allowScripts
// is a package name or a glob ("@esbuild/*"; globs need TrustProvenance).
type Approval struct {
	Version    string `json:"version,omitempty"`    // version that was reviewed (informational)
	Hash       string `json:"hash,omitempty"`       // scripts and the files they run
	Trust      string `json:"trust,omitempty"`      // TrustHash (default) or TrustProvenance
	Repository string `json:"repository,omitempty"` // provenance source, for TrustProvenance
	Expires    string `json:"expires,omitempty"`    // last valid day, YYYY-MM-DD
	At         string `json:"at,omitempty"`         // date approved
}

// TrustMode returns the effective trust mode.
func (a Approval) TrustMode() string {
	if a.Trust == "" {
		return TrustHash
	}
	return a.Trust
}

// Expired reports whether the approval's last valid day is before now.
func (a Approval) Expired(now time.Time) bool {
	if a.Expires == "" {
		return false
	}
	last, err := time.Parse("2006-01-02", a.Expires)
	if err != nil {
		return true // unreadable: treat as expired rather than forever
	}
	return now.UTC().After(last.Add(24*time.Hour - time.Nanosecond))
}

func (a Approval) validate(name string) error {
	switch a.TrustMode() {
	case TrustHash:
		if strings.ContainsAny(name, "*?[") {
			return fmt.Errorf("%s: a glob approval needs trust %q (one hash cannot cover several packages)", name, TrustProvenance)
		}
	case TrustProvenance:
		if a.Repository == "" {
			return fmt.Errorf("%s: trust %q needs a repository", name, TrustProvenance)
		}
	default:
		return fmt.Errorf("%s: unknown trust %q (use %q or %q)", name, a.Trust, TrustHash, TrustProvenance)
	}
	return nil
}

// Acceptance records a finding that has been reviewed and judged harmless.
//
// A code-level acceptance (SI-CODE-*, SI-PTH-001) names a File
// and the Hash of that file's content in the installed package. A
// package-level one (registry metadata rules) has no File: it is pinned to
// the Integrity of the exact tarball and to the Evidence the finding reported
// when it was reviewed.
type Acceptance struct {
	Version   string `json:"version,omitempty"`   // version reviewed
	Rule      string `json:"rule"`                // SI-CODE-001, SI-REC-002, ...; required
	File      string `json:"file,omitempty"`      // path relative to the package (code findings)
	Hash      string `json:"hash,omitempty"`      // sha256:<hex> of that file's content (code findings)
	Integrity string `json:"integrity,omitempty"` // tarball integrity (package-level findings)
	Evidence  string `json:"evidence,omitempty"`  // what the finding reported (package-level findings)
	Reason    string `json:"reason"`              // required: why it is safe
	By        string `json:"by,omitempty"`        // who accepted it
	At        string `json:"at,omitempty"`        // date accepted (YYYY-MM-DD)
	Expires   string `json:"expires,omitempty"`   // last valid day (YYYY-MM-DD)
}

// Expired reports whether the acceptance's last valid day is before now.
func (a Acceptance) Expired(now time.Time) bool {
	if a.Expires == "" {
		return false
	}
	last, err := time.Parse("2006-01-02", a.Expires)
	if err != nil {
		return true // unreadable: treat as expired rather than forever
	}
	return now.UTC().After(last.Add(24*time.Hour - time.Nanosecond))
}

// resolveExpiry turns an expiry given as a date (YYYY-MM-DD) or a duration
// ("90d", "12h") into a date.
func resolveExpiry(s string, now time.Time) (string, error) {
	if s == "" {
		return "", nil
	}
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return s, nil
	}
	d, err := parseDuration(s)
	if err != nil {
		return "", fmt.Errorf("invalid expires %q (use a duration like 90d or a date YYYY-MM-DD)", s)
	}
	return now.UTC().Add(d).Format("2006-01-02"), nil
}

// Validate checks the required fields and converts a duration Expires
// ("90d") into a date. It has a pointer receiver so the conversion is kept.
func (a *Acceptance) Validate() error {
	if a.Rule == "" {
		return fmt.Errorf("rule required")
	}
	if a.Reason == "" {
		return fmt.Errorf("reason required")
	}
	exp, err := resolveExpiry(a.Expires, time.Now())
	if err != nil {
		return err
	}
	a.Expires = exp
	return nil
}

// parseDuration parses a duration string like "90d", "1h", "24h" etc.
func parseDuration(s string) (time.Duration, error) {
	// Check for "d" suffix (days)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		if n < 0 {
			return 0, fmt.Errorf("duration must be non-negative: %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	// Check for Go duration format (e.g., "90d" already handled, but also "24h", "1h")
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cannot parse duration %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration must be non-negative: %q", s)
	}
	return d, nil
}

// Lookup finds the approval for a package: its exact name first, then the
// most specific matching glob. key is the allowScripts entry that matched.
func (p *Policy) Lookup(name string) (a Approval, key string, ok bool) {
	if a, ok := p.AllowScripts[name]; ok {
		return a, name, true
	}
	for k, cand := range p.AllowScripts {
		if !strings.ContainsAny(k, "*?[") {
			continue
		}
		if m, _ := path.Match(k, name); m && (!ok || len(k) > len(key) || (len(k) == len(key) && k < key)) {
			a, key, ok = cand, k, true
		}
	}
	return a, key, ok
}

// FindAcceptances returns every recorded acceptance for the key (package,
// version, rule, file). A package-level key (file "") can hold several, one
// per piece of evidence.
func (p *Policy) FindAcceptances(pkg, ver, rule, file string) []Acceptance {
	var out []Acceptance
	for _, acc := range p.AcceptFindings[pkg] {
		if acc.Version == ver && acc.Rule == rule && acc.File == file {
			out = append(out, acc)
		}
	}
	return out
}

// FindAcceptance returns the recorded entry for the key, or false. The
// caller compares hash, integrity, evidence and expiry.
func (p *Policy) FindAcceptance(pkg, ver, rule, file string) (Acceptance, bool) {
	if accs := p.FindAcceptances(pkg, ver, rule, file); len(accs) > 0 {
		return accs[0], true
	}
	return Acceptance{}, false
}

// AcceptForbidden reports whether the organization forbids accepting
// findings of this rule (a disallowAccept glob matches).
func (p *Policy) AcceptForbidden(rule string) bool {
	for _, g := range p.DisallowAccept {
		if g == "*" {
			return true
		}
		if ok, _ := path.Match(g, rule); ok || g == rule {
			return true
		}
	}
	return false
}

// Policy is the effective policy: the organization policy, overlaid by the
// user's config and the project file, with the organization's minimums and
// blocks enforced.
type Policy struct {
	File
	ProjectPath string // where project approvals are written
	Org         string // organization policy source, if any
	OrgWarning  string // set when a cached organization policy was used
	blocks      []string
}

// GlobalPath returns the user-wide config file
// ($SAFE_INSTALL_CONFIG_DIR, else the OS config dir).
func GlobalPath() (string, error) {
	if dir := os.Getenv("SAFE_INSTALL_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "safe-install", "config.json"), nil
}

// Load reads the global config and the project file in dir; either may be missing.
func Load(dir string) (*Policy, error) {
	p := &Policy{File: File{AllowScripts: map[string]Approval{}, AcceptFindings: map[string][]Acceptance{}}, ProjectPath: filepath.Join(dir, FileName)}
	globalPath, err := GlobalPath()
	if err != nil {
		return nil, err
	}
	var files []*File // user, then project
	for _, path := range []string{globalPath, p.ProjectPath} {
		f, err := Read(path)
		if errors.Is(err, os.ErrNotExist) {
			files = append(files, nil)
			continue
		}
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}

	var org *File
	if src, trusted := orgSource(files[1], files[0]); src != "" {
		if org, p.OrgWarning, err = loadOrg(src, trusted); err != nil {
			return nil, err
		}
		p.Org = src
		p.overlay(org)
	}
	for _, f := range files {
		if f != nil {
			p.overlay(f)
		}
	}
	if org != nil {
		p.enforce(org)
	}
	return p, nil
}

func (p *Policy) overlay(f *File) {
	if f.MinReleaseAge != "" {
		p.MinReleaseAge = f.MinReleaseAge
	}
	if f.FailOn != "" {
		p.FailOn = f.FailOn
	}
	p.MinReleaseAgeExclude = append(p.MinReleaseAgeExclude, f.MinReleaseAgeExclude...)
	p.blocks = append(p.blocks, f.BlockPackages...)
	// Only ever added to: a project cannot lift what the organization forbids.
	p.DisallowAccept = append(p.DisallowAccept, f.DisallowAccept...)
	for name, a := range f.AllowScripts {
		p.AllowScripts[name] = a
	}
	for pkg, accs := range f.AcceptFindings {
		p.AcceptFindings[pkg] = append(p.AcceptFindings[pkg], accs...)
	}
}

// Excluded reports whether name matches a minReleaseAgeExclude glob.
func (p *Policy) Excluded(name string) bool {
	for _, g := range p.MinReleaseAgeExclude {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// Read parses one policy file.
func Read(path string) (*File, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- policy file path
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.AllowScripts == nil {
		f.AllowScripts = map[string]Approval{}
	}
	if f.AcceptFindings == nil {
		f.AcceptFindings = map[string][]Acceptance{}
	}
	return &f, nil
}

// Approve records an approval in the policy file at path, creating it if needed.
func Approve(path, name string, a Approval) error {
	if err := a.validate(name); err != nil {
		return err
	}
	return update(path, func(f *File) bool {
		if a.At == "" {
			a.At = time.Now().UTC().Format("2006-01-02")
		}
		f.AllowScripts[name] = a
		return true
	})
}

// Revoke removes name's approval; it reports whether there was one.
func Revoke(path, name string) (bool, error) {
	removed := false
	err := update(path, func(f *File) bool {
		_, removed = f.AllowScripts[name]
		delete(f.AllowScripts, name)
		return removed
	})
	return removed, err
}

// AcceptFinding records an acceptance in the policy file at path, creating
// it if needed. a.Expires may be a duration ("90d"); it is stored as a date.
// An existing entry with the same version, rule and file (and, for a
// package-level entry, the same evidence) is replaced.
func AcceptFinding(path, pkg string, a Acceptance) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.At == "" {
		a.At = time.Now().UTC().Format("2006-01-02")
	}
	return update(path, func(f *File) bool {
		accs := f.AcceptFindings[pkg]
		for i, e := range accs {
			if e.Version == a.Version && e.Rule == a.Rule && e.File == a.File && (a.File != "" || e.Evidence == a.Evidence) {
				accs[i] = a
				return true
			}
		}
		f.AcceptFindings[pkg] = append(accs, a)
		return true
	})
}

// RevokeFinding removes the acceptances for package, version, rule and file
// (every evidence for a package-level one); it reports whether there was one.
func RevokeFinding(path, pkg, ver, rule, file string) (bool, error) {
	removed := false
	err := update(path, func(f *File) bool {
		var kept []Acceptance
		for _, acc := range f.AcceptFindings[pkg] {
			if acc.Version == ver && acc.Rule == rule && acc.File == file {
				removed = true
				continue
			}
			kept = append(kept, acc)
		}
		if !removed {
			return false
		}
		if len(kept) == 0 {
			delete(f.AcceptFindings, pkg)
		} else {
			f.AcceptFindings[pkg] = kept
		}
		return true
	})
	return removed, err
}

// PruneStale removes the acceptances whose package version is no longer
// present (per the lockfile); it reports how many it removed.
func PruneStale(path string, present func(pkg, ver string) bool) (int, error) {
	pruned := 0
	err := update(path, func(f *File) bool {
		for pkg, accs := range f.AcceptFindings {
			var kept []Acceptance
			for _, acc := range accs {
				if present(pkg, acc.Version) {
					kept = append(kept, acc)
				} else {
					pruned++
				}
			}
			if len(kept) == 0 {
				delete(f.AcceptFindings, pkg)
			} else {
				f.AcceptFindings[pkg] = kept
			}
		}
		return pruned > 0
	})
	return pruned, err
}

// PruneAcceptances removes all expired acceptances from a policy file.
// It reports the number of acceptances removed.
func PruneAcceptances(path string) (int, error) {
	pruned := 0
	now := time.Now()
	err := update(path, func(f *File) bool {
		changed := false
		for pkg, accs := range f.AcceptFindings {
			var kept []Acceptance
			for _, acc := range accs {
				if !acc.Expired(now) {
					kept = append(kept, acc)
				} else {
					changed = true
					pruned++
				}
			}
			if len(kept) == 0 {
				delete(f.AcceptFindings, pkg)
				changed = true
			} else if len(kept) < len(accs) {
				f.AcceptFindings[pkg] = kept
			}
		}
		return changed
	})
	return pruned, err
}

func update(path string, change func(*File) bool) error {
	f, err := Read(path)
	if errors.Is(err, os.ErrNotExist) {
		f, err = &File{AllowScripts: map[string]Approval{}, AcceptFindings: map[string][]Acceptance{}}, nil
	}
	if err != nil {
		return err
	}
	if !change(f) {
		return nil
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".safe-install-*.json")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(append(data, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { // #nosec G302 -- committed project file, not a secret
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
