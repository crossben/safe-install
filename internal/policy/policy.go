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
	"strings"
	"time"
)

// FileName is the project policy file, meant to be committed.
const FileName = ".safe-install.json"

// File is the policy file format.
type File struct {
	MinReleaseAge        string              `json:"minReleaseAge,omitempty"`        // e.g. "72h", "3d", "0"
	MinReleaseAgeExclude []string            `json:"minReleaseAgeExclude,omitempty"` // package name globs
	FailOn               string              `json:"failOn,omitempty"`               // check threshold
	AllowScripts         map[string]Approval `json:"allowScripts,omitempty"`         // by package name
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

// Policy is the effective policy: global config overlaid by the project file.
type Policy struct {
	File
	ProjectPath string // where project approvals are written
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
	p := &Policy{File: File{AllowScripts: map[string]Approval{}}, ProjectPath: filepath.Join(dir, FileName)}
	global, err := GlobalPath()
	if err != nil {
		return nil, err
	}
	for _, path := range []string{global, p.ProjectPath} {
		f, err := Read(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		p.overlay(f)
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
	for name, a := range f.AllowScripts {
		p.AllowScripts[name] = a
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

func update(path string, change func(*File) bool) error {
	f, err := Read(path)
	if errors.Is(err, os.ErrNotExist) {
		f, err = &File{AllowScripts: map[string]Approval{}}, nil
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
