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

// Approval lets one package run its install scripts as long as they hash
// to Hash (the scripts and the files they run).
type Approval struct {
	Version string `json:"version"` // version that was reviewed (informational)
	Hash    string `json:"hash"`
	At      string `json:"at,omitempty"` // date approved
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
