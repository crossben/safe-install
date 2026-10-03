// Package pm detects the project's package manager and drives it.
package pm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Kind identifies a package manager.
type Kind string

// Supported package managers.
const (
	NPM  Kind = "npm"
	PNPM Kind = "pnpm"
	Yarn Kind = "yarn"
	Bun  Kind = "bun"
)

// Detection errors.
var (
	ErrNoPackageJSON = errors.New("no package.json in this directory")
	ErrAmbiguous     = errors.New("lockfiles from several package managers found; pick one with --pm")
	ErrUnknownPM     = errors.New("unknown package manager")
)

// Detection is the package manager found for a project and what decided it.
type Detection struct {
	Kind   Kind
	Source string // lockfile name, "packageManager field", "--pm flag" or "default"
}

// lockfiles in priority order within one package manager.
var lockfiles = []struct {
	name string
	kind Kind
}{
	{"npm-shrinkwrap.json", NPM},
	{"package-lock.json", NPM},
	{"pnpm-lock.yaml", PNPM},
	{"yarn.lock", Yarn},
	{"bun.lock", Bun},
	{"bun.lockb", Bun},
}

// Detect picks the package manager for dir: the --pm override, then the
// lockfile, then package.json's packageManager field, then npm.
func Detect(dir, override string) (Detection, error) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json")) // #nosec G304 -- reading the project manifest is the point
	if errors.Is(err, os.ErrNotExist) {
		return Detection{}, ErrNoPackageJSON
	}
	if err != nil {
		return Detection{}, err
	}

	if override != "" {
		k, err := parseKind(override)
		if err != nil {
			return Detection{}, err
		}
		return Detection{Kind: k, Source: "--pm flag"}, nil
	}

	var found *Detection
	for _, lf := range lockfiles {
		if _, err := os.Stat(filepath.Join(dir, lf.name)); err != nil {
			continue
		}
		if found == nil {
			found = &Detection{Kind: lf.kind, Source: lf.name}
		} else if found.Kind != lf.kind {
			return Detection{}, fmt.Errorf("%w (%s and %s)", ErrAmbiguous, found.Source, lf.name)
		}
	}
	if found != nil {
		return *found, nil
	}

	var pkg struct {
		PackageManager string `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return Detection{}, fmt.Errorf("reading package.json: %w", err)
	}
	if pkg.PackageManager != "" {
		name, _, _ := strings.Cut(pkg.PackageManager, "@")
		k, err := parseKind(name)
		if err != nil {
			return Detection{}, err
		}
		return Detection{Kind: k, Source: "packageManager field"}, nil
	}

	return Detection{Kind: NPM, Source: "default"}, nil
}

func parseKind(s string) (Kind, error) {
	switch k := Kind(strings.ToLower(strings.TrimSpace(s))); k {
	case NPM, PNPM, Yarn, Bun:
		return k, nil
	}
	return "", fmt.Errorf("%w %q (supported: npm, pnpm, yarn, bun)", ErrUnknownPM, s)
}
