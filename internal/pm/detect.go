// Package pm detects the project's package manager and drives it.
package pm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crossben/safe-install/internal/ecosystem"
)

// Kind identifies a package manager.
type Kind string

// Supported package managers.
const (
	NPM  Kind = "npm"
	PNPM Kind = "pnpm"
	Yarn Kind = "yarn"
	Bun  Kind = "bun"

	// Python and PHP: detected, not yet supported (see plan-python-php.md).
	UV       Kind = "uv"
	Pip      Kind = "pip"
	Poetry   Kind = "poetry"
	Pipenv   Kind = "pipenv"
	Composer Kind = "composer"
)

// Ecosystem is where k's packages come from.
func (k Kind) Ecosystem() ecosystem.Ecosystem {
	switch k {
	case UV, Pip, Poetry, Pipenv:
		return ecosystem.PyPI
	case Composer:
		return ecosystem.Packagist
	}
	return ecosystem.NPM
}

// Detection errors.
var (
	ErrNoPackageJSON = errors.New("no package.json in this directory")
	ErrAmbiguous     = errors.New("lockfiles from several package managers found; pick one with --pm")
	ErrUnknownPM     = errors.New("unknown package manager")
	// ErrNotSupported: a Python or PHP project, recognized but not handled yet.
	ErrNotSupported = errors.New("not supported yet")
)

// Detection is the package manager found for a project and what decided it.
type Detection struct {
	Kind   Kind
	Source string // lockfile name, "packageManager field", "--pm flag" or "default"
}

// Ecosystem is where the detected project's packages come from.
func (d Detection) Ecosystem() ecosystem.Ecosystem { return d.Kind.Ecosystem() }

// Supported returns ErrNotSupported (with what was found) for a project whose
// ecosystem safe-install cannot handle yet.
func (d Detection) Supported() error {
	if d.Ecosystem() == ecosystem.NPM {
		return nil
	}
	return fmt.Errorf("%s project (%s, %s): %w; safe-install handles npm, pnpm, Yarn and bun projects today, Python and PHP support is coming",
		d.Ecosystem().Label(), d.Kind, d.Source, ErrNotSupported)
}

// Other ecosystems' project files, in priority order within each ecosystem.
var otherMarkers = []struct {
	name string
	kind Kind
}{
	{"uv.lock", UV},
	{"poetry.lock", Poetry},
	{"Pipfile.lock", Pipenv},
	{"requirements.txt", Pip},
	{"pyproject.toml", UV},
	{"composer.lock", Composer},
	{"composer.json", Composer},
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
	var overridden *Kind
	if override != "" {
		k, err := parseKind(override)
		if err != nil {
			return Detection{}, err
		}
		overridden = &k
	}
	if overridden != nil && overridden.Ecosystem() != ecosystem.NPM {
		return Detection{Kind: *overridden, Source: "--pm flag"}, nil
	}

	data, err := os.ReadFile(filepath.Join(dir, "package.json")) // #nosec G304 -- reading the project manifest is the point
	if errors.Is(err, os.ErrNotExist) {
		if overridden == nil {
			if d, ok, err := detectOther(dir); ok || err != nil {
				return d, err
			}
		}
		return Detection{}, ErrNoPackageJSON
	}
	if err != nil {
		return Detection{}, err
	}

	if overridden != nil {
		return Detection{Kind: *overridden, Source: "--pm flag"}, nil
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

// detectOther looks for a Python or PHP project (no package.json). Files of
// two ecosystems at once are ambiguous: --pm picks one.
func detectOther(dir string) (Detection, bool, error) {
	found := map[ecosystem.Ecosystem]Detection{}
	var order []ecosystem.Ecosystem
	for _, m := range otherMarkers {
		if _, err := os.Stat(filepath.Join(dir, m.name)); err != nil {
			continue
		}
		e := m.kind.Ecosystem()
		if _, seen := found[e]; !seen {
			found[e] = Detection{Kind: m.kind, Source: m.name}
			order = append(order, e)
		}
	}
	switch len(order) {
	case 0:
		return Detection{}, false, nil
	case 1:
		return found[order[0]], true, nil
	}
	return Detection{}, true, fmt.Errorf("%w (%s and %s)", ErrAmbiguous, found[order[0]].Source, found[order[1]].Source)
}

func parseKind(s string) (Kind, error) {
	switch k := Kind(strings.ToLower(strings.TrimSpace(s))); k {
	case NPM, PNPM, Yarn, Bun, UV, Pip, Poetry, Pipenv, Composer:
		return k, nil
	}
	return "", fmt.Errorf("%w %q (supported: npm, pnpm, yarn, bun)", ErrUnknownPM, s)
}
