// Package ecosystem names the package ecosystems safe-install knows: where
// packages come from (registry, advisory database, naming rules), as opposed
// to the package manager that installs them.
package ecosystem

import (
	"regexp"
	"strings"
)

// Ecosystem is a package registry and its conventions.
type Ecosystem string

// Supported ecosystems.
const (
	NPM       Ecosystem = "npm"       // npm, pnpm, Yarn, bun
	PyPI      Ecosystem = "pypi"      // uv, pip, Poetry, Pipenv
	Packagist Ecosystem = "packagist" // Composer
)

// OSVName is the ecosystem's name in the OSV database. The empty ecosystem is
// npm, so data recorded before ecosystems existed keeps its meaning.
func (e Ecosystem) OSVName() string {
	switch e {
	case PyPI:
		return "PyPI"
	case Packagist:
		return "Packagist"
	}
	return "npm"
}

// Or returns e, or NPM when e is empty.
func (e Ecosystem) Or() Ecosystem {
	if e == "" {
		return NPM
	}
	return e
}

// Label is the ecosystem as people name it.
func (e Ecosystem) Label() string {
	switch e {
	case PyPI:
		return "Python"
	case Packagist:
		return "PHP"
	}
	return "JavaScript"
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// Normalize returns the canonical form of a package name: PyPI names are
// case-insensitive and treat runs of "-", "_" and "." alike (PEP 503);
// Packagist names are lowercase; npm names are kept as they are.
func Normalize(e Ecosystem, name string) string {
	switch e {
	case PyPI:
		return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
	case Packagist:
		return strings.ToLower(name)
	}
	return name
}
