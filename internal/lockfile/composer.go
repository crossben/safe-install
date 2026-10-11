package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crossben/safe-install/internal/ecosystem"
)

type composerPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Type    string            `json:"type"`
	Require map[string]string `json:"require"`
	Dist    *struct {
		Type      string `json:"type"`
		URL       string `json:"url"`
		Reference string `json:"reference"`
		Shasum    string `json:"shasum"`
	} `json:"dist"`
	Source *struct {
		Type      string `json:"type"`
		URL       string `json:"url"`
		Reference string `json:"reference"`
	} `json:"source"`
}

// parseComposer reads composer.lock. Direct dependencies come from
// composer.json (require / require-dev); platform requirements (php, ext-*,
// lib-*, composer-*-api) are not packages.
func parseComposer(data []byte, dir string) (*Graph, error) {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("composer.lock: %w", err)
	}
	b := newBuilder(Composer)
	ids := map[string]string{}
	add := func(p composerPackage) {
		name := ecosystem.Normalize(ecosystem.Packagist, p.Name)
		if name == "" || p.Version == "" {
			return
		}
		resolved, ref, shasum := "", "", ""
		switch {
		case p.Dist != nil && p.Dist.Type == "path":
			resolved = "path:" + p.Dist.URL // a local package: not from a registry
		case p.Dist != nil && p.Dist.URL != "":
			resolved, ref, shasum = p.Dist.URL, p.Dist.Reference, p.Dist.Shasum
		case p.Source != nil:
			resolved, ref = p.Source.Type+":"+p.Source.URL, p.Source.Reference // VCS only
		}
		id := b.add(name, p.Version, resolved, "")
		pkg := b.g.Packages[id]
		pkg.Ref, pkg.Plugin = ref, p.Type == "composer-plugin"
		if shasum != "" {
			pkg.Files = append(pkg.Files, File{URL: resolved, Hash: "sha1:" + strings.ToLower(shasum)})
		}
		ids[name] = id
	}
	for _, p := range lock.Packages {
		add(p)
	}
	for _, p := range lock.PackagesDev {
		add(p)
	}
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		from := ids[ecosystem.Normalize(ecosystem.Packagist, p.Name)]
		for dep := range p.Require {
			b.edge(from, ids[ecosystem.Normalize(ecosystem.Packagist, dep)])
		}
	}
	prod, dev := composerDirect(dir)
	for _, name := range prod {
		b.root(ids[name], false)
	}
	for _, name := range dev {
		b.root(ids[name], true)
	}
	g := b.finish()
	inDev := map[string]bool{}
	for _, p := range lock.PackagesDev {
		inDev[ids[ecosystem.Normalize(ecosystem.Packagist, p.Name)]] = true
	}
	for id, p := range g.Packages {
		p.Ecosystem = ecosystem.Packagist
		p.Dev = inDev[id] // Composer itself splits packages and packages-dev
	}
	return g, nil
}

func composerDirect(dir string) (prod, dev []string) {
	data, err := os.ReadFile(filepath.Join(dir, "composer.json")) // #nosec G304 -- the project's manifest
	if err != nil {
		return nil, nil
	}
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return nil, nil
	}
	pick := func(m map[string]string) []string {
		var out []string
		for name := range m {
			if IsComposerPlatform(name) {
				continue
			}
			out = append(out, ecosystem.Normalize(ecosystem.Packagist, name))
		}
		return out
	}
	return pick(manifest.Require), pick(manifest.RequireDev)
}

// IsComposerPlatform reports whether a requirement is the platform (PHP, an
// extension, a library or Composer's own API), not a package.
func IsComposerPlatform(name string) bool {
	n := strings.ToLower(name)
	return n == "php" || n == "php-64bit" || n == "hhvm" || n == "composer" ||
		strings.HasPrefix(n, "ext-") || strings.HasPrefix(n, "lib-") ||
		n == "composer-plugin-api" || n == "composer-runtime-api"
}
