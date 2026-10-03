package lockfile

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

type pnpmLock struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	Packages        map[string]pnpmPackage  `yaml:"packages"`
	Snapshots       map[string]pnpmSnapshot `yaml:"snapshots"`

	// v6 single-project lockfiles keep the root importer at the top level.
	Dependencies         map[string]pnpmDep `yaml:"dependencies"`
	OptionalDependencies map[string]pnpmDep `yaml:"optionalDependencies"`
	DevDependencies      map[string]pnpmDep `yaml:"devDependencies"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmDep `yaml:"dependencies"`
	OptionalDependencies map[string]pnpmDep `yaml:"optionalDependencies"`
	DevDependencies      map[string]pnpmDep `yaml:"devDependencies"`
}

type pnpmDep struct {
	Version string `yaml:"version"`
}

type pnpmPackage struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
	} `yaml:"resolution"`
	PeerDependencies map[string]string `yaml:"peerDependencies"`
	// v6 keeps dependencies on the package (v9 moved them to snapshots).
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

func parsePNPM(data []byte) (*Graph, error) {
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	major, _ := strconv.ParseFloat(fmt.Sprint(lock.LockfileVersion), 64)
	var f Format
	switch {
	case major >= 9 && major < 10:
		f = PNPMv9
	case major >= 6 && major < 7:
		f = PNPMv6
	default:
		return nil, fmt.Errorf("%w: pnpm lockfileVersion %v (supported: 6.x, 9.x)", ErrUnsupportedVersion, lock.LockfileVersion)
	}

	b := newBuilder(f)
	ids := map[string]string{}              // normalized package key -> ID
	peers := map[string]map[string]string{} // normalized package key -> peer deps
	for key, p := range lock.Packages {
		k := pnpmKey(key)
		peers[k] = p.PeerDependencies
		name, version := splitID(k)
		if p.Name != "" {
			name, version = p.Name, p.Version
		}
		ids[k] = b.add(name, version, p.Resolution.Tarball, p.Resolution.Integrity)
	}

	resolve := func(name, ref string) string {
		ref = stripPeers(ref)
		if strings.HasPrefix(ref, "link:") {
			return ""
		}
		if id, ok := ids[name+"@"+ref]; ok {
			return id
		}
		return ids[pnpmKey(ref)] // alias or v6 "/name@version" reference
	}

	// pnpm lists resolved peers among dependencies; peers are not edges.
	edges := func(from string, s pnpmSnapshot) {
		for n, ref := range mergeDeps(s.Dependencies, s.OptionalDependencies) {
			if _, isPeer := peers[from][n]; isPeer {
				continue
			}
			b.edge(ids[from], resolve(n, ref))
		}
	}
	if f == PNPMv9 {
		for key, s := range lock.Snapshots {
			edges(pnpmKey(key), s)
		}
	} else {
		for key, p := range lock.Packages {
			edges(pnpmKey(key), pnpmSnapshot{p.Dependencies, p.OptionalDependencies})
		}
	}

	importers := lock.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": {lock.Dependencies, lock.OptionalDependencies, lock.DevDependencies}}
	}
	for _, imp := range importers {
		for n, d := range imp.Dependencies {
			b.root(resolve(n, d.Version), false)
		}
		for n, d := range imp.OptionalDependencies {
			b.root(resolve(n, d.Version), false)
		}
		for n, d := range imp.DevDependencies {
			b.root(resolve(n, d.Version), true)
		}
	}
	return b.finish(), nil
}

// pnpmKey normalizes a package key: no v6 leading slash, no peer suffix.
func pnpmKey(k string) string {
	return stripPeers(strings.TrimPrefix(k, "/"))
}

func stripPeers(s string) string {
	if i := strings.IndexByte(s, '('); i > 0 {
		return s[:i]
	}
	return s
}
