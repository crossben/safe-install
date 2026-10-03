package lockfile

import (
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

type berryEntry struct {
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	Dependencies map[string]string `yaml:"dependencies"`
}

// parseBerry reads a Yarn 2+ lockfile. Berry records neither tarball URLs
// nor SRI hashes (its checksums are Yarn-specific), and does not mark dev
// dependencies, so workspace manifests are read for that.
func parseBerry(data []byte, dir string) (*Graph, error) {
	var raw map[string]yaml.RawMessage
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	entries := map[string]berryEntry{}
	for key, msg := range raw {
		if key == "__metadata" {
			continue
		}
		var e berryEntry
		if err := yaml.Unmarshal(msg, &e); err != nil {
			return nil, err
		}
		entries[key] = e
	}

	b := newBuilder(YarnBerry)
	byDesc := map[string]string{} // descriptor -> ID ("" for workspaces)
	workspaces := map[string]berryEntry{}
	for key, e := range entries {
		name, ref := splitID(e.Resolution)
		id := ""
		if path, ok := strings.CutPrefix(ref, "workspace:"); ok {
			workspaces[path] = e
		} else {
			id = b.add(name, e.Version, "", "")
		}
		for _, d := range strings.Split(key, ",") {
			byDesc[strings.TrimSpace(d)] = id
		}
	}
	for key, e := range entries {
		from := byDesc[strings.TrimSpace(strings.Split(key, ",")[0])]
		for n, rng := range e.Dependencies {
			b.edge(from, byDesc[n+"@"+rng])
		}
	}
	for path, e := range workspaces {
		m, err := readManifest(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		for n, rng := range e.Dependencies {
			_, dev := m.DevDependencies[n]
			b.root(byDesc[n+"@"+rng], dev)
		}
	}
	return b.finish(), nil
}
