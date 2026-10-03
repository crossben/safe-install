package lockfile

import (
	"encoding/json"
	"fmt"
	"strings"
)

type npmLock struct {
	LockfileVersion int                 `json:"lockfileVersion"`
	Packages        map[string]npmEntry `json:"packages"`
}

type npmEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

const nodeModules = "node_modules/"

func parseNPM(data []byte) (*Graph, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	if lock.LockfileVersion < 2 || lock.Packages == nil {
		return nil, fmt.Errorf("%w: lockfileVersion %d (npm 7+ writes v2/v3; run `npm install` to upgrade)",
			ErrUnsupportedVersion, lock.LockfileVersion)
	}

	b := newBuilder(NPMv3)
	ids := map[string]string{} // install path -> ID
	for path, e := range lock.Packages {
		if !isInstalled(path) || e.Link {
			continue
		}
		name := e.Name
		if name == "" {
			name = path[strings.LastIndex(path, nodeModules)+len(nodeModules):]
		}
		ids[path] = b.add(name, e.Version, e.Resolved, e.Integrity)
	}

	// resolve finds the package Node would load for dep from path.
	resolve := func(from, dep string) string {
		for base := from; ; {
			cand := nodeModules + dep
			if base != "" {
				cand = base + "/" + cand
			}
			if e, ok := lock.Packages[cand]; ok {
				if e.Link {
					return "" // local workspace package
				}
				return ids[cand]
			}
			if base == "" {
				return ""
			}
			if i := strings.LastIndex(base, nodeModules); i >= 0 {
				base = strings.TrimSuffix(base[:i], "/")
			} else {
				base = ""
			}
		}
	}

	for path, e := range lock.Packages {
		if e.Link {
			continue
		}
		deps := mergeDeps(e.Dependencies, e.OptionalDependencies)
		if !isInstalled(path) { // the project or a workspace
			for dep := range deps {
				b.root(resolve(path, dep), false)
			}
			for dep := range e.DevDependencies {
				b.root(resolve(path, dep), true)
			}
			continue
		}
		for dep := range deps {
			b.edge(ids[path], resolve(path, dep))
		}
	}
	return b.finish(), nil
}

// isInstalled reports whether a package-lock path is an installed package
// (as opposed to the project root or a workspace directory).
func isInstalled(path string) bool {
	return strings.HasPrefix(path, nodeModules) || strings.Contains(path, "/"+nodeModules)
}

func mergeDeps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
