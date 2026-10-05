package lockfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Load errors.
var (
	ErrNoLockfile         = errors.New("no lockfile found; run your package manager once to create one")
	ErrBinaryLockfile     = errors.New("bun.lockb is binary; convert it with `bun install --save-text-lockfile`")
	ErrUnsupportedVersion = errors.New("unsupported lockfile version")
)

// Lockfile names, checked in this order.
var names = []string{
	"npm-shrinkwrap.json",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"bun.lock",
	"bun.lockb",
}

// Find returns the path of the lockfile in dir (the first one found, in the order above).
func Find(dir string) (string, error) {
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", ErrNoLockfile
}

// Load parses the lockfile in dir.
func Load(dir string) (*Graph, error) {
	path, err := Find(dir)
	if err != nil {
		return nil, err
	}
	g, err := LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return g, nil
}

// LoadFile parses one lockfile; its directory must hold the project's package.json.
func LoadFile(path string) (*Graph, error) {
	if filepath.Base(path) == "bun.lockb" {
		return nil, ErrBinaryLockfile
	}
	data, err := os.ReadFile(path) // #nosec G304 -- reading the project's lockfile is the point
	if err != nil {
		return nil, err
	}
	return Parse(filepath.Base(path), data, filepath.Dir(path))
}

// Parse parses lockfile contents. name is the lockfile's file name; dir holds
// the project's package.json (and workspaces), read for Yarn lockfiles.
func Parse(name string, data []byte, dir string) (*Graph, error) {
	switch name {
	case "bun.lockb":
		return nil, ErrBinaryLockfile
	case "npm-shrinkwrap.json", "package-lock.json":
		return parseNPM(data)
	case "pnpm-lock.yaml":
		return parsePNPM(data)
	case "bun.lock":
		return parseBun(data)
	case "yarn.lock":
		if bytes.Contains(data, []byte("\n__metadata:")) {
			return parseBerry(data, dir)
		}
		// Yarn v1 does not record workspaces; read every member's manifest.
		ms, err := readWorkspaceManifests(dir)
		if err != nil {
			return nil, err
		}
		return parseYarnV1(bytes.NewReader(data), ms)
	}
	return nil, fmt.Errorf("not a known lockfile: %s", name)
}

// Changed returns the packages of cur that are not in base (new, or a new
// version): the subgraph worth reviewing in a change. A nil base means
// everything is new. Removed packages are not included.
func Changed(base, cur *Graph) *Graph {
	if base == nil {
		return cur
	}
	out := &Graph{Format: cur.Format, Packages: map[string]*Package{}}
	for id, p := range cur.Packages {
		if _, ok := base.Packages[id]; !ok {
			out.Packages[id] = p
		}
	}
	return out
}

// manifest is the part of package.json that declares dependencies.
type manifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"` // ["glob"] or {"packages": ["glob"]}
}

func readManifest(dir string) (manifest, error) {
	var m manifest
	data, err := os.ReadFile(filepath.Join(dir, "package.json")) // #nosec G304 -- project manifest
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("package.json: %w", err)
	}
	return m, nil
}

// readWorkspaceManifests returns the manifest in dir and those of its workspaces.
func readWorkspaceManifests(dir string) ([]manifest, error) {
	root, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	var globs []string
	if len(root.Workspaces) > 0 && json.Unmarshal(root.Workspaces, &globs) != nil {
		var obj struct {
			Packages []string `json:"packages"`
		}
		if err := json.Unmarshal(root.Workspaces, &obj); err != nil {
			return nil, fmt.Errorf("package.json workspaces: %w", err)
		}
		globs = obj.Packages
	}
	out := []manifest{root}
	for _, g := range globs {
		matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(g)))
		if err != nil {
			return nil, fmt.Errorf("workspace pattern %q: %w", g, err)
		}
		for _, m := range matches {
			if _, err := os.Stat(filepath.Join(m, "package.json")); err != nil {
				continue
			}
			wm, err := readManifest(m)
			if err != nil {
				return nil, err
			}
			out = append(out, wm)
		}
	}
	return out, nil
}

// roots calls fn for every declared dependency, dev ones flagged.
func (m manifest) roots(fn func(name, spec string, dev bool)) {
	for n, s := range m.Dependencies {
		fn(n, s, false)
	}
	for n, s := range m.OptionalDependencies {
		fn(n, s, false)
	}
	for n, s := range m.DevDependencies {
		fn(n, s, true)
	}
}
