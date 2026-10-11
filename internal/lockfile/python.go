package lockfile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/crossben/safe-install/internal/ecosystem"
)

// Python lockfiles. Names are normalized (PEP 503) so that the same package
// spelled differently is one node; IDs are "name@version" like npm's.

func pyName(n string) string { return ecosystem.Normalize(ecosystem.PyPI, n) }

// pyFinish tags every package as PyPI.
func pyFinish(b *builder) *Graph {
	g := b.finish()
	for _, p := range g.Packages {
		p.Ecosystem = ecosystem.PyPI
	}
	return g
}

func (b *builder) addFiles(id string, files ...File) {
	p := b.g.Packages[id]
	for _, f := range files {
		if f.Hash != "" {
			p.Files = append(p.Files, f)
		}
	}
}

// --- uv.lock ---------------------------------------------------------------

type uvDep struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type uvFile struct {
	URL  string `toml:"url"`
	Path string `toml:"path"`
	Hash string `toml:"hash"`
}

type uvPackage struct {
	Name         string             `toml:"name"`
	Version      string             `toml:"version"`
	Source       map[string]any     `toml:"source"`
	Dependencies []uvDep            `toml:"dependencies"`
	Optional     map[string][]uvDep `toml:"optional-dependencies"`
	Dev          map[string][]uvDep `toml:"dev-dependencies"`
	Sdist        *uvFile            `toml:"sdist"`
	Wheels       []uvFile           `toml:"wheels"`
}

func parseUV(data []byte) (*Graph, error) {
	var lock struct {
		Version int         `toml:"version"`
		Package []uvPackage `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("uv.lock: %w", err)
	}
	if lock.Version != 1 {
		return nil, fmt.Errorf("%w: uv.lock version %d", ErrUnsupportedVersion, lock.Version)
	}
	b := newBuilder(UV)
	ids := map[string][]string{} // normalized name -> IDs (uv may lock several versions)
	var members []uvPackage      // the project and its workspace members
	for _, p := range lock.Package {
		if isUVMember(p.Source) {
			members = append(members, p)
			continue
		}
		id := b.add(pyName(p.Name), p.Version, uvResolved(p.Source), "")
		ids[pyName(p.Name)] = append(ids[pyName(p.Name)], id)
		var files []uvFile
		if p.Sdist != nil {
			files = append(files, *p.Sdist)
		}
		for _, f := range append(files, p.Wheels...) {
			b.addFiles(id, File{Name: fileName(f.URL, f.Path), URL: f.URL, Hash: f.Hash})
		}
	}
	resolve := func(d uvDep) string {
		cands := ids[pyName(d.Name)]
		for _, id := range cands {
			if d.Version == "" || strings.HasSuffix(id, "@"+d.Version) {
				return id
			}
		}
		return ""
	}
	for _, p := range lock.Package {
		if isUVMember(p.Source) {
			continue
		}
		from := resolve(uvDep{Name: p.Name, Version: p.Version})
		for _, d := range allDeps(p) {
			b.edge(from, resolve(d))
		}
	}
	for _, m := range members {
		for _, d := range m.Dependencies {
			b.root(resolve(d), false)
		}
		for _, group := range m.Optional {
			for _, d := range group {
				b.root(resolve(d), false)
			}
		}
		for _, group := range m.Dev {
			for _, d := range group {
				b.root(resolve(d), true)
			}
		}
	}
	return pyFinish(b), nil
}

func allDeps(p uvPackage) []uvDep {
	out := append([]uvDep{}, p.Dependencies...)
	for _, g := range p.Optional {
		out = append(out, g...)
	}
	for _, g := range p.Dev {
		out = append(out, g...)
	}
	return out
}

// The project itself and workspace members are local, not packages to check.
func isUVMember(src map[string]any) bool {
	_, editable := src["editable"]
	_, virtual := src["virtual"]
	return editable || virtual
}

// uvResolved: the index for registry packages; a non-http marker otherwise
// (git, path, directory), so those are skipped like npm's non-registry ones.
func uvResolved(src map[string]any) string {
	if r, ok := src["registry"].(string); ok {
		return r
	}
	if u, ok := src["url"].(string); ok {
		return u
	}
	for _, k := range []string{"git", "path", "directory"} {
		if v, ok := src[k].(string); ok {
			return k + ":" + v
		}
	}
	return ""
}

func fileName(url, p string) string {
	if url != "" {
		return path.Base(strings.SplitN(url, "#", 2)[0])
	}
	return path.Base(filepath.ToSlash(p))
}

// --- poetry.lock -----------------------------------------------------------

func parsePoetry(data []byte, dir string) (*Graph, error) {
	var lock struct {
		Package []struct {
			Name         string         `toml:"name"`
			Version      string         `toml:"version"`
			Groups       []string       `toml:"groups"`
			Category     string         `toml:"category"` // Poetry 1.x
			Dependencies map[string]any `toml:"dependencies"`
			Files        []struct {
				File string `toml:"file"`
				Hash string `toml:"hash"`
			} `toml:"files"`
			Source *struct {
				Type string `toml:"type"`
				URL  string `toml:"url"`
			} `toml:"source"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("poetry.lock: %w", err)
	}
	b := newBuilder(Poetry)
	ids := map[string]string{}
	for _, p := range lock.Package {
		resolved := ""
		if p.Source != nil {
			switch p.Source.Type {
			case "legacy":
				resolved = p.Source.URL // another index
			default:
				resolved = p.Source.Type + ":" + p.Source.URL // git, url, file, directory
			}
		}
		id := b.add(pyName(p.Name), p.Version, resolved, "")
		ids[pyName(p.Name)] = id
		for _, f := range p.Files {
			b.addFiles(id, File{Name: f.File, Hash: f.Hash})
		}
	}
	for _, p := range lock.Package {
		for dep := range p.Dependencies {
			b.edge(ids[pyName(p.Name)], ids[pyName(dep)])
		}
	}
	prod, dev := pyprojectDirect(dir)
	for name := range prod {
		b.root(ids[name], false)
	}
	for name := range dev {
		b.root(ids[name], true)
	}
	return pyFinish(b), nil
}

// pyprojectDirect reads the direct dependencies from pyproject.toml: PEP 621
// [project] (dependencies, optional-dependencies) and Poetry's own tables
// (main dependencies, and groups other than main, which count as dev).
func pyprojectDirect(dir string) (prod, dev map[string]bool) {
	prod, dev = map[string]bool{}, map[string]bool{}
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")) // #nosec G304 -- the project's manifest
	if err != nil {
		return prod, dev
	}
	var pp struct {
		Project struct {
			Dependencies []string            `toml:"dependencies"`
			Optional     map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		DependencyGroups map[string][]any `toml:"dependency-groups"`
		Tool             struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &pp) != nil {
		return prod, dev
	}
	for _, req := range pp.Project.Dependencies {
		prod[requirementName(req)] = true
	}
	for _, reqs := range pp.Project.Optional {
		for _, req := range reqs {
			prod[requirementName(req)] = true
		}
	}
	for _, reqs := range pp.DependencyGroups {
		for _, req := range reqs {
			if s, ok := req.(string); ok {
				dev[requirementName(s)] = true
			}
		}
	}
	for name := range pp.Tool.Poetry.Dependencies {
		if name != "python" {
			prod[pyName(name)] = true
		}
	}
	for name := range pp.Tool.Poetry.DevDependencies {
		dev[pyName(name)] = true
	}
	for group, g := range pp.Tool.Poetry.Group {
		for name := range g.Dependencies {
			if group == "main" {
				prod[pyName(name)] = true
			} else {
				dev[pyName(name)] = true
			}
		}
	}
	delete(prod, "")
	delete(dev, "")
	return prod, dev
}

var reqName = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

// requirementName is the normalized name of a PEP 508 requirement
// ("requests[socks]>=2; python_version>'3'" -> "requests").
func requirementName(req string) string {
	m := reqName.FindStringSubmatch(req)
	if m == nil {
		return ""
	}
	return pyName(m[1])
}

// --- Pipfile.lock ----------------------------------------------------------

func parsePipenv(data []byte, dir string) (*Graph, error) {
	type entry struct {
		Version string   `json:"version"`
		Hashes  []string `json:"hashes"`
		Index   string   `json:"index"`
		Git     string   `json:"git"`
		Path    string   `json:"path"`
		File    string   `json:"file"`
	}
	var lock struct {
		Meta struct {
			Sources []struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"sources"`
		} `json:"_meta"`
		Default map[string]entry `json:"default"`
		Develop map[string]entry `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing Pipfile.lock: %w", err)
	}
	indexes := map[string]string{}
	for _, s := range lock.Meta.Sources {
		indexes[s.Name] = s.URL
	}
	prod, dev := pipfileDirect(dir)
	b := newBuilder(Pipenv)
	add := func(name string, e entry) string {
		resolved := indexes[e.Index]
		switch {
		case e.Git != "":
			resolved = "git:" + e.Git
		case e.Path != "":
			resolved = "path:" + e.Path
		case e.File != "":
			resolved = e.File
		}
		id := b.add(pyName(name), strings.TrimPrefix(e.Version, "=="), resolved, "")
		for _, h := range e.Hashes {
			b.addFiles(id, File{Hash: h})
		}
		return id
	}
	inDefault := map[string]bool{}
	for name, e := range lock.Default {
		id := add(name, e)
		inDefault[id] = true
		if prod == nil || prod[pyName(name)] {
			b.root(id, false)
		}
	}
	for name, e := range lock.Develop {
		id := add(name, e)
		if dev == nil || dev[pyName(name)] {
			b.root(id, true)
		}
	}
	g := pyFinish(b)
	// No dependency edges in Pipfile.lock: dev = only in the develop section.
	for id, p := range g.Packages {
		p.Dev = !inDefault[id]
	}
	return g, nil
}

// pipfileDirect reads [packages] and [dev-packages] from the Pipfile; nil
// maps mean "unknown" (no Pipfile): then every locked package counts as direct.
func pipfileDirect(dir string) (prod, dev map[string]bool) {
	data, err := os.ReadFile(filepath.Join(dir, "Pipfile")) // #nosec G304 -- the project's manifest
	if err != nil {
		return nil, nil
	}
	var pf struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if toml.Unmarshal(data, &pf) != nil {
		return nil, nil
	}
	prod, dev = map[string]bool{}, map[string]bool{}
	for n := range pf.Packages {
		prod[pyName(n)] = true
	}
	for n := range pf.DevPackages {
		dev[pyName(n)] = true
	}
	return prod, dev
}

// --- requirements.txt ------------------------------------------------------

var (
	pinned  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;\\]+)`)
	hashOpt = regexp.MustCompile(`--hash[=\s]+(\S+)`)
	viaLine = regexp.MustCompile(`^#\s+(?:via\s+)?(.+)$`)
)

// maxIncludes bounds -r recursion (and cycles).
const maxIncludes = 8

func parseRequirements(data []byte, dir string) (*Graph, error) {
	type req struct {
		name, version string
		hashes        []string
		via           []string // names, from pip-compile / uv export "# via" comments
		viaFile       bool     // "# via -r requirements.in": declared by the project
	}
	var reqs []*req
	seenFiles := map[string]bool{}
	var read func(data []byte, depth int) error
	read = func(data []byte, depth int) error {
		var cur *req
		inVia := false
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		var logical string
		for sc.Scan() {
			line := sc.Text()
			if strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
				logical += strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\") + " "
				continue
			}
			line, logical = logical+line, ""
			trimmed := strings.TrimSpace(line)
			switch {
			case trimmed == "":
				inVia = false
			case strings.HasPrefix(trimmed, "#"):
				m := viaLine.FindStringSubmatch(trimmed)
				if cur == nil || m == nil {
					continue
				}
				text := strings.TrimSpace(m[1])
				if strings.HasPrefix(trimmed[1:], "   ") || strings.Contains(trimmed, "via") || inVia {
					inVia = true
					for _, part := range strings.Split(text, ",") {
						part = strings.TrimSpace(strings.TrimPrefix(part, "via"))
						switch {
						case strings.HasPrefix(part, "-r") || strings.HasPrefix(part, "-c") || part == "":
							if part != "" {
								cur.viaFile = true
							}
						default:
							cur.via = append(cur.via, requirementName(part))
						}
					}
				}
			case strings.HasPrefix(trimmed, "-r ") || strings.HasPrefix(trimmed, "--requirement"):
				f := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "--requirement"), "-r"))
				f = strings.TrimSpace(strings.TrimPrefix(f, "="))
				if depth >= maxIncludes {
					return fmt.Errorf("requirements: -r nested more than %d deep", maxIncludes)
				}
				// Only files inside the project are read.
				p := filepath.Join(dir, filepath.FromSlash(f))
				if rel, err := filepath.Rel(dir, p); err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(f) {
					return fmt.Errorf("requirements: %q is outside the project", f)
				}
				if seenFiles[p] {
					continue
				}
				seenFiles[p] = true
				inc, err := os.ReadFile(p) // #nosec G304 G703 -- inside the project, checked above
				if err != nil {
					return fmt.Errorf("requirements: %w", err)
				}
				if err := read(inc, depth+1); err != nil {
					return err
				}
			case strings.HasPrefix(trimmed, "-"):
				// -e ., --index-url, -c …: not a pinned package
				cur, inVia = nil, false
			default:
				inVia = false
				m := pinned.FindStringSubmatch(trimmed)
				if m == nil {
					cur = &req{name: requirementName(trimmed)} // unpinned: listed, version unknown
				} else {
					cur = &req{name: pyName(m[1]), version: m[2]}
				}
				for _, h := range hashOpt.FindAllStringSubmatch(trimmed, -1) {
					cur.hashes = append(cur.hashes, h[1])
				}
				if cur.name != "" {
					reqs = append(reqs, cur)
				} else {
					cur = nil
				}
			}
		}
		return sc.Err()
	}
	if err := read(data, 0); err != nil {
		return nil, err
	}

	b := newBuilder(Requirements)
	ids := map[string]string{}
	for _, r := range reqs {
		id := b.add(r.name, r.version, "", "")
		ids[r.name] = id
		for _, h := range r.hashes {
			b.addFiles(id, File{Hash: h})
		}
	}
	for _, r := range reqs {
		declared := len(r.via) == 0 || r.viaFile
		for _, parent := range r.via {
			if pid, locked := ids[parent]; locked {
				b.edge(pid, ids[r.name])
			} else {
				declared = true // "via <the project itself>" (uv export)
			}
		}
		// Declared by the project: no "# via" at all (a hand-written file),
		// "via -r …" (pip-compile), or via something that is not a locked
		// package, i.e. the project (uv export writes "# via <project>").
		if declared {
			b.root(ids[r.name], false)
		}
	}
	return pyFinish(b), nil
}
