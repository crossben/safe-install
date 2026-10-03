// Package lockfile parses JavaScript lockfiles into one dependency graph.
package lockfile

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Format identifies a lockfile format.
type Format string

// Supported formats.
const (
	NPMv3     Format = "npm"        // package-lock.json / npm-shrinkwrap.json, lockfileVersion 2 or 3
	PNPMv9    Format = "pnpm-v9"    // pnpm-lock.yaml, lockfileVersion 9
	PNPMv6    Format = "pnpm-v6"    // pnpm-lock.yaml, lockfileVersion 6
	YarnV1    Format = "yarn-v1"    // yarn.lock, classic
	YarnBerry Format = "yarn-berry" // yarn.lock, __metadata (Yarn 2+)
	Bun       Format = "bun"        // bun.lock (text)
)

// Package is one resolved name@version in the tree. Local workspace
// packages are not included; their dependencies are roots.
type Package struct {
	ID        string // name@version
	Name      string
	Version   string
	Resolved  string // tarball URL, when the lockfile records one
	Integrity string // SRI hash, when the lockfile records one
	Direct    bool   // declared by the project (or a workspace)
	Dev       bool   // reachable only through devDependencies

	Dependencies []string // IDs, sorted
}

// Graph is the full resolved dependency tree of a project.
type Graph struct {
	Format   Format
	Packages map[string]*Package // by ID
}

// Sorted returns the packages ordered by ID.
func (g *Graph) Sorted() []*Package {
	out := make([]*Package, 0, len(g.Packages))
	for _, p := range g.Packages {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// String renders the graph deterministically (used by golden tests).
func (g *Graph) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "format: %s\n", g.Format)
	for _, p := range g.Sorted() {
		b.WriteString(p.ID)
		if p.Direct {
			b.WriteString(" direct")
		}
		if p.Dev {
			b.WriteString(" dev")
		}
		b.WriteByte('\n')
		if p.Resolved != "" {
			fmt.Fprintf(&b, "  resolved %s\n", p.Resolved)
		}
		if p.Integrity != "" {
			fmt.Fprintf(&b, "  integrity %s\n", p.Integrity)
		}
		for _, d := range p.Dependencies {
			fmt.Fprintf(&b, "  -> %s\n", d)
		}
	}
	return b.String()
}

// shape is String without format-specific fields, to compare formats.
func (g *Graph) shape() string {
	var b strings.Builder
	for _, p := range g.Sorted() {
		fmt.Fprintf(&b, "%s direct=%v dev=%v deps=%v\n", p.ID, p.Direct, p.Dev, p.Dependencies)
	}
	return b.String()
}

// builder collects packages, edges and roots; finish derives Direct and Dev
// the same way for every format.
type builder struct {
	g         *Graph
	prodRoots []string
	devRoots  []string
}

func newBuilder(f Format) *builder {
	return &builder{g: &Graph{Format: f, Packages: map[string]*Package{}}}
}

func (b *builder) add(name, version, resolved, integrity string) string {
	id := name + "@" + version
	p, ok := b.g.Packages[id]
	if !ok {
		p = &Package{ID: id, Name: name, Version: version}
		b.g.Packages[id] = p
	}
	if p.Resolved == "" {
		p.Resolved = resolved
	}
	if p.Integrity == "" {
		p.Integrity = integrity
	}
	return id
}

func (b *builder) edge(from, to string) {
	p := b.g.Packages[from]
	if p == nil || to == "" || slices.Contains(p.Dependencies, to) {
		return
	}
	p.Dependencies = append(p.Dependencies, to)
}

func (b *builder) root(id string, dev bool) {
	if id == "" {
		return
	}
	if dev {
		b.devRoots = append(b.devRoots, id)
	} else {
		b.prodRoots = append(b.prodRoots, id)
	}
}

func (b *builder) finish() *Graph {
	for _, p := range b.g.Packages {
		slices.Sort(p.Dependencies)
	}
	for _, id := range append(slices.Clone(b.prodRoots), b.devRoots...) {
		if p := b.g.Packages[id]; p != nil {
			p.Direct = true
		}
	}
	prod := b.reach(b.prodRoots)
	dev := b.reach(b.devRoots)
	for id, p := range b.g.Packages {
		p.Dev = dev[id] && !prod[id]
	}
	return b.g
}

func (b *builder) reach(roots []string) map[string]bool {
	seen := map[string]bool{}
	stack := slices.Clone(roots)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		p := b.g.Packages[id]
		if p == nil || seen[id] {
			continue
		}
		seen[id] = true
		stack = append(stack, p.Dependencies...)
	}
	return seen
}

// splitID splits "name@version", where name may be scoped ("@a/b@1.0.0").
func splitID(s string) (name, version string) {
	if len(s) == 0 {
		return "", ""
	}
	i := strings.IndexByte(s[1:], '@')
	if i < 0 {
		return s, ""
	}
	return s[:i+1], s[i+2:]
}
