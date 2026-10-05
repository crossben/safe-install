// Package scripts finds the install scripts dependencies want to run and
// flags risky ones.
package scripts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
)

// Lifecycle stages run on install, in order.
var Lifecycle = []string{"preinstall", "install", "postinstall"}

// Candidate is a package that wants to run install scripts.
type Candidate struct {
	Package  *lockfile.Package
	Dir      string            // installed directory; "" when not unpacked (Plug'n'Play)
	Scripts  map[string]string // stage -> command, lifecycle stages only
	Implicit bool              // install is the implicit "node-gyp rebuild" (binding.gyp, no install script)

	Findings []analyze.Finding
	Level    analyze.Level
	State    State // approval status against the policy
}

// Stages returns the candidate's lifecycle stages in run order.
func (c *Candidate) Stages() []string {
	var out []string
	for _, s := range Lifecycle {
		if _, ok := c.Scripts[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Discover reads every installed package in dir/node_modules (including
// pnpm's .pnpm store) and returns those in g with lifecycle scripts. missing
// lists graph packages not found on disk (not installed for this platform,
// or not unpacked at all with Plug'n'Play).
func Discover(dir string, g *lockfile.Graph) (cands []*Candidate, missing []string) {
	installed := Installed(dir)

	for _, p := range g.Sorted() {
		pdir, ok := installed[p.ID]
		if !ok {
			missing = append(missing, p.ID)
			continue
		}
		if c := FromManifest(p, pdir); c != nil {
			cands = append(cands, c)
		}
	}
	return cands, missing
}

// Installed maps name@version to the directory of every package unpacked in
// dir: node_modules (including pnpm's .pnpm store) and Yarn berry's unplugged
// packages. Symlinks (workspaces, pnpm links) are not followed.
func Installed(dir string) map[string]string {
	installed := map[string]string{}
	indexNodeModules(filepath.Join(dir, "node_modules"), installed, 0)
	// Yarn berry unpacks packages with build scripts here, even with Plug'n'Play.
	unplugged, _ := filepath.Glob(filepath.Join(dir, ".yarn", "unplugged", "*", "node_modules"))
	for _, nm := range unplugged {
		indexNodeModules(nm, installed, 0)
	}
	return installed
}

// FromManifest builds a candidate from the package.json in pdir, or returns
// nil when the package has no install scripts.
func FromManifest(p *lockfile.Package, pdir string) *Candidate {
	m, err := readManifest(pdir)
	if err != nil {
		return nil
	}
	c := &Candidate{Package: p, Dir: pdir, Scripts: map[string]string{}}
	for _, s := range Lifecycle {
		if cmd := strings.TrimSpace(m.Scripts[s]); cmd != "" {
			c.Scripts[s] = cmd
		}
	}
	// npm (and the others) run node-gyp for native packages without install scripts.
	if c.Scripts["install"] == "" && c.Scripts["preinstall"] == "" {
		if _, err := os.Stat(filepath.Join(pdir, "binding.gyp")); err == nil {
			c.Scripts["install"] = "node-gyp rebuild"
			c.Implicit = true
		}
	}
	if len(c.Scripts) == 0 {
		return nil
	}
	return c
}

type manifest struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

func readManifest(dir string) (manifest, error) {
	var m manifest
	data, err := os.ReadFile(filepath.Join(dir, "package.json")) // #nosec G304 -- installed package manifest
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	return m, err
}

// indexNodeModules records name@version -> dir for every package under nm.
// Symlinks are not followed: pnpm's top-level links point into .pnpm, which
// is walked directly, and workspace links are local code.
func indexNodeModules(nm string, out map[string]string, depth int) {
	if depth > 32 {
		return
	}
	entries, err := os.ReadDir(nm)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(nm, name)
		switch {
		case !e.IsDir(): // includes symlinks
		case name == ".bin":
		case name == ".pnpm":
			store, _ := os.ReadDir(path)
			for _, s := range store {
				if s.IsDir() {
					indexNodeModules(filepath.Join(path, s.Name(), "node_modules"), out, depth+1)
				}
			}
		case strings.HasPrefix(name, "@"):
			scoped, _ := os.ReadDir(path)
			for _, s := range scoped {
				if s.IsDir() {
					indexPackage(filepath.Join(path, s.Name()), out, depth)
				}
			}
		case strings.HasPrefix(name, "."):
		default:
			indexPackage(path, out, depth)
		}
	}
}

func indexPackage(dir string, out map[string]string, depth int) {
	if m, err := readManifest(dir); err == nil && m.Name != "" {
		id := m.Name + "@" + m.Version
		if _, seen := out[id]; !seen {
			out[id] = dir
		}
	}
	indexNodeModules(filepath.Join(dir, "node_modules"), out, depth+1)
}

// Order sorts candidates so a package's dependencies build before it.
func Order(cands []*Candidate, g *lockfile.Graph) []*Candidate {
	byID := map[string]*Candidate{}
	for _, c := range cands {
		byID[c.Package.ID] = c
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Package.ID < cands[j].Package.ID })

	var out []*Candidate
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(id string)
	visit = func(id string) {
		if state[id] != 0 {
			return // done, or a cycle: break it here
		}
		state[id] = 1
		if p := g.Packages[id]; p != nil {
			for _, d := range p.Dependencies {
				visit(d)
			}
		}
		state[id] = 2
		if c := byID[id]; c != nil {
			out = append(out, c)
		}
	}
	for _, c := range cands {
		visit(c.Package.ID)
	}
	return out
}
