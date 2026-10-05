package lockfile

import (
	"sort"
	"strings"
)

// Find returns the packages matching query: "name@version" exactly, or every
// version of "name". Sorted by ID.
func (g *Graph) Find(query string) []*Package {
	if name, version := splitID(query); version != "" {
		if p, ok := g.Packages[name+"@"+version]; ok {
			return []*Package{p}
		}
		return nil
	}
	var out []*Package
	for _, p := range g.Sorted() {
		if strings.EqualFold(p.Name, query) {
			out = append(out, p)
		}
	}
	return out
}

// Why returns the shortest dependency chains from a direct dependency of
// the project to id (each chain lists IDs, direct dependency first), at most
// limit of them in a stable order, and how many shortest chains exist.
func (g *Graph) Why(id string, limit int) (paths [][]string, total int) {
	if _, ok := g.Packages[id]; !ok {
		return nil, 0
	}
	// Breadth-first from every direct dependency; parents keeps every
	// predecessor on a shortest route.
	dist := map[string]int{}
	parents := map[string][]string{}
	var queue []string
	for _, p := range g.Sorted() {
		if p.Direct {
			dist[p.ID] = 0
			queue = append(queue, p.ID)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		p := g.Packages[cur]
		if p == nil {
			continue
		}
		for _, dep := range p.Dependencies {
			d, seen := dist[dep]
			switch {
			case !seen:
				dist[dep] = dist[cur] + 1
				parents[dep] = []string{cur}
				queue = append(queue, dep)
			case d == dist[cur]+1:
				parents[dep] = append(parents[dep], cur)
			}
		}
	}
	if _, ok := dist[id]; !ok {
		return nil, 0 // not reachable from the project (e.g. an extraneous entry)
	}

	// Count shortest chains (capped to stay cheap on dense graphs), then
	// enumerate up to limit of them.
	const countCap = 1_000_000
	counts := map[string]int{}
	var count func(n string) int
	count = func(n string) int {
		if c, ok := counts[n]; ok {
			return c
		}
		c := 0
		if dist[n] == 0 {
			c = 1
		} else {
			for _, par := range parents[n] {
				c = min(c+count(par), countCap)
			}
		}
		counts[n] = c
		return c
	}
	total = count(id)

	var walk func(n string, suffix []string)
	walk = func(n string, suffix []string) {
		if len(paths) >= limit {
			return
		}
		chain := append([]string{n}, suffix...)
		if dist[n] == 0 {
			paths = append(paths, chain)
			return
		}
		ps := append([]string(nil), parents[n]...)
		sort.Strings(ps)
		for _, par := range ps {
			walk(par, chain)
		}
	}
	walk(id, nil)
	return paths, total
}
