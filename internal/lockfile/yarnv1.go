package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type yarnV1Entry struct {
	descriptors []string
	version     string
	resolved    string
	integrity   string
	deps        map[string]string // name -> range
}

// parseYarnV1 reads the classic yarn.lock format: unindented descriptor
// headers, two-space fields, four-space dependency maps.
func parseYarnV1(r io.Reader, manifests []manifest) (*Graph, error) {
	var entries []*yarnV1Entry
	var cur *yarnV1Entry
	inDeps := false

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 0; sc.Scan(); {
		line++
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(text) - len(strings.TrimLeft(text, " "))
		switch {
		case indent == 0:
			if !strings.HasSuffix(trimmed, ":") {
				return nil, fmt.Errorf("yarn.lock line %d: expected entry header", line)
			}
			cur = &yarnV1Entry{deps: map[string]string{}}
			for _, d := range strings.Split(strings.TrimSuffix(trimmed, ":"), ",") {
				cur.descriptors = append(cur.descriptors, unquote(strings.TrimSpace(d)))
			}
			entries = append(entries, cur)
			inDeps = false
		case cur == nil:
			return nil, fmt.Errorf("yarn.lock line %d: field outside an entry", line)
		case indent == 2:
			key, val, _ := strings.Cut(trimmed, " ")
			key = unquote(key)
			inDeps = false
			switch key {
			case "version":
				cur.version = unquote(val)
			case "resolved":
				cur.resolved = unquote(val)
			case "integrity":
				cur.integrity = unquote(val)
			case "dependencies:", "optionalDependencies:":
				inDeps = true
			}
		case inDeps:
			name, rng, _ := strings.Cut(trimmed, " ")
			cur.deps[unquote(name)] = unquote(rng)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	b := newBuilder(YarnV1)
	byDesc := map[string]string{} // descriptor -> ID
	for _, e := range entries {
		if len(e.descriptors) == 0 || e.version == "" {
			continue
		}
		id := b.add(yarnRealName(e.descriptors[0]), e.version, e.resolved, e.integrity)
		for _, d := range e.descriptors {
			byDesc[d] = id
		}
	}
	for _, e := range entries {
		from := byDesc[firstOr(e.descriptors)]
		for n, rng := range e.deps {
			b.edge(from, byDesc[n+"@"+rng])
		}
	}
	for _, m := range manifests {
		m.roots(func(name, spec string, dev bool) {
			b.root(byDesc[name+"@"+spec], dev)
		})
	}
	return b.finish(), nil
}

// yarnRealName returns the package name of a descriptor, following
// "alias@npm:real@range" aliases.
func yarnRealName(desc string) string {
	name, rng := splitID(desc)
	if after, ok := strings.CutPrefix(rng, "npm:"); ok && strings.Contains(after[1:], "@") {
		target, _ := splitID(after)
		return target
	}
	return name
}

func unquote(s string) string {
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return s
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
