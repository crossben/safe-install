package lockfile

import (
	"encoding/json"
	"fmt"
	"strings"
)

type bunLock struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Workspaces      map[string]bunWorkspace      `json:"workspaces"`
	Packages        map[string][]json.RawMessage `json:"packages"`
}

type bunWorkspace struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

type bunMeta struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// parseBun reads bun.lock: JSON with trailing commas. Each package is
// [ident, registry, meta, integrity] for npm packages; keys nest like
// install paths ("debug/ms" is ms installed under debug).
func parseBun(data []byte) (*Graph, error) {
	var lock bunLock
	if err := json.Unmarshal(stripTrailingCommas(data), &lock); err != nil {
		return nil, err
	}
	if lock.LockfileVersion > 1 {
		return nil, fmt.Errorf("%w: bun lockfileVersion %d", ErrUnsupportedVersion, lock.LockfileVersion)
	}

	b := newBuilder(Bun)
	ids := map[string]string{} // key -> ID
	metas := map[string]bunMeta{}
	for key, arr := range lock.Packages {
		if len(arr) == 0 {
			continue
		}
		var ident string
		if json.Unmarshal(arr[0], &ident) != nil {
			continue
		}
		name, version := splitID(ident)
		if strings.HasPrefix(version, "workspace:") || name == "" {
			continue
		}
		var registry, integrity string
		var meta bunMeta
		if len(arr) >= 4 && json.Unmarshal(arr[1], &registry) == nil {
			_ = json.Unmarshal(arr[2], &meta)
			_ = json.Unmarshal(arr[3], &integrity)
		} else {
			for _, raw := range arr[1:] {
				if json.Unmarshal(raw, &meta) == nil {
					break
				}
			}
		}
		ids[key] = b.add(name, version, registry, integrity)
		metas[key] = meta
	}

	// resolve looks dep up from the install path chain, innermost first.
	resolve := func(chain []string, dep string) string {
		for i := len(chain); i >= 0; i-- {
			key := strings.Join(append(append([]string{}, chain[:i]...), dep), "/")
			if id, ok := ids[key]; ok {
				return id
			}
		}
		return ""
	}

	for key, meta := range metas {
		chain := bunKeyChain(key)
		for dep := range mergeDeps(meta.Dependencies, meta.OptionalDependencies) {
			b.edge(ids[key], resolve(chain, dep))
		}
	}
	for path, ws := range lock.Workspaces {
		var chain []string
		if path != "" && ws.Name != "" {
			chain = []string{ws.Name}
		}
		for dep := range mergeDeps(ws.Dependencies, ws.OptionalDependencies) {
			b.root(resolve(chain, dep), false)
		}
		for dep := range ws.DevDependencies {
			b.root(resolve(chain, dep), true)
		}
	}
	return b.finish(), nil
}

// bunKeyChain splits "a/@s/b/c" into package names ["a", "@s/b", "c"].
func bunKeyChain(key string) []string {
	var out []string
	parts := strings.Split(key, "/")
	for i := 0; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
			out = append(out, parts[i]+"/"+parts[i+1])
			i++
			continue
		}
		out = append(out, parts[i])
	}
	return out
}

// stripTrailingCommas removes commas directly before } or ], outside strings.
func stripTrailingCommas(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inString, escaped := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
		}
		if c == ',' {
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\n' || in[j] == '\r' || in[j] == '\t') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
