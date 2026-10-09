package cli

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/scripts"
)

// JSON shapes of `scripts` and `explain` (--format json). Field names are a
// contract for tools such as the VS Code extension: add fields, never rename.

type jsonFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type jsonScriptsPackage struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Direct   bool              `json:"direct"`
	Dev      bool              `json:"dev"`
	Dir      string            `json:"dir"`
	Scripts  map[string]string `json:"scripts"`
	Stages   []string          `json:"stages"`   // run order
	Implicit bool              `json:"implicit"` // install is node-gyp rebuild (binding.gyp)
	Level    string            `json:"level"`
	State    string            `json:"state"` // unapproved, approved, changed, expired, provenance
	Findings []jsonFinding     `json:"findings"`
}

type jsonExplanation struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Why   string `json:"why"`
	Fix   string `json:"fix"`
}

func scriptsJSON(cands []*scripts.Candidate) []jsonScriptsPackage {
	out := []jsonScriptsPackage{}
	for _, c := range cands {
		p := jsonScriptsPackage{
			ID: c.Package.ID, Name: c.Package.Name, Version: c.Package.Version,
			Direct: c.Package.Direct, Dev: c.Package.Dev, Dir: c.Dir,
			Scripts: map[string]string{}, Stages: c.Stages(), Implicit: c.Implicit,
			Level: c.Level.String(), State: c.State.Key(), Findings: []jsonFinding{},
		}
		for stage, command := range c.Scripts {
			p.Scripts[stage] = command
		}
		for _, f := range c.Findings {
			p.Findings = append(p.Findings, jsonFinding{f.Rule, f.Severity.String(), f.Message})
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func explainJSON(e analyze.Explanation) jsonExplanation {
	return jsonExplanation{e.ID, e.Title, e.Why, e.Fix}
}

func explainJSONList(es []analyze.Explanation) []jsonExplanation {
	out := make([]jsonExplanation, 0, len(es))
	for _, e := range es {
		out = append(out, explainJSON(e))
	}
	return out
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // read by tools, not embedded in HTML
	return enc.Encode(v)
}
