// Package report renders analysis results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
)

// Text writes a human-readable report: risky packages worst first, then a summary.
func Text(w io.Writer, r *analyze.Report, source string) error {
	ew := &errWriter{w: w}
	if r.Base != "" {
		ew.printf("Analyzed %d new or changed package(s) from %s (%s) vs %s", len(r.Results), source, r.Format, r.Base)
	} else {
		ew.printf("Analyzed %d packages from %s (%s)", len(r.Results), source, r.Format)
	}
	if r.Skipped > 0 {
		ew.printf(", %d skipped (not from a registry)", r.Skipped)
	}
	ew.printf("\n")

	counts := map[analyze.Level]int{}
	for _, res := range r.Results {
		if res.Err == nil {
			counts[res.Level]++
		}
	}
	for lvl := analyze.LevelBlock; lvl > analyze.LevelNone; lvl-- {
		for _, res := range r.Results {
			if res.Err != nil || res.Level != lvl {
				continue
			}
			ew.printf("\n%-6s %s  (score %d%s)\n", strings.ToUpper(lvl.String()), res.Package.ID, res.Score, tags(res))
			for _, f := range res.Findings {
				ew.printf("       %s  %s\n", f.Rule, f.Message)
			}
		}
	}
	for _, w := range r.Warnings {
		ew.printf("\nwarning: %s\n", w)
	}
	if failed := r.Failed(); failed > 0 {
		ew.printf("\nCould not check %d package(s):\n", failed)
		for _, res := range r.Results {
			if res.Err != nil {
				ew.printf("  %s: %v\n", res.Package.ID, res.Err)
			}
		}
	}
	ew.printf("\n%d block, %d high, %d medium, %d low, %d clean\n",
		counts[analyze.LevelBlock], counts[analyze.LevelHigh], counts[analyze.LevelMedium],
		counts[analyze.LevelLow], counts[analyze.LevelNone])
	return ew.err
}

func tags(res analyze.Result) string {
	var t []string
	if res.Package.Direct {
		t = append(t, "direct")
	}
	if res.Package.Dev {
		t = append(t, "dev")
	}
	if len(t) == 0 {
		return ""
	}
	return ", " + strings.Join(t, ", ")
}

type jsonDiff struct {
	Base     string `json:"base"`
	Packages int    `json:"packages"` // new or changed packages checked
}

type jsonFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type jsonPackage struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	Direct   bool          `json:"direct"`
	Dev      bool          `json:"dev"`
	Score    int           `json:"score"`
	Level    string        `json:"level"`
	Findings []jsonFinding `json:"findings"`
	Error    string        `json:"error,omitempty"`
}

// JSON writes the full report as one JSON document.
func JSON(w io.Writer, r *analyze.Report, source string) error {
	out := struct {
		Format   string        `json:"format"`
		Lockfile string        `json:"lockfile"`
		Worst    string        `json:"worst"`
		Skipped  int           `json:"skipped"`
		Failed   int           `json:"failed"`
		Warnings []string      `json:"warnings"`
		Diff     *jsonDiff     `json:"diff,omitempty"`
		Packages []jsonPackage `json:"packages"`
	}{string(r.Format), source, r.Worst().String(), r.Skipped, r.Failed(), append([]string{}, r.Warnings...), nil, []jsonPackage{}}
	if r.Base != "" {
		out.Diff = &jsonDiff{Base: r.Base, Packages: len(r.Results) + r.Skipped}
	}
	for _, res := range r.Results {
		p := jsonPackage{
			ID: res.Package.ID, Name: res.Package.Name, Version: res.Package.Version,
			Direct: res.Package.Direct, Dev: res.Package.Dev,
			Score: res.Score, Level: res.Level.String(), Findings: []jsonFinding{},
		}
		for _, f := range res.Findings {
			p.Findings = append(p.Findings, jsonFinding{f.Rule, f.Severity.String(), f.Message})
		}
		if res.Err != nil {
			p.Error = res.Err.Error()
		}
		out.Packages = append(out.Packages, p)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// errWriter keeps the first write error so callers check once.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, args...)
	}
}
