// Package analyze scores every package in a dependency graph against the risk rules.
package analyze

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/registry"
)

// Severity of a single finding.
type Severity int

// Severities and their score weights.
const (
	Low    Severity = 10
	Medium Severity = 30
	High   Severity = 60
	Block  Severity = 100
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Block:
		return "block"
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// Level is a package's overall risk.
type Level int

// Levels, ordered.
const (
	LevelNone Level = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelBlock
)

var levelNames = []string{"none", "low", "medium", "high", "block"}

func (l Level) String() string { return levelNames[l] }

// ParseLevel parses a level name (as used by --fail-on).
func ParseLevel(s string) (Level, error) {
	for i, n := range levelNames {
		if strings.EqualFold(s, n) {
			return Level(i), nil
		}
	}
	return 0, fmt.Errorf("unknown level %q (use %s)", s, strings.Join(levelNames, ", "))
}

// Finding is one rule hit with its evidence.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"-"`
	Message  string   `json:"message"`
}

// Result is the verdict for one package.
type Result struct {
	Package  *lockfile.Package
	Findings []Finding
	Score    int   // sum of severity weights, capped at 100
	Level    Level // block if any blocking finding, else by score
	Err      error // metadata could not be fetched; the package was not checked
}

// Report is the analysis of a whole graph.
type Report struct {
	Format  lockfile.Format
	Results []Result // one per registry package, sorted by ID
	Skipped int      // non-registry packages (git, file, ...) not checked
}

// Failed counts packages whose metadata could not be fetched.
func (r *Report) Failed() int {
	n := 0
	for _, res := range r.Results {
		if res.Err != nil {
			n++
		}
	}
	return n
}

// Worst returns the highest level in the report.
func (r *Report) Worst() Level {
	w := LevelNone
	for _, res := range r.Results {
		w = max(w, res.Level)
	}
	return w
}

// Config tunes the rules.
type Config struct {
	Now           time.Time
	MinReleaseAge time.Duration          // 0 disables SI-REC-001
	Exclude       func(name string) bool // packages exempt from SI-REC-001
	RegistryURL   string                 // expected source of tarballs (SI-INT-002)
	Concurrency   int                    // parallel registry fetches; default 16
}

// Input is what a rule sees for one package.
type Input struct {
	Package *lockfile.Package
	Doc     *registry.Packument
	Meta    *registry.VersionMeta // nil when the version is not in the registry
	Config  Config
}

// Rule checks one risk signal.
type Rule interface {
	ID() string
	Check(in *Input) []Finding
}

// Rules is the default rule set.
var Rules = []Rule{recencyRule{}, publisherRule{}, deprecatedRule{}, integrityRule{}, sourceRule{}}

// Analyze fetches metadata for every registry package in g and runs the rules.
func Analyze(ctx context.Context, g *lockfile.Graph, f registry.Fetcher, cfg Config) *Report {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 16
	}
	rep := &Report{Format: g.Format}

	byName := map[string][]*lockfile.Package{}
	for _, p := range g.Sorted() {
		if !fromRegistry(p) {
			rep.Skipped++
			continue
		}
		byName[p.Name] = append(byName[p.Name], p)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Concurrency)
	for name, pkgs := range byName {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			doc, err := f.Packument(ctx, name)
			<-sem
			results := make([]Result, 0, len(pkgs))
			for _, p := range pkgs {
				if err != nil {
					results = append(results, Result{Package: p, Err: err})
					continue
				}
				results = append(results, check(p, doc, cfg))
			}
			mu.Lock()
			rep.Results = append(rep.Results, results...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(rep.Results, func(i, j int) bool { return rep.Results[i].Package.ID < rep.Results[j].Package.ID })
	return rep
}

func check(p *lockfile.Package, doc *registry.Packument, cfg Config) Result {
	in := &Input{Package: p, Doc: doc, Config: cfg}
	if m, ok := doc.Versions[p.Version]; ok {
		in.Meta = &m
	}
	res := Result{Package: p}
	for _, r := range Rules {
		res.Findings = append(res.Findings, r.Check(in)...)
	}
	res.Score, res.Level = Score(res.Findings)
	return res
}

// Score sums finding weights (capped at 100) and derives the level: block if
// any finding blocks, else by score.
func Score(findings []Finding) (int, Level) {
	score, level := 0, LevelNone
	for _, f := range findings {
		score += int(f.Severity)
		if f.Severity == Block {
			level = LevelBlock
		}
	}
	score = min(score, 100)
	if level == LevelBlock {
		return score, level
	}
	switch {
	case score >= 60:
		level = LevelHigh
	case score >= 30:
		level = LevelMedium
	case score > 0:
		level = LevelLow
	}
	return score, level
}

// fromRegistry reports whether p came from a registry rather than a git,
// file, link or tarball reference.
func fromRegistry(p *lockfile.Package) bool {
	v := p.Version
	if v == "" || v[0] < '0' || v[0] > '9' || strings.ContainsAny(v, ":/#") {
		return false
	}
	r := p.Resolved
	return r == "" || strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://")
}
