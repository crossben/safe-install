// Package analyze scores every package in a dependency graph against the risk rules.
package analyze

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/osv"
	"github.com/crossben/safe-install/internal/popularity"
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

	// From the registry, for check --deep: where the tarball is and its integrity.
	Tarball, RegistryIntegrity string
	// DistFiles (PyPI): the version's files with their registry hashes.
	DistFiles []registry.DistFile
}

// Report is the analysis of a whole graph.
type Report struct {
	Format  lockfile.Format
	Results []Result // one per registry package, sorted by ID
	Skipped int      // packages not checked (see SkippedWhy)
	// SkippedWhy explains Skipped; "" means "not from a registry" (git, file, …).
	SkippedWhy string
	Warnings   []string // optional data sources that failed (OSV, download counts)
	Base       string   // set when only packages changed since this base were checked
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
	Blocked       func(name string) bool // packages blocked by policy (SI-POL-001)
	RegistryHosts []string               // expected tarball hosts (SI-INT-002); empty skips the rule
	Concurrency   int                    // parallel registry fetches; default 16

	Popular   *popularity.List // enables SI-POP-001 and SI-POP-002
	Downloads DownloadSource   // weekly download counts for SI-POP-002; nil skips it
	OSV       VulnSource       // advisories for SI-VUL-001; nil skips it
	// Provenance (PyPI): which files carry a PEP 740 attestation, for
	// SI-REC-002. Looked up only for releases inside its window; nil skips it.
	Provenance ProvenanceSource

	Progress func(done, total int) // called after each registry fetch; nil for none
}

// VulnSource looks up advisories (osv.Client).
type VulnSource interface {
	Lookup(ctx context.Context, pkgs []osv.Package) (map[osv.Package][]osv.Vuln, error)
}

// ProvenanceSource reports, per file name, whether a file has an attestation (registry.PyPI).
type ProvenanceSource interface {
	Provenance(ctx context.Context, name string) (map[string]bool, error)
}

// DownloadSource returns weekly download counts (popularity.Downloads).
type DownloadSource interface {
	Weekly(ctx context.Context, names []string) (map[string]int, error)
}

// Input is what a rule sees for one package.
type Input struct {
	Package *lockfile.Package
	Doc     *registry.Packument
	Meta    *registry.VersionMeta // nil when the version is not in the registry
	Config  Config

	Vulns     []osv.Vuln
	Downloads int // last week's downloads; -1 when unknown
}

// Rule checks one risk signal.
type Rule interface {
	ID() string
	Check(in *Input) []Finding
}

// Scoped is implemented by rules that only make sense for some ecosystems
// (their data source is ecosystem-specific). Other rules apply everywhere.
type Scoped interface {
	Ecosystems() []ecosystem.Ecosystem
}

func appliesTo(r Rule, e ecosystem.Ecosystem) bool {
	s, ok := r.(Scoped)
	return !ok || slices.Contains(s.Ecosystems(), e.Or())
}

// Rules is the default rule set.
var Rules = []Rule{recencyRule{}, publisherRule{}, deprecatedRule{}, integrityRule{}, sourceRule{},
	typosquatRule{}, popularityRule{}, vulnRule{}, blockRule{}, buildRule{}}

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

	docs, errs := fetchAll(ctx, f, byName, cfg.Concurrency, cfg.Progress)

	var inputs []*Input
	for name, pkgs := range byName {
		for _, p := range pkgs {
			doc, err := docs[name], errs[name]
			if errors.Is(err, registry.ErrNotFound) {
				// Unpublished (often for being malicious): still checked.
				doc, err = &registry.Packument{Name: name}, nil
			}
			if err != nil {
				rep.Results = append(rep.Results, Result{Package: p, Err: err})
				continue
			}
			in := &Input{Package: p, Doc: doc, Config: cfg, Downloads: -1}
			if m, ok := in.Doc.Versions[p.Version]; ok {
				in.Meta = &m
			}
			inputs = append(inputs, in)
		}
	}
	rep.Warnings = enrich(ctx, inputs, cfg)
	for _, in := range inputs {
		rep.Results = append(rep.Results, check(in))
	}

	sort.Slice(rep.Results, func(i, j int) bool { return rep.Results[i].Package.ID < rep.Results[j].Package.ID })
	return rep
}

func fetchAll(ctx context.Context, f registry.Fetcher, byName map[string][]*lockfile.Package, concurrency int, progress func(done, total int)) (map[string]*registry.Packument, map[string]error) {
	docs := map[string]*registry.Packument{}
	errs := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for name := range byName {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			doc, err := f.Packument(ctx, name)
			<-sem
			mu.Lock()
			docs[name], errs[name] = doc, err
			if progress != nil {
				progress(len(docs), len(byName))
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return docs, errs
}

// enrich adds advisories and download counts. These sources are optional:
// a failure becomes a warning, not an unchecked package.
func enrich(ctx context.Context, inputs []*Input, cfg Config) []string {
	var warnings []string
	if cfg.OSV != nil && len(inputs) > 0 {
		pkgs := make([]osv.Package, len(inputs))
		for i, in := range inputs {
			pkgs[i] = osv.Package{Name: in.Package.Name, Version: in.Package.Version, Ecosystem: in.Package.Ecosystem}
		}
		vulns, err := cfg.OSV.Lookup(ctx, pkgs)
		if err != nil {
			warnings = append(warnings, "known-vulnerability check skipped: "+err.Error())
		}
		for i, in := range inputs {
			in.Vulns = vulns[pkgs[i]]
		}
	}
	if cfg.Provenance != nil {
		warnings = append(warnings, markProvenance(ctx, inputs, cfg)...)
	}
	if cfg.Downloads != nil && cfg.Popular != nil {
		// Only unpopular packages with install scripts are worth a lookup.
		want := map[string]bool{}
		for _, in := range inputs {
			if in.Meta != nil && hasInstallScript(in.Meta) && !cfg.Popular.Popular(in.Package.Name) {
				want[in.Package.Name] = true
			}
		}
		if len(want) > 0 {
			names := make([]string, 0, len(want))
			for n := range want {
				names = append(names, n)
			}
			sort.Strings(names)
			counts, err := cfg.Downloads.Weekly(ctx, names)
			if err != nil {
				warnings = append(warnings, "download counts skipped: "+err.Error())
			}
			for _, in := range inputs {
				if c, ok := counts[in.Package.Name]; ok {
					in.Downloads = c
				}
			}
		}
	}
	return warnings
}

// markProvenance fills DistFile.Provenance for PyPI packages whose version is
// recent enough for SI-REC-002 (one lookup per project; older releases are
// not worth a request).
func markProvenance(ctx context.Context, inputs []*Input, cfg Config) []string {
	byName := map[string][]*Input{}
	for _, in := range inputs {
		published := in.Doc.Published(in.Package.Version)
		if in.Package.Ecosystem == ecosystem.PyPI && in.Meta != nil && !published.IsZero() &&
			cfg.Now.Sub(published) <= publisherWindow {
			byName[in.Package.Name] = append(byName[in.Package.Name], in)
		}
	}
	var failed []string
	for name, ins := range byName {
		attested, err := cfg.Provenance.Provenance(ctx, name)
		if err != nil {
			failed = append(failed, name)
			continue
		}
		mark := func(files []registry.DistFile) {
			for i := range files {
				files[i].Provenance = attested[files[i].Name]
			}
		}
		doc := ins[0].Doc
		for v, m := range doc.Versions {
			m.Files = slices.Clone(m.Files)
			mark(m.Files)
			doc.Versions[v] = m
		}
		for _, in := range ins {
			if m, ok := doc.Versions[in.Package.Version]; ok {
				in.Meta = &m
			}
		}
	}
	if len(failed) == 0 {
		return nil
	}
	sort.Strings(failed)
	return []string{"provenance check skipped for " + strings.Join(failed, ", ")}
}

func hasInstallScript(m *registry.VersionMeta) bool {
	return m.Scripts["preinstall"] != "" || m.Scripts["install"] != "" || m.Scripts["postinstall"] != ""
}

func check(in *Input) Result {
	res := Result{Package: in.Package}
	if in.Meta != nil {
		res.Tarball, res.RegistryIntegrity = in.Meta.Dist.Tarball, in.Meta.Dist.Integrity
		res.DistFiles = in.Meta.Files
	}
	for _, r := range Rules {
		if !appliesTo(r, in.Package.Ecosystem) {
			continue
		}
		res.Findings = append(res.Findings, r.Check(in)...)
	}
	res.Score, res.Level = Score(res.Findings)
	return res
}

// Score adds up the weight of each rule's most severe finding (capped at 100)
// and derives the level: block if any finding blocks, else by score. Several
// findings of one rule (three advisories, two script stages) count once:
// they are one kind of evidence; different rules add up.
func Score(findings []Finding) (int, Level) {
	worst := map[string]Severity{}
	level := LevelNone
	for _, f := range findings {
		worst[f.Rule] = max(worst[f.Rule], f.Severity)
		if f.Severity == Block {
			level = LevelBlock
		}
	}
	score := 0
	for _, sev := range worst {
		score += int(sev)
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
