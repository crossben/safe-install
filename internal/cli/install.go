package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/pm"
	"github.com/crossben/safe-install/internal/policy"
	"github.com/crossben/safe-install/internal/scripts"
)

func newInstallCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "install [-- <package manager args>]",
		Short: "Install dependencies, then run only the install scripts you approve",
		Example: "  safe-install install\n" +
			"  safe-install install -- --omit=dev",
		Args: installArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, g, args, false)
		},
	}
}

func newAddCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "add <package>... [-- <package manager args>]",
		Short: "Add packages with scripts disabled, then review their install scripts",
		Example: "  safe-install add left-pad\n" +
			"  safe-install add -- -D typescript",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, g, args, true)
		},
	}
}

// installArgs accepts arguments only after "--"; they go to the package manager.
func installArgs(cmd *cobra.Command, args []string) error {
	if dash := cmd.ArgsLenAtDash(); len(args) > 0 && dash != 0 {
		return errors.New("unexpected arguments; to add a package use `safe-install add`, to pass flags to the package manager put them after --")
	}
	return nil
}

// isInteractive reports whether approvals can be asked on the terminal.
var isInteractive = func() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// session is one install: the project, its package manager and policy.
type session struct {
	cmd     *cobra.Command
	g       *globalFlags
	dir     string
	det     pm.Detection
	adapter pm.Adapter
	pol     *policy.Policy
	w       *lineWriter
}

func newSession(cmd *cobra.Command, g *globalFlags) (*session, error) {
	pol, err := loadPolicy(cmd, g)
	if err != nil {
		return nil, err
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	det, err := pm.Detect(dir, g.pm)
	if err != nil {
		return nil, err
	}
	adapter, err := pm.For(det.Kind, dir)
	if err != nil {
		return nil, err
	}
	return &session{cmd, g, dir, det, adapter, pol, &lineWriter{w: cmd.ErrOrStderr()}}, nil
}

func runInstall(cmd *cobra.Command, g *globalFlags, pmArgs []string, add bool) error {
	s, err := newSession(cmd, g)
	if err != nil {
		return err
	}
	minAge, err := parseMinAge(g.minAge)
	if err != nil {
		return err
	}
	w := s.w
	gate := "release-age gate off"
	if minAge > 0 {
		gate = "new versions must be " + g.minAge + " old"
		if !pm.SupportsMinAge(s.adapter) {
			gate = "no release-age gate for this package manager (`safe-install check` still flags fresh versions)"
		}
	}
	w.printf("safe-install: using %s (%s); lifecycle scripts disabled; %s\n", s.det.Kind, s.det.Source, gate)
	opts := pm.InstallOptions{Args: pmArgs, Add: add, MinAge: minAge, Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr()}
	if err := s.adapter.InstallNoScripts(cmd.Context(), s.dir, opts); err != nil {
		return err
	}

	cands, graph, err := s.candidates()
	if err != nil {
		w.printf("safe-install: could not read the lockfile (%v); no dependency scripts were run\n", err)
		return w.err
	}
	approved, err := s.approve(cands)
	if err != nil {
		return err
	}
	if err := s.run(scripts.Order(approved, graph)); err != nil {
		return err
	}
	summarize(w, cands, approved)
	projectScriptsNote(w, s.dir, s.det.Kind)
	if w.err != nil {
		return w.err
	}
	if g.ci {
		ran := map[*scripts.Candidate]bool{}
		for _, c := range approved {
			ran[c] = true
		}
		for _, c := range cands {
			if !ran[c] && c.Level >= analyze.LevelHigh {
				return &exitError{ExitPolicyFailure, fmt.Errorf("%s wants to run a %s-risk install script", c.Package.ID, c.Level)}
			}
		}
	}
	return nil
}

// candidates finds the installed packages with install scripts, ordered
// dependencies first, with findings, level and approval state filled in.
func (s *session) candidates() ([]*scripts.Candidate, *lockfile.Graph, error) {
	graph, err := lockfile.Load(s.dir)
	if err != nil {
		return nil, nil, err
	}
	cands, _ := scripts.Discover(s.dir, graph)
	cands = scripts.Order(cands, graph)
	s.assess(cands, graph.Format)
	return cands, graph, nil
}

// assess scans each candidate's scripts, adds the registry rules and checks
// recorded approvals.
func (s *session) assess(cands []*scripts.Candidate, format lockfile.Format) {
	sub := &lockfile.Graph{Format: format, Packages: map[string]*lockfile.Package{}}
	for _, c := range cands {
		sub.Packages[c.Package.ID] = c.Package
	}
	registryFindings := map[string][]analyze.Finding{}
	if fetcher, err := newFetcher(s.g); err == nil && len(cands) > 0 {
		minAge, _ := parseMinAge(s.g.minAge)
		rep := analyze.Analyze(s.cmd.Context(), sub, fetcher, analysisConfig(s.g, s.pol, minAge))
		for _, w := range rep.Warnings {
			s.w.printf("safe-install: %s\n", w)
		}
		for _, res := range rep.Results {
			registryFindings[res.Package.ID] = res.Findings
		}
	}
	for _, c := range cands {
		c.Findings = append(scripts.Scan(c), registryFindings[c.Package.ID]...)
		state, f := scripts.ApprovalState(c, s.pol.AllowScripts)
		c.State = state
		if f != nil {
			c.Findings = append(c.Findings, *f)
		}
		_, c.Level = analyze.Score(c.Findings)
	}
}

// approve decides which candidates run: recorded approvals always; then
// asked one by one on a terminal, below-high with --yes, none otherwise.
func (s *session) approve(cands []*scripts.Candidate) ([]*scripts.Candidate, error) {
	var approved, pending []*scripts.Candidate
	for _, c := range cands {
		if c.State == scripts.Approved {
			approved = append(approved, c)
		} else {
			pending = append(pending, c)
		}
	}
	if len(pending) == 0 {
		return approved, nil
	}
	w := s.w
	switch {
	case s.g.yes:
		for _, c := range pending {
			if c.Level < analyze.LevelHigh {
				approved = append(approved, c)
			}
		}
	case !s.g.ci && isInteractive():
		in := bufio.NewReader(s.cmd.InOrStdin())
		w.printf("\n%d package(s) want to run install scripts.\n", len(pending))
		for _, c := range pending {
			describe(w, c)
			w.printf("Run these scripts? [y]es and remember / [o]nce / [N]o: ")
			line, err := in.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				if err := policy.Approve(s.pol.ProjectPath, c.Package.Name, policy.Approval{Version: c.Package.Version, Hash: c.Hash()}); err != nil {
					return nil, err
				}
				approved = append(approved, c)
			case "o", "once":
				approved = append(approved, c)
			}
			if errors.Is(err, io.EOF) && line == "" {
				w.printf("\n")
				break
			}
		}
	}
	return approved, w.err
}

// run executes the candidates' scripts through the package manager.
func (s *session) run(cands []*scripts.Candidate) error {
	if len(cands) == 0 {
		return nil
	}
	targets := make([]pm.Target, 0, len(cands))
	for _, c := range cands {
		targets = append(targets, pm.Target{Name: c.Package.Name, Version: c.Package.Version, Dir: c.Dir, Stages: c.Stages()})
	}
	s.w.printf("\nsafe-install: running approved scripts for %d package(s)\n", len(targets))
	if s.w.err != nil {
		return s.w.err
	}
	return s.adapter.RunScripts(s.cmd.Context(), s.dir, targets, pm.RunOptions{Stdout: s.cmd.OutOrStdout(), Stderr: s.cmd.ErrOrStderr()})
}

func describe(w *lineWriter, c *scripts.Candidate) {
	var tags []string
	if c.Package.Direct {
		tags = append(tags, "direct")
	}
	if c.Package.Dev {
		tags = append(tags, "dev")
	}
	extra := ""
	if len(tags) > 0 {
		extra = " (" + strings.Join(tags, ", ") + ")"
	}
	w.printf("\n%s%s  risk: %s\n", c.Package.ID, extra, strings.ToUpper(c.Level.String()))
	describeScripts(w, c)
}

func describeScripts(w *lineWriter, c *scripts.Candidate) {
	for _, s := range c.Stages() {
		note := ""
		if c.Implicit && s == "install" {
			note = "  (implicit: binding.gyp)"
		}
		w.printf("  %-11s %s%s\n", s+":", c.Scripts[s], note)
	}
	for _, f := range c.Findings {
		if f.Rule != "SI-SCR-001" {
			w.printf("  ! %s  %s\n", f.Rule, f.Message)
		}
	}
}

func summarize(w *lineWriter, cands, approved []*scripts.Candidate) {
	if len(cands) == 0 {
		w.printf("\nsafe-install: no dependency wants to run install scripts\n")
		return
	}
	ran := map[*scripts.Candidate]bool{}
	for _, c := range approved {
		ran[c] = true
	}
	var skipped []*scripts.Candidate
	for _, c := range cands {
		if !ran[c] {
			skipped = append(skipped, c)
		}
	}
	w.printf("\nsafe-install: ran install scripts for %d package(s), skipped %d\n", len(approved), len(skipped))
	for _, c := range skipped {
		w.printf("\nskipped %s  risk: %s  (%s)\n", c.Package.ID, strings.ToUpper(c.Level.String()), c.State)
		describeScripts(w, c)
	}
	if len(skipped) > 0 {
		w.printf("\nSkipped packages may not work until their scripts run. Review and run them with `safe-install approve <package>`.\n")
	}
}

// projectScriptsNote reminds that the project's own lifecycle scripts were not run.
func projectScriptsNote(w *lineWriter, dir string, kind pm.Kind) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json")) // #nosec G304 -- project manifest
	if err != nil {
		return
	}
	var m struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &m) != nil {
		return
	}
	var own []string
	for _, s := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if m.Scripts[s] != "" {
			own = append(own, s)
		}
	}
	if len(own) > 0 {
		w.printf("\nYour project's own scripts were not run: %s. If you trust this project, run them with `%s run <name>`.\n",
			strings.Join(own, ", "), kind)
	}
}

// lineWriter keeps the first write error so output code checks once.
type lineWriter struct {
	w   io.Writer
	err error
}

func (l *lineWriter) printf(format string, args ...any) {
	if l.err == nil {
		_, l.err = fmt.Fprintf(l.w, format, args...)
	}
}
