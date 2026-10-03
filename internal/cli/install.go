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
	"time"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/pm"
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
			return runInstall(cmd, g, args)
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

func runInstall(cmd *cobra.Command, g *globalFlags, pmArgs []string) error {
	minAge, err := parseMinAge(g.minAge)
	if err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	det, err := pm.Detect(dir, g.pm)
	if err != nil {
		return err
	}
	adapter, err := pm.For(det.Kind, dir)
	if err != nil {
		return err
	}

	stderr := cmd.ErrOrStderr()
	w := &lineWriter{w: stderr}
	gate := "release-age gate off"
	if minAge > 0 {
		gate = "new versions must be " + g.minAge + " old"
		if !pm.SupportsMinAge(adapter) {
			gate = "no release-age gate for this package manager (`safe-install check` still flags fresh versions)"
		}
	}
	w.printf("safe-install: using %s (%s); lifecycle scripts disabled; %s\n", det.Kind, det.Source, gate)
	opts := pm.InstallOptions{Args: pmArgs, MinAge: minAge, Stdout: cmd.OutOrStdout(), Stderr: stderr}
	if err := adapter.InstallNoScripts(cmd.Context(), dir, opts); err != nil {
		return err
	}

	graph, err := lockfile.Load(dir)
	if err != nil {
		w.printf("safe-install: could not read the lockfile (%v); no dependency scripts were run\n", err)
		return w.err
	}
	cands, _ := scripts.Discover(dir, graph)
	cands = scripts.Order(cands, graph)
	assess(cmd, g, cands, graph.Format)

	approved, err := approve(cmd, g, w, cands)
	if err != nil {
		return err
	}
	if len(approved) > 0 {
		targets := make([]pm.Target, 0, len(approved))
		for _, c := range approved {
			targets = append(targets, pm.Target{Name: c.Package.Name, Version: c.Package.Version, Dir: c.Dir, Stages: c.Stages()})
		}
		w.printf("\nsafe-install: running approved scripts for %d package(s)\n", len(targets))
		if err := adapter.RunScripts(cmd.Context(), dir, targets, pm.RunOptions{Stdout: cmd.OutOrStdout(), Stderr: stderr}); err != nil {
			return err
		}
	}

	summarize(w, cands, approved)
	projectScriptsNote(w, dir, det.Kind)
	if w.err != nil {
		return w.err
	}
	if g.ci {
		for _, c := range cands {
			if c.Level >= analyze.LevelHigh {
				return &exitError{ExitPolicyFailure, fmt.Errorf("%s wants to run a %s-risk install script", c.Package.ID, c.Level)}
			}
		}
	}
	return nil
}

// assess scans each candidate's scripts and adds the registry rules.
func assess(cmd *cobra.Command, g *globalFlags, cands []*scripts.Candidate, format lockfile.Format) {
	sub := &lockfile.Graph{Format: format, Packages: map[string]*lockfile.Package{}}
	for _, c := range cands {
		sub.Packages[c.Package.ID] = c.Package
	}
	registryFindings := map[string][]analyze.Finding{}
	if fetcher, err := newFetcher(g); err == nil && len(cands) > 0 {
		minAge, _ := parseMinAge(g.minAge)
		rep := analyze.Analyze(cmd.Context(), sub, fetcher, analyze.Config{
			Now: time.Now(), MinReleaseAge: minAge, RegistryURL: registryURL(g),
		})
		for _, res := range rep.Results {
			registryFindings[res.Package.ID] = res.Findings
		}
	}
	for _, c := range cands {
		c.Findings = append(scripts.Scan(c), registryFindings[c.Package.ID]...)
		_, c.Level = analyze.Score(c.Findings)
	}
}

// approve decides which candidates run: asked one by one on a terminal,
// below-high with --yes, none otherwise.
func approve(cmd *cobra.Command, g *globalFlags, w *lineWriter, cands []*scripts.Candidate) ([]*scripts.Candidate, error) {
	if len(cands) == 0 {
		return nil, nil
	}
	var approved []*scripts.Candidate
	switch {
	case g.yes:
		for _, c := range cands {
			if c.Level < analyze.LevelHigh {
				approved = append(approved, c)
			}
		}
	case !g.ci && isInteractive():
		in := bufio.NewReader(cmd.InOrStdin())
		w.printf("\n%d package(s) want to run install scripts.\n", len(cands))
		for _, c := range cands {
			describe(w, c)
			w.printf("Run these scripts? [y/N] ")
			line, err := in.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			if ans := strings.ToLower(strings.TrimSpace(line)); ans == "y" || ans == "yes" {
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
		w.printf("\nskipped %s  risk: %s\n", c.Package.ID, strings.ToUpper(c.Level.String()))
		for _, s := range c.Stages() {
			w.printf("  %-11s %s\n", s+":", c.Scripts[s])
		}
		for _, f := range c.Findings {
			if f.Rule != "SI-SCR-001" {
				w.printf("  ! %s  %s\n", f.Rule, f.Message)
			}
		}
	}
	if len(skipped) > 0 {
		w.printf("\nSkipped packages may not work until their scripts run. Re-run safe-install in a terminal to review them.\n")
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
