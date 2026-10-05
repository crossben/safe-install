package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/npmrc"
	"github.com/crossben/safe-install/internal/osv"
	"github.com/crossben/safe-install/internal/pm"
	"github.com/crossben/safe-install/internal/policy"
	"github.com/crossben/safe-install/internal/popularity"
	"github.com/crossben/safe-install/internal/registry"
	"github.com/crossben/safe-install/internal/report"
)

func newCheckCmd(g *globalFlags) *cobra.Command {
	var failOn, sarifFile, diff string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Analyze the dependency tree without installing",
		Long: "Scores every package in the lockfile against the risk rules.\n" +
			"Exits 1 when a package reaches --fail-on, 3 when metadata could not be fetched.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pol, err := loadPolicy(cmd, g)
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("fail-on") && pol.FailOn != "" {
				failOn = pol.FailOn
			}
			threshold, err := analyze.ParseLevel(failOn)
			if err != nil {
				return err
			}
			return runCheck(cmd, g, pol, threshold, sarifFile, diff)
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a package reaches this level: low, medium, high, block, none")
	cmd.Flags().StringVar(&sarifFile, "sarif-file", "", "also write a SARIF report to this file (for code scanning)")
	cmd.Flags().StringVar(&diff, "diff", "", "only check packages new or changed since a git ref (e.g. origin/main) or an old lockfile")
	return cmd
}

func runCheck(cmd *cobra.Command, g *globalFlags, pol *policy.Policy, failOn analyze.Level, sarifFile, diff string) error {
	minAge, err := parseMinAge(g.minAge)
	if err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err := pm.Detect(dir, g.pm); err != nil {
		return err
	}
	path, err := lockfile.Find(dir)
	if err != nil {
		return err
	}
	graph, err := lockfile.LoadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	fetcher, err := newFetcher(g)
	if err != nil {
		return err
	}

	var baseMissing bool
	if diff != "" {
		base, err := baseGraph(path, diff)
		if err != nil {
			return err
		}
		baseMissing = base == nil
		graph = lockfile.Changed(base, graph)
	}
	rep := analyze.Analyze(cmd.Context(), graph, fetcher, analysisConfig(g, pol, minAge))
	rep.Base = diff
	if baseMissing {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s does not exist at %s: every package counts as new", filepath.Base(path), diff))
	}

	source := filepath.Base(path)
	sarif := func(w io.Writer) error {
		data, err := os.ReadFile(path) // #nosec G304 -- the project's lockfile
		if err != nil {
			return err
		}
		return report.SARIF(w, rep, repoRelative(path), data, version)
	}
	out := cmd.OutOrStdout()
	switch g.format {
	case "text":
		err = report.Text(out, rep, source)
	case "json":
		err = report.JSON(out, rep, source)
	case "sarif":
		err = sarif(out)
	default:
		return fmt.Errorf("unknown --format %q (text, json, sarif)", g.format)
	}
	if err != nil {
		return err
	}
	if sarifFile != "" {
		f, err := os.Create(sarifFile) // #nosec G304 -- path given by the user
		if err != nil {
			return err
		}
		werr := sarif(f)
		if err := errors.Join(werr, f.Close()); err != nil {
			return fmt.Errorf("writing %s: %w", sarifFile, err)
		}
	}

	if n := rep.Failed(); n > 0 {
		return &exitError{ExitToolError, fmt.Errorf("%d package(s) could not be checked", n)}
	}
	if failOn != analyze.LevelNone && rep.Worst() >= failOn {
		return &exitError{ExitPolicyFailure, fmt.Errorf("found %s-risk packages (--fail-on %s)", rep.Worst(), failOn)}
	}
	return nil
}

// analysisConfig builds the analysis settings, including the optional data
// sources: OSV advisories and npm download counts. Offline mode and registry
// fixtures turn them off unless their URL is set explicitly (tests).
func analysisConfig(g *globalFlags, pol *policy.Policy, minAge time.Duration) analyze.Config {
	cfg := analyze.Config{
		Now:           time.Now(),
		MinReleaseAge: minAge,
		Exclude:       pol.Excluded,
		RegistryHosts: registryConfig(g).Hosts(),
		Popular:       popularity.Default(),
	}
	if u, ok := sourceURL(g, "SAFE_INSTALL_OSV_URL", osv.DefaultURL); ok {
		cfg.OSV = &osv.Client{BaseURL: u}
	}
	if u, ok := sourceURL(g, "SAFE_INSTALL_DOWNLOADS_URL", popularity.DefaultDownloadsURL); ok {
		cfg.Downloads = &popularity.Downloads{BaseURL: u}
	}
	return cfg
}

func sourceURL(g *globalFlags, env, def string) (string, bool) {
	if u := os.Getenv(env); u != "" {
		return u, u != "off"
	}
	if g.offline || os.Getenv("SAFE_INSTALL_REGISTRY_FIXTURES") != "" {
		return "", false
	}
	return def, true
}

// repoRelative returns path relative to the enclosing git repository (as
// code scanning expects), or just its base name outside one.
func repoRelative(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Base(path)
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			if rel, err := filepath.Rel(dir, abs); err == nil {
				return filepath.ToSlash(rel)
			}
		}
		if filepath.Dir(dir) == dir {
			return filepath.Base(path)
		}
	}
}

func newFetcher(g *globalFlags) (registry.Fetcher, error) {
	if path := os.Getenv("SAFE_INSTALL_REGISTRY_FIXTURES"); path != "" {
		return registry.NewFixtureClient(path)
	}
	return &registry.Client{Config: registryConfig(g), CacheDir: registry.DefaultCacheDir(), Offline: g.offline}, nil
}

// registryConfig reads the project's (and user's) .npmrc and .yarnrc.yml;
// --registry overrides the default registry. An unreadable file falls back
// to the public registry rather than failing the run.
func registryConfig(g *globalFlags) *npmrc.Config {
	dir, _ := os.Getwd()
	cfg, err := npmrc.Load(dir, os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "safe-install: ignoring registry config:", err)
		cfg, _ = npmrc.Load(os.TempDir(), func(string) string { return "" })
	}
	if g.registry != "" {
		cfg.SetRegistry(g.registry)
	}
	return cfg
}

// parseMinAge accepts Go durations plus a "d" (days) suffix; "0" disables.
func parseMinAge(s string) (time.Duration, error) {
	var d time.Duration
	var err error
	if days, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		n, err = strconv.Atoi(days)
		d = time.Duration(n) * 24 * time.Hour
	} else {
		d, err = time.ParseDuration(s)
	}
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid --min-age %q (examples: 72h, 3d, 0)", s)
	}
	return d, nil
}
