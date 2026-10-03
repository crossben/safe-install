package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/pm"
	"github.com/crossben/safe-install/internal/policy"
	"github.com/crossben/safe-install/internal/registry"
	"github.com/crossben/safe-install/internal/report"
)

func newCheckCmd(g *globalFlags) *cobra.Command {
	var failOn string
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
			return runCheck(cmd, g, pol, threshold)
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a package reaches this level: low, medium, high, block, none")
	return cmd
}

func runCheck(cmd *cobra.Command, g *globalFlags, pol *policy.Policy, failOn analyze.Level) error {
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

	rep := analyze.Analyze(cmd.Context(), graph, fetcher, analyze.Config{
		Now:           time.Now(),
		MinReleaseAge: minAge,
		Exclude:       pol.Excluded,
		RegistryURL:   registryURL(g),
	})

	source := filepath.Base(path)
	out := cmd.OutOrStdout()
	switch g.format {
	case "text":
		err = report.Text(out, rep, source)
	case "json":
		err = report.JSON(out, rep, source)
	case "sarif":
		return errors.New("--format sarif is not available yet")
	default:
		return fmt.Errorf("unknown --format %q (text, json)", g.format)
	}
	if err != nil {
		return err
	}

	if n := rep.Failed(); n > 0 {
		return &exitError{ExitToolError, fmt.Errorf("%d package(s) could not be checked", n)}
	}
	if failOn != analyze.LevelNone && rep.Worst() >= failOn {
		return &exitError{ExitPolicyFailure, fmt.Errorf("found %s-risk packages (--fail-on %s)", rep.Worst(), failOn)}
	}
	return nil
}

func newFetcher(g *globalFlags) (registry.Fetcher, error) {
	if path := os.Getenv("SAFE_INSTALL_REGISTRY_FIXTURES"); path != "" {
		return registry.NewFixtureClient(path)
	}
	return &registry.Client{BaseURL: registryURL(g), CacheDir: registry.DefaultCacheDir(), Offline: g.offline}, nil
}

func registryURL(g *globalFlags) string {
	if g.registry != "" {
		return g.registry
	}
	return registry.DefaultURL
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
