package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/codescan"
	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
	"github.com/crossben/safe-install/internal/report"
	"github.com/crossben/safe-install/internal/scripts"
)

func newScanCmd(g *globalFlags) *cobra.Command {
	var failOn string
	var prune bool
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan the code of installed packages for malicious patterns",
		Long: "Scans the JavaScript of every package in node_modules (code that runs when the\n" +
			"package is imported) for download-and-execute, credential exfiltration and\n" +
			"obfuscation. Exits 1 when a package reaches --fail-on.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			threshold, err := analyze.ParseLevel(failOn)
			if err != nil {
				return err
			}
			return runScan(cmd, g, threshold, prune)
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a package reaches this level: low, medium, high, block, none")
	cmd.Flags().BoolVar(&prune, "prune-accepted", false, "remove acceptFindings entries that are expired or whose package version is no longer in the lockfile")
	return cmd
}

func runScan(cmd *cobra.Command, g *globalFlags, failOn analyze.Level, prune bool) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	det, err := detectSupported(dir, g.pm, ecosystem.PyPI, ecosystem.Packagist)
	if err != nil {
		return err
	}
	path, err := lockfile.FindFor(dir, det.Ecosystem())
	if err != nil {
		return err
	}
	graph, err := lockfile.LoadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	var installed map[string]string
	var code map[string][]analyze.Finding
	if det.Ecosystem() == ecosystem.PyPI {
		installed, code = map[string]string{}, map[string][]analyze.Finding{}
		project := projectName(dir)
		for id, d := range pyInstalled(dir) {
			if d.name == project {
				continue
			}
			installed[id] = d.site
			code[id] = codescan.PythonInstalled(d.site, d.name, d.files)
		}
	} else if det.Ecosystem() == ecosystem.Packagist {
		installed, code = map[string]string{}, map[string][]analyze.Finding{}
		for id, pdir := range composerInstalled(dir) {
			installed[id] = pdir
			code[id] = codescan.ComposerInstalled(pdir)
		}
	} else {
		installed = scripts.Installed(dir)
		code = codeFindings(cmd, g, installed, graph)
	}

	// Only packages unpacked on disk were scanned; the rest (other platforms'
	// optional binaries, Plug'n'Play zips) are counted as skipped.
	rep := &analyze.Report{Format: graph.Format, SkippedWhy: "not installed on this machine"}
	if prune {
		if err := pruneAccepted(cmd.ErrOrStderr(), filepath.Join(dir, policy.FileName), graph); err != nil {
			return err
		}
	}
	pol, err := policy.Load(dir)
	if err != nil {
		return err
	}
	for _, p := range graph.Sorted() {
		if _, ok := installed[p.ID]; !ok {
			rep.Skipped++
			continue
		}
		res := analyze.Result{Package: p, Findings: code[p.ID]}
		res.Score, res.Level = analyze.Score(res.Findings)
		rep.Results = append(rep.Results, res)
	}
	applyAcceptances(rep, pol, func(id string) string { return installed[id] }, cmd.ErrOrStderr())
	if !prune {
		warnStale(cmd.ErrOrStderr(), pol, graph)
	}

	source := filepath.Base(path)
	out := cmd.OutOrStdout()
	switch g.format {
	case "text":
		err = report.Text(out, rep, source)
	case "json":
		err = report.JSON(out, rep, source)
	case "sarif":
		err = func(w io.Writer) error {
			data, err := os.ReadFile(path) // #nosec G304 -- the project's lockfile
			if err != nil {
				return err
			}
			return report.SARIF(w, rep, repoRelative(path), data, version)
		}(out)
	default:
		return fmt.Errorf("unknown --format %q (text, json, sarif)", g.format)
	}
	if err != nil {
		return err
	}
	// Accepted findings no longer count toward a package's level.
	if worst := rep.Worst(); failOn != analyze.LevelNone && worst >= failOn {
		return &exitError{ExitPolicyFailure, errors.New("found " + worst.String() + "-risk code (--fail-on " + failOn.String() + ")")}
	}
	return nil
}

// pruneAccepted removes acceptFindings entries from the project file that
// are expired or whose package version is not in the lockfile.
func pruneAccepted(w io.Writer, path string, graph *lockfile.Graph) error {
	if _, err := os.Stat(path); err != nil {
		_, _ = fmt.Fprintf(w, "safe-install: no %s here: nothing to prune\n", policy.FileName)
		return nil
	}
	stale, err := policy.PruneStale(path, lockfilePresent(graph))
	if err != nil {
		return err
	}
	expired, err := policy.PruneAcceptances(path)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "safe-install: removed %d stale and %d expired acceptance(s) from %s\n", stale, expired, policy.FileName)
	return nil
}
