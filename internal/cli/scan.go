package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/pm"
	"github.com/crossben/safe-install/internal/report"
	"github.com/crossben/safe-install/internal/scripts"
)

func newScanCmd(g *globalFlags) *cobra.Command {
	var failOn string
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
			return runScan(cmd, g, threshold)
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a package reaches this level: low, medium, high, block, none")
	return cmd
}

func runScan(cmd *cobra.Command, g *globalFlags, failOn analyze.Level) error {
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
	installed := scripts.Installed(dir)
	code := codeFindings(installed, graph)

	// Only packages unpacked on disk were scanned; the rest (other platforms'
	// optional binaries, Plug'n'Play zips) are counted as skipped.
	rep := &analyze.Report{Format: graph.Format, SkippedWhy: "not installed on this machine"}
	for _, p := range graph.Sorted() {
		if _, ok := installed[p.ID]; !ok {
			rep.Skipped++
			continue
		}
		res := analyze.Result{Package: p, Findings: code[p.ID]}
		res.Score, res.Level = analyze.Score(res.Findings)
		rep.Results = append(rep.Results, res)
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
	if failOn != analyze.LevelNone && rep.Worst() >= failOn {
		return &exitError{ExitPolicyFailure, errors.New("found " + rep.Worst().String() + "-risk code (--fail-on " + failOn.String() + ")")}
	}
	return nil
}
