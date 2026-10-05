package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/pm"
)

// whyLimit is how many chains are shown per package.
const whyLimit = 10

func newWhyCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "why <package>[@version]",
		Short: "Show which dependency chains bring a package into the project",
		Example: "  safe-install why ms\n" +
			"  safe-install why ms@2.0.0 --format json",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWhy(cmd, g, args[0])
		},
	}
}

type whyResult struct {
	ID     string     `json:"id"`
	Direct bool       `json:"direct"`
	Dev    bool       `json:"dev"`
	Total  int        `json:"total"` // number of shortest chains
	Paths  [][]string `json:"paths"` // at most whyLimit, direct dependency first
}

func runWhy(cmd *cobra.Command, g *globalFlags, query string) error {
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
	found := graph.Find(query)
	if len(found) == 0 {
		return &exitError{ExitPolicyFailure, fmt.Errorf("%s is not in %s", query, filepath.Base(path))}
	}

	results := make([]whyResult, 0, len(found))
	for _, p := range found {
		paths, total := graph.Why(p.ID, whyLimit)
		results = append(results, whyResult{ID: p.ID, Direct: p.Direct, Dev: p.Dev, Total: total, Paths: paths})
	}

	out := cmd.OutOrStdout()
	if g.format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	w := &lineWriter{w: out}
	for i, r := range results {
		if i > 0 {
			w.printf("\n")
		}
		var tags []string
		if r.Direct {
			tags = append(tags, "direct")
		}
		if r.Dev {
			tags = append(tags, "dev")
		}
		head := r.ID
		if len(tags) > 0 {
			head += "  (" + strings.Join(tags, ", ") + ")"
		}
		w.printf("%s\n", head)
		if r.Total == 0 {
			w.printf("  not reachable from your dependencies (an extraneous lockfile entry)\n")
			continue
		}
		for _, chain := range r.Paths {
			w.printf("  your project › %s\n", strings.Join(chain, " › "))
		}
		if more := r.Total - len(r.Paths); more > 0 {
			w.printf("  … and %d more\n", more)
		}
	}
	return w.err
}
