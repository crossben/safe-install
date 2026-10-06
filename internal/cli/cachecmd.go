package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/cache"
)

func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Show or clean safe-install's cache (registry metadata, code-scan results, organization policy)",
		Long: "The cache is capped at 1 GB (SAFE_INSTALL_CACHE_MAX, e.g. 500MB): after each\n" +
			"command, the least recently used files are removed once it is over the cap.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "dir",
		Short: "Print the cache directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), cache.Dir())
			return err
		},
	}, &cobra.Command{
		Use:   "info",
		Short: "Show the size of each part of the cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := &lineWriter{w: cmd.OutOrStdout()}
			usage := cache.Usage()
			var total int64
			for _, p := range cache.Parts {
				w.printf("%-10s %s\n", p, humanBytes(usage[p]))
				total += usage[p]
			}
			limit, err := cache.ParseSize(os.Getenv("SAFE_INSTALL_CACHE_MAX"))
			if err != nil {
				return err
			}
			w.printf("%-10s %s of %s, in %s\n", "total", humanBytes(total), humanBytes(limit), cache.Dir())
			return w.err
		},
	}, &cobra.Command{
		Use:   "clean [registry|codescan|org]...",
		Short: "Empty the cache, or only the given parts",
		RunE: func(cmd *cobra.Command, parts []string) error {
			if err := cache.Clean(parts...); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "cache cleaned")
			return err
		},
	})
	return cmd
}

// pruneCache keeps the cache under its cap; it never fails a command.
func pruneCache() {
	limit, err := cache.ParseSize(os.Getenv("SAFE_INSTALL_CACHE_MAX"))
	if err != nil {
		limit = cache.DefaultMax
	}
	_, _ = cache.Prune(limit)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
