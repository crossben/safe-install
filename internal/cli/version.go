package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Set at build time by GoReleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "safe-install %s (%s, %s) %s/%s\n",
				version, commit, date, runtime.GOOS, runtime.GOARCH)
		},
	}
}
