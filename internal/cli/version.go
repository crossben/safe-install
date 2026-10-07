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

// versionLine is what `version` and `--version` print.
func versionLine() string {
	return fmt.Sprintf("safe-install %s (%s, %s) %s/%s", version, commit, date, runtime.GOOS, runtime.GOARCH)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionLine())
			return err
		},
	}
}
