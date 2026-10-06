package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/progress"
)

// startProgress shows a progress line on stderr for slow work safe-install
// does itself, only in an interactive terminal and never in CI or with
// machine-readable output. The returned bar may be nil (no output).
func startProgress(cmd *cobra.Command, g *globalFlags, label string, total int) *progress.Bar {
	show := g.format == "text" && !g.ci && os.Getenv("CI") == ""
	return progress.Start(cmd.ErrOrStderr(), show, label, total)
}
