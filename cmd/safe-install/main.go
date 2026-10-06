// Command safe-install installs JavaScript dependencies without running
// lifecycle scripts you have not approved.
package main

import (
	"os"

	"github.com/crossben/safe-install/internal/cli"
	"github.com/crossben/safe-install/internal/scriptshell"
)

func main() {
	// Invoked by a package manager as the script shell of a monitored run.
	if code, ok := scriptshell.Run(os.Args); ok {
		os.Exit(code)
	}
	os.Exit(cli.Execute())
}
