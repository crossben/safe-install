// Command safe-install installs JavaScript dependencies without running
// lifecycle scripts you have not approved.
package main

import (
	"os"

	"github.com/crossben/safe-install/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
