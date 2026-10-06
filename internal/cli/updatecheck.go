package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/crossben/safe-install/internal/cache"
	"github.com/crossben/safe-install/internal/progress"
	"github.com/crossben/safe-install/internal/update"
)

// checkForUpdate looks for a newer release in the background while the
// command runs, and returns a function that prints a notice if there is one.
// It runs only for a person at a terminal: never in CI, with --ci or
// --offline, for development builds, or with SAFE_INSTALL_NO_UPDATE_CHECK.
func checkForUpdate(args []string, errOut io.Writer) func() {
	if os.Getenv("SAFE_INSTALL_NO_UPDATE_CHECK") != "" || os.Getenv("CI") != "" ||
		version == "dev" || !progress.Terminal(errOut) ||
		slices.Contains(args, "--offline") || slices.Contains(args, "--ci") {
		return func() {}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	result := make(chan string, 1)
	go func() {
		latest, err := (&update.Checker{CacheDir: cache.Sub(cache.Update)}).Latest(ctx)
		if err != nil {
			latest = ""
		}
		result <- latest
	}()
	return func() {
		defer cancel()
		select {
		case latest := <-result:
			if update.Newer(version, latest) {
				_, _ = fmt.Fprintf(errOut, "\n%s\n", update.Notice(version, latest))
			}
		case <-time.After(500 * time.Millisecond):
			// The command is done; do not keep the user waiting on GitHub.
		}
	}
}
