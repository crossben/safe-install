package pm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type npmAdapter struct{}

func (npmAdapter) Name() Kind { return NPM }

func (a npmAdapter) InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error {
	cmd, err := a.installCmd(ctx, dir, opts.Args, opts.Before)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = opts.Stdout, opts.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install: %w", err)
	}
	return nil
}

// installCmd builds the npm command. before maps to npm's --before: new
// resolutions skip newer versions; versions already locked are kept.
func (npmAdapter) installCmd(ctx context.Context, dir string, args []string, before time.Time) (*exec.Cmd, error) {
	bin, err := exec.LookPath("npm")
	if err != nil {
		return nil, fmt.Errorf("npm not found in PATH: %w", err)
	}
	// Flag last (npm lets the last flag win) and env, so neither user args
	// nor .npmrc can switch scripts back on.
	argv := append([]string{"install"}, args...)
	if !before.IsZero() {
		argv = append(argv, "--before", before.UTC().Format(time.RFC3339))
	}
	argv = append(argv, "--ignore-scripts")
	cmd := exec.CommandContext(ctx, bin, argv...) // #nosec G204 -- bin from LookPath, args are the user's own
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "npm_config_ignore_scripts=true")
	return cmd, nil
}
