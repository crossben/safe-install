package pm

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

type npmAdapter struct{}

func (npmAdapter) Name() Kind { return NPM }

func (a npmAdapter) InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error {
	var before time.Time
	if opts.MinAge > 0 {
		before = time.Now().Add(-opts.MinAge)
	}
	cmd, err := a.installCmd(ctx, dir, opts.Args, before)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = opts.Stdout, opts.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install: %w", err)
	}
	return nil
}

func (npmAdapter) RunScripts(ctx context.Context, _ string, targets []Target, opts RunOptions) error {
	return runInPackageDirs(ctx, targets, opts)
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
	cmd := newCmd(ctx, dir, bin, argv)
	cmd.Env = append(cmd.Env, "npm_config_ignore_scripts=true")
	return cmd, nil
}
