package pm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// ErrNotUnpacked is returned when a package's files are not on disk.
var ErrNotUnpacked = errors.New("package is not unpacked on disk")

// Adapter drives one package manager.
type Adapter interface {
	Name() Kind
	// InstallNoScripts installs dependencies in dir with every lifecycle
	// script disabled.
	InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error
	// RunScripts runs the given packages' lifecycle scripts, in order.
	RunScripts(ctx context.Context, dir string, targets []Target, opts RunOptions) error
}

// InstallOptions configures an install.
type InstallOptions struct {
	Args           []string      // passed through to the package manager
	Add            bool          // add packages (named in Args) instead of installing
	MinAge         time.Duration // skip versions younger than this when resolving; 0 disables
	Stdout, Stderr io.Writer
}

// Target is one approved package whose scripts should run.
type Target struct {
	Name, Version string
	Dir           string   // installed directory; "" when not unpacked
	Stages        []string // lifecycle stages to run, in order
}

// RunOptions configures RunScripts.
type RunOptions struct {
	Stdout, Stderr io.Writer
	ScriptShell    string   // run scripts with this shell instead of sh (the runtime monitor)
	Env            []string // extra environment for the scripts
}

// For returns the adapter for k in project dir.
func For(k Kind, dir string) (Adapter, error) {
	switch k {
	case NPM:
		return npmAdapter{}, nil
	case PNPM:
		return pnpmAdapter{}, nil
	case Yarn:
		if isBerry(dir) {
			return yarnBerryAdapter{}, nil
		}
		return yarnClassicAdapter{}, nil
	case Bun:
		return bunAdapter{}, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownPM, k)
}

// SupportsMinAge reports whether the adapter can enforce a release age itself.
func SupportsMinAge(a Adapter) bool {
	_, classic := a.(yarnClassicAdapter)
	return !classic
}

// command finds bin on PATH, falling back to `corepack <bin>` for package
// managers that are usually provided by corepack.
func command(ctx context.Context, dir, bin string, args ...string) (*exec.Cmd, error) {
	if path, err := exec.LookPath(bin); err == nil {
		return newCmd(ctx, dir, path, args), nil
	}
	if bin == "pnpm" || bin == "yarn" {
		if cp, err := exec.LookPath("corepack"); err == nil {
			return newCmd(ctx, dir, cp, append([]string{bin}, args...)), nil
		}
	}
	return nil, fmt.Errorf("%s not found in PATH", bin)
}

func newCmd(ctx context.Context, dir, bin string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- bin from LookPath, args built by safe-install
	cmd.Dir = dir
	cmd.Env = os.Environ()
	return cmd
}

func run(cmd *exec.Cmd, stdout, stderr io.Writer, what string) error {
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// runInPackageDirs runs each stage with `npm run <stage> --ignore-scripts`
// inside the package's own directory. npm runs an explicitly named script
// even with --ignore-scripts, but not its pre/post hooks, so exactly the
// approved stages run. Works for every node_modules layout.
func runInPackageDirs(ctx context.Context, targets []Target, opts RunOptions) error {
	for _, t := range targets {
		if t.Dir == "" {
			return fmt.Errorf("%s@%s: %w", t.Name, t.Version, ErrNotUnpacked)
		}
		for _, stage := range t.Stages {
			args := []string{"run", stage, "--ignore-scripts"}
			if opts.ScriptShell != "" {
				args = append(args, "--script-shell="+opts.ScriptShell)
			}
			cmd, err := command(ctx, t.Dir, "npm", args...)
			if err != nil {
				return fmt.Errorf("running approved scripts needs npm: %w", err)
			}
			cmd.Env = append(cmd.Env, opts.Env...)
			if err := run(cmd, opts.Stdout, opts.Stderr, fmt.Sprintf("%s@%s %s", t.Name, t.Version, stage)); err != nil {
				return err
			}
		}
	}
	return nil
}

func minutes(d time.Duration) string { return fmt.Sprint(int64(d.Minutes())) }
