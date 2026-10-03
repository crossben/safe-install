package pm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// pnpm: --ignore-scripts covers the project and every dependency;
// minimumReleaseAge (minutes) is pnpm's native release-age gate.
type pnpmAdapter struct{}

func (pnpmAdapter) Name() Kind { return PNPM }

func (pnpmAdapter) InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error {
	cmd, err := command(ctx, dir, "pnpm", append(append([]string{verb(opts, "install")}, opts.Args...), "--ignore-scripts")...)
	if err != nil {
		return err
	}
	cmd.Env = append(cmd.Env, "npm_config_ignore_scripts=true")
	if opts.MinAge > 0 {
		cmd.Env = append(cmd.Env, "npm_config_minimum_release_age="+minutes(opts.MinAge))
	}
	return run(cmd, opts.Stdout, opts.Stderr, "pnpm install")
}

func (pnpmAdapter) RunScripts(ctx context.Context, _ string, targets []Target, opts RunOptions) error {
	return runInPackageDirs(ctx, targets, opts)
}

// Yarn classic (v1): --ignore-scripts; no native release-age gate.
type yarnClassicAdapter struct{}

func (yarnClassicAdapter) Name() Kind { return Yarn }

func (yarnClassicAdapter) InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error {
	cmd, err := command(ctx, dir, "yarn", append(append([]string{verb(opts, "install")}, opts.Args...), "--ignore-scripts")...)
	if err != nil {
		return err
	}
	cmd.Env = append(cmd.Env, "npm_config_ignore_scripts=true", "YARN_IGNORE_SCRIPTS=true")
	return run(cmd, opts.Stdout, opts.Stderr, "yarn install")
}

func (yarnClassicAdapter) RunScripts(ctx context.Context, _ string, targets []Target, opts RunOptions) error {
	return runInPackageDirs(ctx, targets, opts)
}

// Yarn berry (v2+): --mode=skip-build skips every build script, the
// project's own included (enableScripts=false covers only dependencies, and
// stops berry from unplugging them). npmMinimalAgeGate (minutes) is the
// native release-age gate.
//
// `yarn rebuild <pkg>` would also run the project's pending scripts, so
// approved scripts run directly instead: berry unplugs packages with build
// scripts into .yarn/unplugged, and .pnp.cjs makes require() resolve there.
type yarnBerryAdapter struct{}

func (yarnBerryAdapter) Name() Kind { return Yarn }

func (yarnBerryAdapter) InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error {
	cmd, err := command(ctx, dir, "yarn", append(append([]string{verb(opts, "install")}, opts.Args...), "--mode=skip-build")...)
	if err != nil {
		return err
	}
	if opts.MinAge > 0 {
		cmd.Env = append(cmd.Env, "YARN_NPM_MINIMAL_AGE_GATE="+minutes(opts.MinAge))
	}
	return run(cmd, opts.Stdout, opts.Stderr, "yarn install")
}

func (yarnBerryAdapter) RunScripts(ctx context.Context, dir string, targets []Target, opts RunOptions) error {
	if pnp := filepath.Join(dir, ".pnp.cjs"); fileExists(pnp) {
		nodeOpts := strings.TrimSpace(os.Getenv("NODE_OPTIONS") + " --require=" + pnp)
		if loader := filepath.Join(dir, ".pnp.loader.mjs"); fileExists(loader) {
			nodeOpts += " --experimental-loader=" + (&url.URL{Scheme: "file", Path: filepath.ToSlash(loader)}).String()
		}
		opts.env = append(opts.env, "NODE_OPTIONS="+nodeOpts)
	}
	return runInPackageDirs(ctx, targets, opts)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// bun: --ignore-scripts; --minimum-release-age (seconds) is the native gate.
type bunAdapter struct{}

func (bunAdapter) Name() Kind { return Bun }

func (bunAdapter) InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error {
	args := append([]string{verb(opts, "install")}, opts.Args...)
	if opts.MinAge > 0 {
		args = append(args, fmt.Sprintf("--minimum-release-age=%d", int64(opts.MinAge.Seconds())))
	}
	cmd, err := command(ctx, dir, "bun", append(args, "--ignore-scripts")...)
	if err != nil {
		return err
	}
	cmd.Env = append(cmd.Env, "npm_config_ignore_scripts=true")
	return run(cmd, opts.Stdout, opts.Stderr, "bun install")
}

func (bunAdapter) RunScripts(ctx context.Context, _ string, targets []Target, opts RunOptions) error {
	return runInPackageDirs(ctx, targets, opts)
}

func verb(opts InstallOptions, install string) string {
	if opts.Add {
		return "add"
	}
	return install
}

// isBerry decides between Yarn classic and berry from the project alone:
// packageManager, then .yarnrc.yml, then the lockfile format; default classic.
func isBerry(dir string) bool {
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil { // #nosec G304 -- project manifest
		var m struct {
			PackageManager string `json:"packageManager"`
		}
		if json.Unmarshal(data, &m) == nil {
			if v, ok := strings.CutPrefix(m.PackageManager, "yarn@"); ok {
				return !strings.HasPrefix(v, "1.")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".yarnrc.yml")); err == nil {
		return true
	}
	if data, err := os.ReadFile(filepath.Join(dir, "yarn.lock")); err == nil { // #nosec G304 -- project lockfile
		return bytes.Contains(data, []byte("__metadata:"))
	}
	return false
}
