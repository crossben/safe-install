package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
)

// Composer installs. Dependencies' scripts never run in Composer; the
// project's own are skipped (--no-scripts) and reported, as for npm. What
// does run code is plugins: each one is reviewed and approved (pinned to its
// commit), and Composer is run on a temporary copy of composer.json whose
// allow-plugins lists exactly the approved ones, so the project's files are
// never edited and no other plugin loads.

// composerCommand starts Composer; replaced in tests.
var composerCommand = func(dir string, env []string, args ...string) *exec.Cmd {
	c := exec.Command("composer", args...) // #nosec G204 -- fixed binary, arguments built by safe-install
	c.Dir = dir
	c.Env = append(os.Environ(), env...)
	return c
}

// The temporary manifest Composer is pointed at (COMPOSER=…); its lock is
// the same name with .lock.
const composerShadow = ".safe-install-composer"

func runComposerInstall(cmd *cobra.Command, g *globalFlags, pmArgs []string, add bool, pol *policy.Policy, dir string) error {
	if _, err := exec.LookPath("composer"); err != nil {
		return errors.New("composer is not on your PATH: install Composer (https://getcomposer.org) to install this project")
	}
	minAge, err := parseMinAge(g.minAge)
	if err != nil {
		return err
	}
	w := &lineWriter{w: cmd.ErrOrStderr()}
	gate := "release-age gate off"
	if minAge > 0 {
		gate = "new versions must be " + g.minAge + " old"
	}
	w.printf("safe-install: using composer (composer.lock); scripts off, plugins need approval; %s\n", gate)
	run := func(env []string, args ...string) error {
		c := composerCommand(dir, append(env, "COMPOSER_NO_INTERACTION=1"), args...)
		c.Stdout, c.Stderr = cmd.OutOrStdout(), cmd.ErrOrStderr()
		return c.Run()
	}

	// 1. Resolve without installing or running anything, then refuse fresh versions.
	lockPath := filepath.Join(dir, "composer.lock")
	before := snapshot(lockPath, filepath.Join(dir, "composer.json"))
	_, noLock := os.Stat(lockPath)
	resolveArgs := []string{"--no-install", "--no-scripts", "--no-plugins", "--no-interaction"}
	switch {
	case add:
		if err := run(nil, append(append([]string{"require"}, resolveArgs...), pmArgs...)...); err != nil {
			before.restore()
			return fmt.Errorf("composer require: %w", err)
		}
	case noLock != nil:
		if err := run(nil, append([]string{"update"}, resolveArgs...)...); err != nil {
			before.restore()
			return fmt.Errorf("composer update: %w", err)
		}
	}
	graph, err := lockfile.LoadFile(lockPath)
	if err != nil {
		return fmt.Errorf("composer.lock: %w", err)
	}
	if minAge > 0 && (add || noLock != nil) {
		var old *lockfile.Graph
		if data := before[lockPath]; data != nil {
			old, _ = lockfile.Parse("composer.lock", data, dir)
		}
		if fresh := freshVersions(cmd, g, pol, lockfile.Changed(old, graph), ecosystem.Packagist); len(fresh) > 0 {
			before.restore()
			w.printf("safe-install: these versions are younger than %s, so nothing was changed or installed:\n", g.minAge)
			for _, f := range fresh {
				w.printf("  %s\n", f)
			}
			w.printf("Pin an older version, wait, or pass --min-age 0 if you are sure.\n")
			return &exitError{ExitPolicyFailure, fmt.Errorf("%d fresh version(s) refused (--min-age %s)", len(fresh), g.minAge)}
		}
	}

	// 2. Review the plugins.
	allowed, err := reviewPlugins(cmd, g, pol, w, graph)
	if err != nil {
		return err
	}

	// 3. Install through a shadow manifest that allows exactly those plugins.
	shadowJSON, shadowLock, err := writeComposerShadow(dir, allowed)
	defer func() {
		_ = os.Remove(shadowJSON)
		_ = os.Remove(shadowLock)
	}()
	if err != nil {
		return err
	}
	args := append([]string{"install", "--no-scripts", "--no-interaction"}, installPassthrough(pmArgs, add)...)
	if err := run([]string{"COMPOSER=" + filepath.Base(shadowJSON)}, args...); err != nil {
		return fmt.Errorf("composer install: %w", err)
	}
	names := make([]string, 0, len(allowed))
	for n, ok := range allowed {
		if ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	w.printf("safe-install: installed with scripts off; plugins enabled: %s\n", listOrNone(names))
	composerScriptsNote(w, dir)
	return w.err
}

// installPassthrough keeps the arguments meant for `composer install` (after
// `--`); for add they were the package names, already used by require.
func installPassthrough(args []string, add bool) []string {
	if add {
		return nil
	}
	return args
}

// reviewPlugins returns plugin name -> allowed for this run.
func reviewPlugins(cmd *cobra.Command, g *globalFlags, pol *policy.Policy, w *lineWriter, graph *lockfile.Graph) (map[string]bool, error) {
	allowed := map[string]bool{}
	sub := &lockfile.Graph{Format: graph.Format, Packages: map[string]*lockfile.Package{}}
	for _, p := range graph.Sorted() {
		if !p.Plugin {
			continue
		}
		allowed[p.Name] = false
		if a, _, ok := pol.Lookup(p.Name); ok && p.Ref != "" && a.Hash == "ref:"+p.Ref && !a.Expired(time.Now()) && !pol.Blocked(p.Name) {
			allowed[p.Name] = true
			continue
		}
		sub.Packages[p.ID] = p
	}
	if len(sub.Packages) == 0 {
		return allowed, nil
	}
	minAge, _ := parseMinAge(g.minAge)
	fetcher, err := newFetcherFor(g, ecosystem.Packagist)
	if err != nil {
		return nil, err
	}
	cfg := analysisConfig(g, pol, minAge)
	cfg.RegistryHosts, cfg.Downloads = composerHosts(), nil
	rep := analyze.Analyze(cmd.Context(), sub, fetcher, cfg)
	deepScan(cmd, g, rep)
	for _, msg := range rep.Warnings {
		w.printf("safe-install: %s\n", msg)
	}
	switch {
	case g.yes:
		for _, r := range rep.Results {
			allowed[r.Package.Name] = r.Level < analyze.LevelHigh
		}
	case !g.ci && isInteractive():
		in := bufio.NewReader(cmd.InOrStdin())
		w.printf("\n%d Composer plugin(s) want to run inside Composer.\n", len(rep.Results))
		for _, r := range rep.Results {
			describeResult(w, r)
			w.printf("Enable it? [y]es and remember / [o]nce / [N]o: ")
			line, err := in.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				if err := policy.Approve(pol.ProjectPath, r.Package.Name, policy.Approval{Version: r.Package.Version, Hash: "ref:" + r.Package.Ref}); err != nil {
					return nil, err
				}
				allowed[r.Package.Name] = true
			case "o", "once":
				allowed[r.Package.Name] = true
			}
		}
	default:
		for _, r := range rep.Results {
			w.printf("\nsafe-install: plugin %s is not approved and will not be loaded\n", r.Package.ID)
			describeResult(w, r)
		}
		w.printf("Packages that need a plugin to install correctly may then fail; approve it after reviewing the findings.\n")
	}
	if g.ci {
		for _, r := range rep.Results {
			if !allowed[r.Package.Name] && r.Level >= analyze.LevelHigh {
				return nil, &exitError{ExitPolicyFailure, fmt.Errorf("plugin %s is %s risk", r.Package.ID, r.Level)}
			}
		}
	}
	return allowed, w.err
}

func describeResult(w *lineWriter, r analyze.Result) {
	w.printf("\n%s  risk: %s\n", r.Package.ID, strings.ToUpper(r.Level.String()))
	for _, f := range r.Findings {
		if f.Rule != "SI-PLG-001" && f.Rule != "SI-BLD-001" {
			w.printf("  ! %s  %s\n", f.Rule, f.Message)
		}
	}
}

// writeComposerShadow writes copies of composer.json and composer.lock whose
// config.allow-plugins is exactly allowed (every locked plugin listed, false
// unless approved). allow-plugins is not part of the lock's content-hash.
func writeComposerShadow(dir string, allowed map[string]bool) (string, string, error) {
	jsonPath := filepath.Join(dir, composerShadow+".json")
	lockPath := filepath.Join(dir, composerShadow+".lock")
	data, err := os.ReadFile(filepath.Join(dir, "composer.json")) // #nosec G304 -- the project's manifest
	if err != nil {
		return jsonPath, lockPath, err
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		return jsonPath, lockPath, fmt.Errorf("composer.json: %w", err)
	}
	cfg, _ := manifest["config"].(map[string]any)
	if cfg == nil {
		cfg = map[string]any{}
	}
	rules := map[string]any{}
	for name, ok := range allowed {
		rules[name] = ok
	}
	cfg["allow-plugins"] = rules // replaces the project's own list for this run
	manifest["config"] = cfg
	out, err := json.MarshalIndent(manifest, "", "    ")
	if err != nil {
		return jsonPath, lockPath, err
	}
	lock, err := os.ReadFile(filepath.Join(dir, "composer.lock")) // #nosec G304 -- the project's lockfile
	if err != nil {
		return jsonPath, lockPath, err
	}
	if err := os.WriteFile(jsonPath, out, 0o600); err != nil {
		return jsonPath, lockPath, err
	}
	return jsonPath, lockPath, os.WriteFile(lockPath, lock, 0o600) // #nosec G703 -- fixed file name inside the project
}

// composerScriptsNote reports the project's own scripts Composer would run
// on install, which safe-install skipped.
func composerScriptsNote(w *lineWriter, dir string) {
	data, err := os.ReadFile(filepath.Join(dir, "composer.json")) // #nosec G304 -- the project's manifest
	if err != nil {
		return
	}
	var manifest struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return
	}
	var skipped []string
	for _, ev := range []string{"pre-install-cmd", "post-install-cmd", "pre-autoload-dump", "post-autoload-dump", "post-root-package-install", "post-create-project-cmd"} {
		if _, ok := manifest.Scripts[ev]; ok {
			skipped = append(skipped, ev)
		}
	}
	if len(skipped) > 0 {
		w.printf("safe-install: your project's own scripts were not run (%s); run them with `composer run-script <event>` if you need them\n", strings.Join(skipped, ", "))
	}
}

// composerInstalled maps "name@version" to the installed directory of each
// package Composer recorded in vendor/composer/installed.json. Paths that
// leave the project are ignored.
func composerInstalled(dir string) map[string]string {
	out := map[string]string{}
	base := filepath.Join(dir, "vendor", "composer")
	data, err := os.ReadFile(filepath.Join(base, "installed.json")) // #nosec G304 -- the project's own vendor metadata
	if err != nil {
		return out
	}
	var installed struct {
		Packages []struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			InstallPath string `json:"install-path"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &installed) != nil {
		return out
	}
	for _, p := range installed.Packages {
		if p.InstallPath == "" {
			continue
		}
		pdir := filepath.Clean(filepath.Join(base, filepath.FromSlash(p.InstallPath)))
		if rel, err := filepath.Rel(dir, pdir); err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		out[ecosystem.Normalize(ecosystem.Packagist, p.Name)+"@"+p.Version] = pdir
	}
	return out
}
