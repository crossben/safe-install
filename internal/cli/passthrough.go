package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/crossben/safe-install/internal/pm"
)

type verbKind int

const (
	verbPassthrough  verbKind = iota // handed to the package manager unchanged
	verbInstall                      // routed to safe-install install/add
	verbCleanInstall                 // routed to safe-install install --frozen-lockfile
	verbRefused                      // may run dependency scripts or remote code
	verbScriptsOff                   // handed over with install scripts forced off
)

var (
	installVerbs = set("install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add")
	cleanVerbs   = set("ci", "clean-install", "ic", "install-clean", "isntall-clean")
	// Removing packages is common and needs no new code: allowed, scripts off.
	scriptsOffVerbs = set("uninstall", "remove", "rm", "r", "un", "unlink")
	// The only verbs passed through as they are: the project's own scripts, and
	// commands that read or publish without installing or running dependency
	// code. Everything else is refused (fail closed): package managers keep
	// adding commands that install or execute packages.
	safeVerbs = set(
		"run", "run-script", "rum", "urn", "test", "t", "tst", "start", "stop", "restart",
		"ls", "list", "la", "ll", "outdated", "view", "info", "show", "v", "why", "explain",
		"config", "c", "get", "set", "pkg", "search", "s", "se", "find",
		"bin", "prefix", "root", "help", "docs", "home", "repo", "bugs",
		"whoami", "ping", "doctor", "login", "logout", "adduser", "owner", "team", "access",
		"token", "profile", "pack", "publish", "unpublish", "deprecate", "dist-tag", "star",
		"stars", "unstar", "fund", "audit", "licenses", "query", "sbom", "init",
	)
	refusedReasons = map[string]string{
		"update":  "it installs new versions with install scripts on",
		"upgrade": "it installs new versions with install scripts on",
		"up":      "it installs new versions with install scripts on",
		"rebuild": "it runs every package's install scripts: use safe-install approve <package>",
		"rb":      "it runs every package's install scripts: use safe-install approve <package>",
		"exec":    "it downloads and runs a package with no review",
		"x":       "it downloads and runs a package with no review",
		"dlx":     "it downloads and runs a package with no review",
		"create":  "it downloads and runs a create-* package with no review",
	}
)

func set(words ...string) map[string]bool {
	m := map[string]bool{}
	for _, w := range words {
		m[w] = true
	}
	return m
}

// classify decides what to do with a command. scripts are the project's own
// package.json script names (yarn, pnpm and bun run them by name).
func classify(args []string, scripts map[string]bool) verbKind {
	verb := args[0]
	switch {
	case installVerbs[verb]:
		return verbInstall
	case cleanVerbs[verb]:
		return verbCleanInstall
	case scriptsOffVerbs[verb]:
		return verbScriptsOff
	case verb == "init" && len(args) > 1 && !strings.HasPrefix(args[1], "-"):
		return verbRefused // npm init <initializer> runs create-<initializer>
	case verb == "audit" && slices.Contains(args[1:], "fix"):
		return verbRefused // audit fix reinstalls with install scripts on
	case safeVerbs[verb], scripts[verb]:
		return verbPassthrough
	}
	return verbRefused
}

func refusal(args []string) string {
	why, ok := refusedReasons[args[0]]
	switch {
	case args[0] == "init":
		why = "with an initializer it downloads and runs create-" + args[1] + " with no review"
	case args[0] == "audit":
		why = "it reinstalls packages with install scripts on"
	case !ok:
		why = "it is not on safe-install's list of commands that run no dependency code"
	}
	return fmt.Sprintf("not passing %q to your package manager: %s. If you are sure, run it with the package manager directly (add --ignore-scripts where it installs), then run safe-install to review any new install scripts", strings.Join(args, " "), why)
}

// projectScripts returns the script names in dir's package.json.
func projectScripts(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "package.json")) // #nosec G304 -- project manifest
	if err != nil {
		return nil
	}
	var m struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	out := map[string]bool{}
	for name := range m.Scripts {
		out[name] = true
	}
	return out
}

// installArgsFor routes an install verb: with package names it is `add`,
// otherwise `install`; everything after the verb goes to the package manager.
// A word right after a flag without "=" may be that flag's value
// (`--filter web`, `-w app`), so it does not count as a package name.
func installArgsFor(rest []string) []string {
	for i, a := range rest {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if i > 0 && strings.HasPrefix(rest[i-1], "-") && !strings.Contains(rest[i-1], "=") {
			continue
		}
		return append([]string{"add", "--"}, rest...)
	}
	return append([]string{"install", "--"}, rest...)
}

// passthrough runs the project's package manager with args, connected to
// this terminal, and returns its exit code. With scriptsOff, install scripts
// are forced off for the command.
func passthrough(args []string, scriptsOff bool, in io.Reader, out, errOut io.Writer) int {
	dir, err := os.Getwd()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "safe-install:", err)
		return ExitToolError
	}
	kind := pm.NPM
	if det, err := pm.Detect(dir, ""); err == nil {
		kind = det.Kind
	}
	cmd, err := passthroughCmd(dir, kind, args, scriptsOff)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "safe-install:", err)
		return ExitToolError
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errOut
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return exit.ExitCode()
	case err != nil:
		_, _ = fmt.Fprintln(errOut, "safe-install:", err)
		return ExitToolError
	}
	return ExitOK
}

// passthroughCmd builds the package manager command; with scriptsOff it
// forces install scripts off (flag and environment).
func passthroughCmd(dir string, kind pm.Kind, args []string, scriptsOff bool) (*exec.Cmd, error) {
	if scriptsOff {
		flag := "--ignore-scripts"
		if kind == pm.Yarn && pm.YarnBerry(dir) {
			flag = "--mode=skip-build"
		}
		args = append(append([]string{}, args...), flag)
	}
	cmd, err := pm.Command(context.Background(), dir, kind, args...)
	if err != nil {
		return nil, err
	}
	if scriptsOff {
		cmd.Env = append(cmd.Env, "npm_config_ignore_scripts=true")
	}
	return cmd, nil
}
