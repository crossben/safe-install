package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInstallArgsFor(t *testing.T) {
	tests := []struct {
		rest []string
		verb string
	}{
		{nil, "install"},
		{[]string{"lodash"}, "add"},
		{[]string{"--save-exact", "lodash"}, "install"}, // could be a flag value: stay safe
		{[]string{"lodash", "-D"}, "add"},
		{[]string{"--filter", "web"}, "install"},
		{[]string{"-w", "app"}, "install"},
		{[]string{"--filter=web", "react"}, "add"},
		{[]string{"--frozen-lockfile"}, "install"},
	}
	for _, tt := range tests {
		if got := installArgsFor(tt.rest)[0]; got != tt.verb {
			t.Errorf("installArgsFor(%v) = %s, want %s", tt.rest, got, tt.verb)
		}
	}
}

func TestClassify(t *testing.T) {
	scripts := map[string]bool{"build": true, "lint": true}
	tests := []struct {
		args []string
		want verbKind
	}{
		{[]string{"install"}, verbInstall},
		{[]string{"i", "lodash"}, verbInstall},
		{[]string{"add", "-D", "x"}, verbInstall},
		{[]string{"isntall"}, verbInstall},
		{[]string{"ci"}, verbCleanInstall},
		{[]string{"clean-install"}, verbCleanInstall},
		// Allowed: the project's own scripts and read-only commands.
		{[]string{"run", "build"}, verbPassthrough},
		{[]string{"test"}, verbPassthrough},
		{[]string{"outdated"}, verbPassthrough},
		{[]string{"ls"}, verbPassthrough},
		{[]string{"audit"}, verbPassthrough},
		{[]string{"init"}, verbPassthrough},
		{[]string{"init", "-y"}, verbPassthrough},
		{[]string{"build"}, verbPassthrough}, // a script shorthand (yarn build)
		// Removing packages: passed through with scripts forced off.
		{[]string{"uninstall", "x"}, verbScriptsOff},
		{[]string{"remove", "x"}, verbScriptsOff},
		{[]string{"rm", "x"}, verbScriptsOff},
		// Refused: they run dependency scripts or remote code...
		{[]string{"update"}, verbRefused},
		{[]string{"rebuild", "esbuild"}, verbRefused},
		{[]string{"exec", "cowsay"}, verbRefused},
		{[]string{"dlx", "create-vite"}, verbRefused},
		{[]string{"create", "vite"}, verbRefused},
		{[]string{"init", "vite"}, verbRefused},
		{[]string{"audit", "fix"}, verbRefused},
		// ...and so does anything not known to be safe (fail closed).
		{[]string{"dedupe"}, verbRefused},
		{[]string{"prune"}, verbRefused},
		{[]string{"pm", "trust", "x"}, verbRefused},
		{[]string{"import"}, verbRefused},
		{[]string{"some-future-command"}, verbRefused},
		{[]string{"deploy"}, verbRefused}, // not a script in this project
	}
	for _, tt := range tests {
		if got := classify(tt.args, scripts); got != tt.want {
			t.Errorf("classify(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

// passthroughProject: an npm project whose own scripts write markers or fail.
func passthroughProject(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	dir := t.TempDir()
	markers := filepath.Join(dir, "markers")
	mustMkdir(t, markers)
	mustWriteJSON(t, filepath.Join(dir, "package.json"), map[string]any{"name": "p", "version": "1.0.0", "scripts": map[string]string{
		"hello": `node -e "require('fs').writeFileSync(process.argv[1] + '/hello-' + process.argv[2], '')" ` + markers,
		"boom":  `node -e "process.exit(7)"`,
	}})
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", t.TempDir())
	t.Chdir(dir)
	return markers
}

func runArgs(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &out)
	return out.String(), code
}

func TestPassthroughRunsProjectScripts(t *testing.T) {
	markers := passthroughProject(t)
	out, code := runArgs(t, "run", "hello", "--", "world")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(markers, "hello-world")); err != nil {
		t.Fatalf("script did not run with its arguments:\n%s", out)
	}
	if _, code := runArgs(t, "run", "boom"); code == 0 {
		t.Fatal("a failing script's exit code was lost")
	}
}

func TestPassthroughRefusesDangerousVerbs(t *testing.T) {
	passthroughProject(t)
	for _, args := range [][]string{{"exec", "cowsay"}, {"update"}, {"rebuild"}, {"audit", "fix"}, {"dedupe"}, {"brand-new-verb"}} {
		out, code := runArgs(t, args...)
		if code != ExitPolicyFailure || !strings.Contains(out, "safe-install") {
			t.Errorf("%v: exit %d\n%s", args, code, out)
		}
	}
}

func TestSafeInstallCommandsStillWork(t *testing.T) {
	passthroughProject(t)
	if out, code := runArgs(t, "version"); code != 0 || !strings.Contains(out, "safe-install") {
		t.Fatalf("version: %d %s", code, out)
	}
	if out, code := runArgs(t, "explain", "SI-SCR-002"); code != 0 || !strings.Contains(out, "SI-SCR-002") {
		t.Fatalf("explain: %d %s", code, out)
	}
}

// `i` and `ci` take safe-install's own path: scripts off, nothing unapproved runs.
func TestInstallVerbsAreRouted(t *testing.T) {
	markers := installProject(t)
	prev := isInteractive
	isInteractive = func() bool { return false }
	t.Cleanup(func() { isInteractive = prev })

	out, code := runArgs(t, "i")
	if code != 0 || !strings.Contains(out, "lifecycle scripts disabled") {
		t.Fatalf("i: exit %d\n%s", code, out)
	}
	if got := listMarkers(t, markers); len(got) != 0 {
		t.Fatalf("scripts ran through `i`: %v", got)
	}
	out, code = runArgs(t, "ci")
	if code != 0 || !strings.Contains(out, "lifecycle scripts disabled") {
		t.Fatalf("ci: exit %d\n%s", code, out)
	}
	if got := listMarkers(t, markers); len(got) != 0 {
		t.Fatalf("scripts ran through `ci`: %v", got)
	}
}

func TestScriptsOffCommand(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	dir := t.TempDir()
	cmd, err := passthroughCmd(dir, "npm", []string{"uninstall", "x"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cmd.Args, "--ignore-scripts") || !slices.Contains(cmd.Env, "npm_config_ignore_scripts=true") {
		t.Fatalf("scripts not forced off: %v", cmd.Args)
	}
	berry := t.TempDir()
	mustWriteJSON(t, filepath.Join(berry, "package.json"), map[string]any{"packageManager": "yarn@4.10.3"})
	if _, err := exec.LookPath("corepack"); err == nil {
		cmd, err := passthroughCmd(berry, "yarn", []string{"remove", "x"}, true)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(cmd.Args, "--mode=skip-build") {
			t.Fatalf("berry: %v", cmd.Args)
		}
	}
	plain, err := passthroughCmd(dir, "npm", []string{"run", "x"}, false)
	if err != nil || slices.Contains(plain.Args, "--ignore-scripts") {
		t.Fatalf("plain passthrough changed: %v %v", plain.Args, err)
	}
}

// Removing a package works through safe-install (functional check; that
// scripts are forced off is TestScriptsOffCommand).
func TestUninstallWorks(t *testing.T) {
	markers := installProject(t)
	prev := isInteractive
	isInteractive = func() bool { return false }
	t.Cleanup(func() { isInteractive = prev })
	if out, code := runArgs(t, "i"); code != 0 {
		t.Fatalf("i: %d\n%s", code, out)
	}
	out, code := runArgs(t, "uninstall", "evil-dep")
	if code != 0 {
		t.Fatalf("uninstall: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join("node_modules", "evil-dep")); !os.IsNotExist(err) {
		t.Fatal("evil-dep still installed")
	}
	if got := listMarkers(t, markers); len(got) != 0 {
		t.Fatalf("scripts ran during uninstall: %v\n%s", got, out)
	}
}
