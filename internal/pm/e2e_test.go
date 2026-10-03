package pm

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

// Each marker script writes "<package>-<stage>" into $MARKER_DIR.
const markerJS = `node -e "require('fs').writeFileSync(require('path').join(process.env.MARKER_DIR, process.env.npm_package_name + '-' + process.env.npm_lifecycle_event), '')"`

func markerScripts() map[string]string {
	return map[string]string{"preinstall": markerJS, "postinstall": markerJS}
}

// scriptedProject builds a project whose root and two tarball dependencies
// all have marker-writing lifecycle scripts.
func scriptedProject(t *testing.T, packageManager string) string {
	t.Helper()
	root := t.TempDir()
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o750); err != nil {
		t.Fatal(err)
	}
	deps := map[string]string{}
	for _, name := range []string{"good-dep", "other-dep"} {
		src := filepath.Join(root, name)
		if err := os.MkdirAll(src, 0o750); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, filepath.Join(src, "package.json"), map[string]any{"name": name, "version": "1.0.0", "scripts": markerScripts()})
		pack := exec.Command("npm", "pack", "--silent", "--pack-destination", proj)
		pack.Dir = src
		if out, err := pack.CombinedOutput(); err != nil {
			t.Fatalf("npm pack: %v\n%s", err, out)
		}
		deps[name] = "file:./" + name + "-1.0.0.tgz"
	}
	manifest := map[string]any{"name": "proj", "version": "1.0.0", "dependencies": deps, "scripts": markerScripts()}
	if packageManager != "" {
		manifest["packageManager"] = packageManager
	}
	writeJSON(t, filepath.Join(proj, "package.json"), manifest)
	return proj
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, string(data))
}

func markers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestAdaptersE2E(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm is needed to build fixtures and run scripts")
	}
	cases := []struct {
		name, tool, packageManager string
		kind                       Kind
	}{
		{"npm", "npm", "", NPM},
		{"pnpm", "pnpm", "", PNPM},
		{"yarn classic", "corepack", "yarn@1.22.22", Yarn},
		{"yarn berry", "corepack", "yarn@4.10.3", Yarn},
		{"bun", "bun", "", Bun},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.LookPath(tc.tool); err != nil {
				t.Skipf("%s not installed", tc.tool)
			}
			ctx := context.Background()
			proj := scriptedProject(t, tc.packageManager)
			if tc.packageManager == "yarn@4.10.3" {
				write(t, filepath.Join(proj, "yarn.lock"), "")
				t.Setenv("YARN_ENABLE_GLOBAL_CACHE", "false")
			}
			markerDir := t.TempDir()
			t.Setenv("MARKER_DIR", markerDir)
			t.Setenv("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
			// These projects have no lockfile yet. On CI (CI=true), Yarn berry
			// defaults to immutable installs and pnpm to --frozen-lockfile, which
			// refuse to create one.
			t.Setenv("YARN_ENABLE_IMMUTABLE_INSTALLS", "false")
			t.Setenv("npm_config_frozen_lockfile", "false")

			a, err := For(tc.kind, proj)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.InstallNoScripts(ctx, proj, InstallOptions{Stdout: io.Discard, Stderr: io.Discard}); err != nil {
				t.Fatalf("install: %v", err)
			}
			if got := markers(t, markerDir); len(got) != 0 {
				t.Fatalf("scripts ran during install: %v", got)
			}

			target := Target{Name: "good-dep", Version: "1.0.0", Stages: []string{"preinstall", "postinstall"}}
			if dir, ok := findInstalled(proj, "good-dep"); ok {
				target.Dir = dir
			}
			if err := a.RunScripts(ctx, proj, []Target{target}, RunOptions{Stdout: io.Discard, Stderr: io.Discard}); err != nil {
				t.Fatalf("run scripts: %v", err)
			}
			want := []string{"good-dep-postinstall", "good-dep-preinstall"}
			if got := markers(t, markerDir); !slices.Equal(got, want) {
				t.Fatalf("markers = %v, want %v", got, want)
			}
		})
	}
}

// findInstalled resolves node_modules/<name> (or berry's unplugged copy)
// to its real directory.
func findInstalled(proj, name string) (string, bool) {
	if dir, err := filepath.EvalSymlinks(filepath.Join(proj, "node_modules", name)); err == nil {
		return dir, true
	}
	matches, _ := filepath.Glob(filepath.Join(proj, ".yarn", "unplugged", "*", "node_modules", name))
	if len(matches) == 1 {
		return matches[0], true
	}
	return "", false
}
