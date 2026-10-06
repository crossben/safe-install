//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// ABI returns the kernel's Landlock ABI version, 0 when unavailable.
func ABI() int {
	v, err := ll.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	return v
}

// systemRO are read-only for every script: binaries, libraries, config,
// and kernel interfaces.
var systemRO = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt", "/proc", "/sys", "/run", "/snap", "/nix", "/var/lib"}

// homeCaches are the writable cache folders under $HOME. Only the caches
// themselves: never a folder holding executables (~/.bun/bin, pnpm's home,
// npx's cache), which a script could replace to run unsandboxed later.
var homeCaches = []string{
	".npm/_cacache", ".npm/_logs", // npm
	".cache/node-gyp", ".node-gyp", // native build headers
	".cache/yarn", ".yarn/berry/cache", // Yarn classic, berry
	".local/share/pnpm/store", ".pnpm-store", // pnpm
	".bun/install/cache", // bun
}

// Exec confines the current process with p and replaces it with
// `/bin/sh -c script`. It only returns on error; the restriction cannot be
// undone and is inherited by everything the script starts.
func Exec(p Policy, script string) error {
	if err := Apply(p); err != nil {
		return err
	}
	// Running the script the user approved is the point of this call.
	return syscall.Exec("/bin/sh", []string{"sh", "-c", script}, os.Environ()) // #nosec G204 G702 -- the approved script
}

// Apply confines the current process (all threads) and its future children
// with p, and points npm away from the now unreadable user .npmrc.
func Apply(p Policy) error {
	if err := Check(p.AllowNet); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()

	ro := append([]string{}, systemRO...)
	ro = append(ro, p.Project)
	ro = append(ro, p.ReadOnly...)
	ro = append(ro, pathDirs(home)...)
	if node, err := exec.LookPath("node"); err == nil {
		if resolved, err := filepath.EvalSymlinks(node); err == nil {
			ro = append(ro, filepath.Dir(filepath.Dir(resolved))) // the Node installation prefix
		}
	}

	// The package, node_modules and temp are writable by design (npm itself
	// puts node_modules/.bin on the script's PATH). Home caches are writable
	// only if no PATH entry lies in or around them: a tool installed there
	// could be replaced and later run outside the sandbox.
	rw := []string{p.Package, filepath.Join(p.Project, "node_modules"), os.TempDir(), "/tmp", "/var/tmp", "/dev/shm"}
	if home != "" {
		var caches []string
		for _, c := range homeCaches {
			caches = append(caches, filepath.Join(home, c))
		}
		rw = append(rw, withoutPathDirs(clean(caches))...)
	}

	rules := []landlock.Rule{
		landlock.RODirs(clean(ro)...).IgnoreIfMissing(),
		landlock.RWDirs(clean(rw)...).IgnoreIfMissing(),
		landlock.RWDirs("/dev").WithIoctlDev().IgnoreIfMissing(),
	}
	cfg := landlock.V10.BestEffort()
	var err error
	if p.AllowNet {
		err = cfg.RestrictPaths(rules...)
	} else {
		// No network rules: every TCP (and, on ABI 10+, UDP) connect and bind
		// is denied. Restrict also scopes signals and abstract sockets.
		err = cfg.Restrict(rules...)
	}
	if err != nil {
		return fmt.Errorf("applying the sandbox: %w", err)
	}
	// npm inside the script must not try to read the (now unreadable) user .npmrc.
	return os.Setenv("NPM_CONFIG_USERCONFIG", "/dev/null")
}

// withoutPathDirs drops paths that contain, or lie inside, a PATH entry.
func withoutPathDirs(rw []string) []string {
	var out []string
	for _, w := range rw {
		ok := true
		for _, d := range filepath.SplitList(os.Getenv("PATH")) {
			if !filepath.IsAbs(d) {
				continue
			}
			d = filepath.Clean(d)
			if within(d, w) || within(w, d) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, w)
		}
	}
	return out
}

func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// pathDirs returns the absolute PATH entries, except the home folder itself.
func pathDirs(home string) []string {
	var out []string
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.IsAbs(d) && filepath.Clean(d) != filepath.Clean(home) {
			out = append(out, d)
		}
	}
	return out
}

func clean(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if p == "" || !filepath.IsAbs(p) {
			continue
		}
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
