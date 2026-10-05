package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/crossben/safe-install/internal/lockfile"
)

// baseGraph loads the lockfile to compare against for --diff: a lockfile on
// disk if base names one, otherwise the same lockfile at git ref base. A nil
// graph means the lockfile did not exist there, so every package is new.
func baseGraph(lockPath, base string) (*lockfile.Graph, error) {
	name, dir := filepath.Base(lockPath), filepath.Dir(lockPath)
	if st, err := os.Stat(base); err == nil && st.Mode().IsRegular() {
		data, err := os.ReadFile(base) // #nosec G304 -- a lockfile the user named
		if err != nil {
			return nil, err
		}
		return lockfile.Parse(name, data, dir)
	}

	if base == "" || strings.HasPrefix(base, "-") || strings.ContainsAny(base, " \t\n\x00") {
		return nil, fmt.Errorf("--diff %q: not a lockfile or a git ref", base)
	}
	if _, err := git(dir, "rev-parse", "--verify", "--quiet", base+"^{commit}"); err != nil {
		return nil, fmt.Errorf("--diff %q: not a lockfile or a git ref in this repository", base)
	}
	top, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(lockPath)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(strings.TrimSpace(top), abs)
	if err != nil {
		return nil, err
	}
	object := base + ":" + filepath.ToSlash(rel)
	if _, err := git(dir, "cat-file", "-e", object); err != nil {
		return nil, nil // no lockfile at that ref
	}
	data, err := git(dir, "show", object)
	if err != nil {
		return nil, err
	}
	return lockfile.Parse(name, []byte(data), dir)
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) // #nosec G204 -- fixed program, validated ref
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "", fmt.Errorf("git %s: %s", args[0], strings.TrimSpace(string(exit.Stderr)))
	}
	if err != nil {
		return "", fmt.Errorf("--diff needs git: %w", err)
	}
	return string(out), nil
}
