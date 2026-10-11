package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/crossben/safe-install/internal/pm"
)

func runCLI(t *testing.T, args ...string) (stderr string, err error) {
	t.Helper()
	root := newRootCmd()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return errBuf.String(), err
}

func TestInstallWithoutPackageJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, args := range [][]string{nil, {"install"}} {
		if _, err := runCLI(t, args...); !errors.Is(err, pm.ErrNoPackageJSON) {
			t.Fatalf("%v: got %v, want ErrNoPackageJSON", args, err)
		}
	}
}

func TestInstallRejectsPositionalArgs(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := runCLI(t, "install", "left-pad"); err == nil {
		t.Fatal("expected error: packages are added with `safe-install add`")
	}
}

func TestOtherEcosystemsSayNotSupportedYet(t *testing.T) {
	for _, file := range []string{"uv.lock", "composer.lock"} {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, file), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"check"}, {"install"}, {"why", "x"}, {"scan"}} {
			if _, err := runCLI(t, args...); !errors.Is(err, pm.ErrNotSupported) {
				t.Errorf("%s %v: got %v, want ErrNotSupported", file, args, err)
			}
		}
	}
}
