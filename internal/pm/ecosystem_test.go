package pm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/crossben/safe-install/internal/ecosystem"
)

func project(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetectOtherEcosystems(t *testing.T) {
	for _, c := range []struct {
		files  []string
		kind   Kind
		source string
		eco    ecosystem.Ecosystem
	}{
		{[]string{"pyproject.toml", "uv.lock"}, UV, "uv.lock", ecosystem.PyPI},
		{[]string{"pyproject.toml", "poetry.lock"}, Poetry, "poetry.lock", ecosystem.PyPI},
		{[]string{"Pipfile", "Pipfile.lock"}, Pipenv, "Pipfile.lock", ecosystem.PyPI},
		{[]string{"requirements.txt"}, Pip, "requirements.txt", ecosystem.PyPI},
		{[]string{"pyproject.toml"}, UV, "pyproject.toml", ecosystem.PyPI},
		{[]string{"composer.json", "composer.lock"}, Composer, "composer.lock", ecosystem.Packagist},
		{[]string{"composer.json"}, Composer, "composer.json", ecosystem.Packagist},
	} {
		d, err := Detect(project(t, c.files...), "")
		if err != nil || d.Kind != c.kind || d.Source != c.source || d.Ecosystem() != c.eco {
			t.Errorf("%v: got %+v (%v), want %s from %s", c.files, d, err, c.kind, c.source)
		}
		if err := d.Supported(); !errors.Is(err, ErrNotSupported) {
			t.Errorf("%v: Supported() = %v, want ErrNotSupported", c.files, err)
		}
	}
}

func TestDetectJavaScriptUnchanged(t *testing.T) {
	// package.json wins: a JavaScript project with a Python helper stays JavaScript.
	d, err := Detect(project(t, "package.json", "package-lock.json", "requirements.txt"), "")
	if err != nil || d.Kind != NPM || d.Supported() != nil {
		t.Fatalf("got %+v, %v", d, err)
	}
	// …unless --pm picks the other ecosystem.
	d, err = Detect(project(t, "package.json", "uv.lock"), "uv")
	if err != nil || d.Kind != UV || d.Source != "--pm flag" {
		t.Fatalf("--pm uv: got %+v, %v", d, err)
	}
}

func TestDetectAmbiguousOtherEcosystems(t *testing.T) {
	if _, err := Detect(project(t, "uv.lock", "composer.lock"), ""); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("got %v, want ErrAmbiguous", err)
	}
	if _, err := Detect(project(t), ""); !errors.Is(err, ErrNoPackageJSON) {
		t.Fatalf("empty dir: got %v", err)
	}
}

func TestNoAdapterYetForOtherEcosystems(t *testing.T) {
	for _, k := range []Kind{UV, Pip, Poetry, Pipenv, Composer} {
		if _, err := For(k, t.TempDir()); !errors.Is(err, ErrNotSupported) {
			t.Errorf("For(%s) = %v", k, err)
		}
	}
}
