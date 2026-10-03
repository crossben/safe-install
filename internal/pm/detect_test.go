package pm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetect(t *testing.T) {
	const pkg = `{"name":"x"}`
	tests := []struct {
		name     string
		files    map[string]string
		override string
		want     Kind
		source   string
	}{
		{"npm lockfile", map[string]string{"package.json": pkg, "package-lock.json": "{}"}, "", NPM, "package-lock.json"},
		{"npm shrinkwrap", map[string]string{"package.json": pkg, "npm-shrinkwrap.json": "{}"}, "", NPM, "npm-shrinkwrap.json"},
		{"pnpm lockfile", map[string]string{"package.json": pkg, "pnpm-lock.yaml": ""}, "", PNPM, "pnpm-lock.yaml"},
		{"yarn lockfile", map[string]string{"package.json": pkg, "yarn.lock": ""}, "", Yarn, "yarn.lock"},
		{"bun text lockfile", map[string]string{"package.json": pkg, "bun.lock": ""}, "", Bun, "bun.lock"},
		{"bun binary lockfile", map[string]string{"package.json": pkg, "bun.lockb": ""}, "", Bun, "bun.lockb"},
		{"packageManager field", map[string]string{"package.json": `{"packageManager":"pnpm@9.12.0"}`}, "", PNPM, "packageManager field"},
		{"default npm", map[string]string{"package.json": pkg}, "", NPM, "default"},
		{"override wins", map[string]string{"package.json": pkg, "yarn.lock": ""}, "bun", Bun, "--pm flag"},
		{"npm lock + shrinkwrap is still npm", map[string]string{"package.json": pkg, "package-lock.json": "{}", "npm-shrinkwrap.json": "{}"}, "", NPM, "npm-shrinkwrap.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeFiles(t, tt.files)
			got, err := Detect(dir, tt.override)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if got.Kind != tt.want || got.Source != tt.source {
				t.Fatalf("got %s via %q, want %s via %q", got.Kind, got.Source, tt.want, tt.source)
			}
		})
	}
}

func TestDetectErrors(t *testing.T) {
	t.Run("no package.json", func(t *testing.T) {
		if _, err := Detect(t.TempDir(), ""); !errors.Is(err, ErrNoPackageJSON) {
			t.Fatalf("got %v, want ErrNoPackageJSON", err)
		}
	})
	t.Run("conflicting lockfiles", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"package.json": "{}", "package-lock.json": "{}", "yarn.lock": ""})
		if _, err := Detect(dir, ""); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("got %v, want ErrAmbiguous", err)
		}
	})
	t.Run("unknown override", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"package.json": "{}"})
		if _, err := Detect(dir, "cargo"); !errors.Is(err, ErrUnknownPM) {
			t.Fatalf("got %v, want ErrUnknownPM", err)
		}
	})
	t.Run("unknown packageManager field", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"package.json": `{"packageManager":"deno@2"}`})
		if _, err := Detect(dir, ""); !errors.Is(err, ErrUnknownPM) {
			t.Fatalf("got %v, want ErrUnknownPM", err)
		}
	})
	t.Run("invalid package.json", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"package.json": "{"})
		if _, err := Detect(dir, ""); err == nil {
			t.Fatal("expected error for invalid package.json")
		}
	})
}
