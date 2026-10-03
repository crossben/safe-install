package pm

import (
	"testing"
)

func TestFor(t *testing.T) {
	for _, k := range []Kind{NPM, PNPM, Yarn, Bun} {
		a, err := For(k, t.TempDir())
		if err != nil || a.Name() != k {
			t.Errorf("For(%s) = %v, %v", k, a, err)
		}
	}
	if _, err := For("cargo", t.TempDir()); err == nil {
		t.Error("expected error for unknown kind")
	}
}

func TestYarnFlavor(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		berry bool
	}{
		{"yarnrc.yml", map[string]string{"package.json": "{}", ".yarnrc.yml": ""}, true},
		{"berry lockfile", map[string]string{"package.json": "{}", "yarn.lock": "# x\n\n__metadata:\n  version: 8\n"}, true},
		{"packageManager v4", map[string]string{"package.json": `{"packageManager":"yarn@4.10.3"}`}, true},
		{"packageManager v1", map[string]string{"package.json": `{"packageManager":"yarn@1.22.22"}`}, false},
		{"classic lockfile", map[string]string{"package.json": "{}", "yarn.lock": "# yarn lockfile v1\n"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBerry(writeFiles(t, tt.files)); got != tt.berry {
				t.Fatalf("isBerry = %v, want %v", got, tt.berry)
			}
		})
	}
}

func TestAddVerb(t *testing.T) {
	if verb(InstallOptions{Add: true}, "install") != "add" || verb(InstallOptions{}, "install") != "install" {
		t.Fatal("verb")
	}
}
