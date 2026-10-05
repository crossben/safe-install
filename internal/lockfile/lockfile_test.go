package lockfile

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Every fixture is the same project locked by a different tool (see testdata/basic).
var basicFixtures = []struct {
	dir    string
	format Format
}{
	{"npm", NPMv3},
	{"pnpm9", PNPMv9},
	{"pnpm6", PNPMv6},
	{"yarnv1", YarnV1},
	{"berry", YarnBerry},
	{"bun", Bun},
}

func loadBasic(t *testing.T, dir string) *Graph {
	t.Helper()
	return loadFixture(t, "basic", dir)
}

func loadFixture(t *testing.T, set, dir string) *Graph {
	t.Helper()
	g, err := Load(filepath.Join("testdata", set, dir))
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	return g
}

var fixtureSets = []string{"basic", "workspace"}

func TestGolden(t *testing.T) {
	for _, set := range fixtureSets {
		for _, fx := range basicFixtures {
			t.Run(set+"/"+fx.dir, func(t *testing.T) {
				testGolden(t, set, fx.dir, fx.format)
			})
		}
	}
}

func testGolden(t *testing.T, set, dir string, format Format) {
	t.Helper()
	{
		{
			g := loadFixture(t, set, dir)
			if g.Format != format {
				t.Fatalf("format = %s, want %s", g.Format, format)
			}
			got := g.String()
			golden := filepath.Join("testdata", set, dir+".golden")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Fatalf("graph differs from %s (run with -update and review the diff)\n%s", golden, got)
			}
		}
	}
}

// The same project must produce the same tree whatever tool locked it.
func TestFormatsAgree(t *testing.T) {
	for _, set := range fixtureSets {
		ref := loadFixture(t, set, "npm").shape()
		for _, fx := range basicFixtures[1:] {
			if got := loadFixture(t, set, fx.dir).shape(); got != ref {
				t.Errorf("%s/%s disagrees with npm:\n--- npm\n%s\n--- %s\n%s", set, fx.dir, ref, fx.dir, got)
			}
		}
	}
}

// Workspaces, an npm: alias and a peer dependency (testdata/workspace).
func TestWorkspaceFacts(t *testing.T) {
	for _, fx := range basicFixtures {
		t.Run(fx.dir, func(t *testing.T) {
			g := loadFixture(t, "workspace", fx.dir)
			want := map[string][2]bool{ // id -> {direct, dev}
				"left-pad@1.3.0":                {true, false}, // installed as "lp"
				"react@18.3.1":                  {true, false},
				"loose-envify@1.4.0":            {false, false},
				"js-tokens@4.0.0":               {false, false},
				"use-sync-external-store@1.2.0": {true, false},
				"ms@2.0.0":                      {true, false}, // workspace a
				"is-number@7.0.0":               {true, true},  // workspace a, dev
			}
			if len(g.Packages) != len(want) {
				t.Errorf("%d packages, want %d:\n%s", len(g.Packages), len(want), g)
			}
			for id, w := range want {
				p, ok := g.Packages[id]
				if !ok {
					t.Errorf("%s missing", id)
					continue
				}
				if p.Direct != w[0] || p.Dev != w[1] {
					t.Errorf("%s: direct=%v dev=%v, want %v %v", id, p.Direct, p.Dev, w[0], w[1])
				}
			}
			// Peer dependencies are not edges: the provider is already in the tree.
			if p := g.Packages["use-sync-external-store@1.2.0"]; p != nil && len(p.Dependencies) != 0 {
				t.Errorf("use-sync-external-store deps = %v, want none", p.Dependencies)
			}
		})
	}
}

// Facts checked by hand against the fixture lockfiles.
func TestBasicFacts(t *testing.T) {
	for _, fx := range basicFixtures {
		t.Run(fx.dir, func(t *testing.T) {
			g := loadBasic(t, fx.dir)
			if n := len(g.Packages); n != 32 {
				t.Errorf("%d packages, want 32", n)
			}
			check := func(id string, direct, dev bool) {
				p, ok := g.Packages[id]
				if !ok {
					t.Errorf("%s missing", id)
					return
				}
				if p.Direct != direct || p.Dev != dev {
					t.Errorf("%s: direct=%v dev=%v, want direct=%v dev=%v", id, p.Direct, p.Dev, direct, dev)
				}
			}
			check("debug@2.6.9", true, false)
			check("ms@2.0.0", false, false) // nested under debug
			check("ms@2.1.3", true, false)
			check("esbuild@0.25.10", true, false)
			check("@esbuild/linux-x64@0.25.10", false, false)
			check("is-odd@3.0.1", true, true)
			check("is-number@6.0.0", false, true)

			if deps := g.Packages["debug@2.6.9"].Dependencies; len(deps) != 1 || deps[0] != "ms@2.0.0" {
				t.Errorf("debug deps = %v, want [ms@2.0.0]", deps)
			}
			// Formats that record SRI integrity must carry it through.
			if fx.format != YarnBerry {
				const want = "sha512-bC7ElrdJaJnPbAP+1EotYvqZsb3ecl5wi6Bfi6BJTUcNowp6cvspg0jXznRTKDjm/E7AdgFBVeAPVMNcKGsHMA=="
				if got := g.Packages["debug@2.6.9"].Integrity; got != want {
					t.Errorf("debug integrity = %q", got)
				}
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	write := func(t *testing.T, name, content string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if name != "" {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	tests := []struct {
		name, file, content string
		want                error
	}{
		{"no lockfile", "", "", ErrNoLockfile},
		{"bun binary", "bun.lockb", "\x00\x01", ErrBinaryLockfile},
		{"npm v1", "package-lock.json", `{"lockfileVersion":1,"dependencies":{}}`, ErrUnsupportedVersion},
		{"pnpm v5", "pnpm-lock.yaml", "lockfileVersion: 5.4\n", ErrUnsupportedVersion},
		{"bad json", "package-lock.json", `{`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.file, tt.content))
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSplitID(t *testing.T) {
	tests := []struct{ in, name, version string }{
		{"ms@2.1.3", "ms", "2.1.3"},
		{"@esbuild/linux-x64@0.25.10", "@esbuild/linux-x64", "0.25.10"},
		{"pkg@https://example.com/a@b.tgz", "pkg", "https://example.com/a@b.tgz"},
		{"nover", "nover", ""},
		{"@scope/nover", "@scope/nover", ""},
	}
	for _, tt := range tests {
		n, v := splitID(tt.in)
		if n != tt.name || v != tt.version {
			t.Errorf("splitID(%q) = %q, %q", tt.in, n, v)
		}
	}
}

func FuzzYarnV1(f *testing.F) {
	seed, err := os.ReadFile(filepath.Join("testdata", "basic", "yarnv1", "yarn.lock"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(seed))
	f.Add("a@^1:\n  version \"1.0.0\"\n  dependencies:\n    b \"^2\"\n")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = parseYarnV1(strings.NewReader(s), nil) // must not panic
	})
}

func FuzzBunJSONC(f *testing.F) {
	seed, err := os.ReadFile(filepath.Join("testdata", "basic", "bun", "bun.lock"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"a": [1, 2,], "s": "x,]",}`))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = parseBun(b) // must not panic
	})
}

// Windows checkouts (core.autocrlf) turn lockfiles into CRLF; they must parse the same.
func TestCRLFLockfiles(t *testing.T) {
	for _, set := range fixtureSets {
		for _, fx := range basicFixtures {
			t.Run(set+"/"+fx.dir, func(t *testing.T) {
				src := filepath.Join("testdata", set, fx.dir)
				dst := t.TempDir()
				err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return err
					}
					rel, _ := filepath.Rel(src, path)
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					crlf := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n", "\r\n")
					if err := os.MkdirAll(filepath.Dir(filepath.Join(dst, rel)), 0o750); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(dst, rel), []byte(crlf), 0o600)
				})
				if err != nil {
					t.Fatal(err)
				}
				g, err := Load(dst)
				if err != nil {
					t.Fatalf("Load CRLF: %v", err)
				}
				if got, want := g.shape(), loadFixture(t, set, fx.dir).shape(); got != want {
					t.Fatalf("CRLF parse differs:\n--- LF\n%s\n--- CRLF\n%s", want, got)
				}
			})
		}
	}
}

func TestParseMatchesLoadFile(t *testing.T) {
	for _, fx := range basicFixtures {
		dir := filepath.Join("testdata", "basic", fx.dir)
		path, err := Find(dir)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		g, err := Parse(filepath.Base(path), data, dir)
		if err != nil {
			t.Fatalf("%s: %v", fx.dir, err)
		}
		if g.String() != loadBasic(t, fx.dir).String() {
			t.Errorf("%s: Parse differs from LoadFile", fx.dir)
		}
	}
}

func TestChanged(t *testing.T) {
	base := loadBasic(t, "npm")
	cur := loadBasic(t, "npm")
	if got := Changed(base, cur); len(got.Packages) != 0 {
		t.Fatalf("identical graphs: %d changed", len(got.Packages))
	}

	// A new package, and an upgraded one.
	cur.Packages["left-pad@1.3.0"] = &Package{ID: "left-pad@1.3.0", Name: "left-pad", Version: "1.3.0", Direct: true}
	delete(cur.Packages, "ms@2.1.3")
	cur.Packages["ms@2.1.4"] = &Package{ID: "ms@2.1.4", Name: "ms", Version: "2.1.4", Direct: true}
	// A removed package is not reported.
	delete(cur.Packages, "is-number@6.0.0")

	got := Changed(base, cur)
	var ids []string
	for _, p := range got.Sorted() {
		ids = append(ids, p.ID)
	}
	if want := []string{"left-pad@1.3.0", "ms@2.1.4"}; strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("changed = %v, want %v", ids, want)
	}
	if got.Format != cur.Format {
		t.Fatal("format not kept")
	}
	if Changed(nil, cur) != cur {
		t.Fatal("no base: everything is new")
	}
}

func TestWhy(t *testing.T) {
	g := loadBasic(t, "npm")
	tests := []struct {
		id   string
		want [][]string
	}{
		{"debug@2.6.9", [][]string{{"debug@2.6.9"}}},
		{"ms@2.0.0", [][]string{{"debug@2.6.9", "ms@2.0.0"}}},
		{"ms@2.1.3", [][]string{{"ms@2.1.3"}}},
		{"is-number@6.0.0", [][]string{{"is-odd@3.0.1", "is-number@6.0.0"}}},
		{"@esbuild/linux-x64@0.25.10", [][]string{{"esbuild@0.25.10", "@esbuild/linux-x64@0.25.10"}}},
	}
	for _, tt := range tests {
		paths, total := g.Why(tt.id, 10)
		if total != len(tt.want) || fmt.Sprint(paths) != fmt.Sprint(tt.want) {
			t.Errorf("Why(%s) = %v (total %d), want %v", tt.id, paths, total, tt.want)
		}
	}
	if paths, total := g.Why("nope@1.0.0", 10); paths != nil || total != 0 {
		t.Errorf("unknown package: %v %d", paths, total)
	}
}

func TestWhyManyPathsAndLimit(t *testing.T) {
	// a, b, c are direct and all depend on shared; shared -> leaf.
	g := &Graph{Packages: map[string]*Package{}}
	add := func(id string, direct bool, deps ...string) {
		g.Packages[id] = &Package{ID: id, Name: id[:len(id)-6], Version: "1.0.0", Direct: direct, Dependencies: deps}
	}
	add("a@1.0.0", true, "shared@1.0.0")
	add("b@1.0.0", true, "shared@1.0.0")
	add("c@1.0.0", true, "shared@1.0.0", "leaf@1.0.0")
	add("shared@1.0.0", false, "leaf@1.0.0", "a@1.0.0") // a cycle back to a
	add("leaf@1.0.0", false)

	paths, total := g.Why("leaf@1.0.0", 10)
	// Shortest chains only: c -> leaf is length 2; the length-3 ones are not shown.
	if total != 1 || fmt.Sprint(paths) != "[[c@1.0.0 leaf@1.0.0]]" {
		t.Errorf("Why(leaf) = %v (total %d)", paths, total)
	}
	paths, total = g.Why("shared@1.0.0", 2)
	if total != 3 || len(paths) != 2 {
		t.Errorf("limit: %v (total %d), want 2 of 3", paths, total)
	}
}

func TestFindByName(t *testing.T) {
	g := loadBasic(t, "npm")
	if got := g.Find("ms"); fmt.Sprint(ids(got)) != "[ms@2.0.0 ms@2.1.3]" {
		t.Errorf("Find(ms) = %v", ids(got))
	}
	if got := g.Find("ms@2.1.3"); fmt.Sprint(ids(got)) != "[ms@2.1.3]" {
		t.Errorf("Find(ms@2.1.3) = %v", ids(got))
	}
	if got := g.Find("@esbuild/linux-x64"); len(got) != 1 {
		t.Errorf("Find(scoped) = %v", ids(got))
	}
	if got := g.Find("nope"); len(got) != 0 {
		t.Errorf("Find(nope) = %v", ids(got))
	}
}

func ids(ps []*Package) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.ID)
	}
	return out
}
