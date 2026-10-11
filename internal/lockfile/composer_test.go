package lockfile

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/crossben/safe-install/internal/ecosystem"
)

// testdata/composer: a real composer.lock (Composer 2.10) for monolog,
// guzzle and, as dev, symfony/var-dumper.
func TestComposerLock(t *testing.T) {
	g, err := LoadFile(filepath.Join("testdata/composer", "composer.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Format != Composer || len(g.Packages) != 13 {
		t.Fatalf("format %s, %d packages", g.Format, len(g.Packages))
	}
	var direct []string
	for _, p := range g.Sorted() {
		if p.Ecosystem != ecosystem.Packagist || p.Ref == "" || p.Resolved == "" {
			t.Errorf("%s: %+v", p.ID, p)
		}
		if p.Direct {
			direct = append(direct, p.Name)
		}
	}
	if want := []string{"guzzlehttp/guzzle", "monolog/monolog", "symfony/var-dumper"}; !slices.Equal(direct, want) {
		t.Errorf("direct = %v, want %v", direct, want)
	}
	var vd *Package
	for _, p := range g.Packages {
		if p.Name == "symfony/var-dumper" {
			vd = p
		}
	}
	if vd == nil || !vd.Dev || vd.Version[0] != 'v' {
		t.Errorf("var-dumper: %+v (dev, v-prefixed version)", vd)
	}
	for _, p := range g.Packages {
		if p.Name == "monolog/monolog" && !slices.ContainsFunc(p.Dependencies, func(id string) bool { return id[:8] == "psr/log@" }) {
			t.Errorf("monolog -> psr/log edge missing: %v", p.Dependencies)
		}
	}
}

func TestComposerPlatformAndPaths(t *testing.T) {
	g, err := Parse("composer.lock", []byte(`{"packages":[
		{"name":"Acme/Plugin","version":"1.0.0","type":"composer-plugin","dist":{"type":"zip","url":"https://api.github.com/repos/acme/plugin/zipball/abc","reference":"abc","shasum":"DEADBEEF"}},
		{"name":"acme/local","version":"dev-main","dist":{"type":"path","url":"../local"}}
	]}`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pl := g.Packages["acme/plugin@1.0.0"]
	if pl == nil || !pl.Plugin || pl.Files[0].Hash != "sha1:deadbeef" {
		t.Fatalf("plugin = %+v", pl)
	}
	if l := g.Packages["acme/local@dev-main"]; l == nil || l.Resolved != "path:../local" {
		t.Fatalf("path package = %+v", l)
	}
	for _, n := range []string{"php", "ext-json", "lib-curl", "composer-plugin-api", "PHP"} {
		if !IsComposerPlatform(n) {
			t.Errorf("%s is a platform requirement", n)
		}
	}
	if IsComposerPlatform("phpunit/phpunit") {
		t.Error("phpunit is a package")
	}
}
