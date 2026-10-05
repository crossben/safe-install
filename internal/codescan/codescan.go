// Package codescan looks for malicious code in a package's JavaScript files,
// the code that runs when the package is imported rather than at install.
//
// Rules fire on combinations, never on a single token: a capability (running
// commands, evaluating code, reading credentials) together with what makes it
// dangerous (a downloader, fetched data, a network send), close together in
// the same file. Expensive patterns only run after a cheap substring check.
package codescan

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
)

// Version identifies the rule set; cached results from another version are
// rescanned.
const Version = 1

const (
	maxFileBytes    = 2 << 20  // larger files (bundles) are skipped
	maxPackageBytes = 64 << 20 // stop scanning a package after this much code
	evalWindow      = 400      // network call -> eval distance (bytes)
	exfilWindow     = 1500     // credential -> network send distance (bytes)
	obfuscatorNames = 100      // _0x… identifiers that mark obfuscated code
)

var (
	execDownload = regexp.MustCompile("\\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\\s*\\(\\s*[`'\"][^`'\"]{0,300}?\\b(?:curl|wget|powershell|pwsh|iwr|irm|Invoke-WebRequest|Invoke-Expression|iex)\\b")
	netCall      = regexp.MustCompile(`\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|\baxios(?:\.\w+)?\s*\(|\bXMLHttpRequest\b|\bnet\.connect\s*\(`)
	evalCall     = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn\w*Context\s*\(|\brunInThisContext\s*\(`)
	secretRef    = regexp.MustCompile(`\.ssh[/\\'"]|\bid_rsa\b|\bid_ed25519\b|\.npmrc\b|\.aws/credentials|\.git-credentials|\.config/gcloud|Login Data|\b(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY)\b`)
	netSend      = regexp.MustCompile(`\bfetch\s*\(|\bhttps?\.request\s*\(|\baxios\.(?:post|put|request)\s*\(|\bXMLHttpRequest\b|\bnet\.connect\s*\(|\bdns\.(?:resolve|lookup)\w*\s*\(`)
	obfName      = regexp.MustCompile(`\b_0x[0-9a-f]{4,6}\b`)
	blobExec     = regexp.MustCompile(`(?:\beval|\bFunction|\brunIn\w*Context|\brunInThisContext)\s*\([^)]{0,120}$`)
)

type hit struct {
	rule string
	sev  analyze.Severity
	what string
}

// scanFile returns the rules a file's content triggers.
func scanFile(src string) []hit {
	var out []hit
	if containsAny(src, "curl", "wget", "powershell", "pwsh", "iwr", "irm", "Invoke-") && execDownload.MatchString(src) {
		out = append(out, hit{"SI-CODE-001", analyze.High, "runs a downloader from code"})
	} else if containsAny(src, "eval", "Function", "runIn") &&
		containsAny(src, "fetch", "http", "axios", "XMLHttpRequest", "net.connect") &&
		evalAfterNetwork(src) {
		out = append(out, hit{"SI-CODE-001", analyze.High, "evaluates code right after a network call"})
	}
	if containsAny(src, ".ssh", "id_rsa", "id_ed25519", ".npmrc", ".aws", ".git-credentials", "gcloud", "Login Data", "_TOKEN", "AWS_SECRET") &&
		secretRef.MatchString(src) && nearEither(secretRef, netSend, src, exfilWindow) {
		out = append(out, hit{"SI-CODE-002", analyze.High, "reads credentials next to a network send"})
	}
	if strings.Contains(src, "_0x") && len(obfName.FindAllStringIndex(src, obfuscatorNames)) >= obfuscatorNames {
		out = append(out, hit{"SI-CODE-003", analyze.Medium, "is obfuscated (javascript-obfuscator naming)"})
	} else if len(src) > 4000 && containsAny(src, "eval", "Function", "runIn") {
		for _, start := range base64Runs(src, 4000) {
			if blobExec.MatchString(src[max(0, start-160):start]) {
				out = append(out, hit{"SI-CODE-003", analyze.Medium, "evaluates a large encoded blob"})
				break
			}
		}
	}
	return out
}

// evalAfterNetwork reports whether code is evaluated within evalWindow bytes
// after a network call. Eval sites are rare, so they are found with plain
// string search first; the regexes only run on small windows.
func evalAfterNetwork(src string) bool {
	for _, tok := range []string{"eval", "Function", "runInThisContext", "runInNewContext", "runInContext"} {
		for from := 0; ; {
			i := strings.Index(src[from:], tok)
			if i < 0 {
				break
			}
			i += from
			from = i + len(tok)
			site := src[max(0, i-8):min(len(src), from+16)]
			if !evalCall.MatchString(site) {
				continue
			}
			if netCall.MatchString(src[max(0, i-evalWindow):i]) {
				return true
			}
		}
	}
	return false
}

// base64Runs returns the start offsets of base64-alphabet runs of at least
// minLen bytes, in one pass.
func base64Runs(src string, minLen int) []int {
	var out []int
	start := -1
	for i := 0; i <= len(src); i++ {
		in := i < len(src) && isBase64(src[i])
		switch {
		case in && start < 0:
			start = i
		case !in && start >= 0:
			if i-start >= minLen {
				out = append(out, start)
			}
			start = -1
		}
	}
	return out
}

func isBase64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// nearEither reports whether a and b match within window bytes of each other.
func nearEither(a, b *regexp.Regexp, src string, window int) bool {
	for _, loc := range a.FindAllStringIndex(src, -1) {
		if b.MatchString(src[max(0, loc[0]-window):min(len(src), loc[1]+window)]) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// readCapped reads at most maxFileBytes of a file inside the root.
func readCapped(fsys fs.FS, path string) ([]byte, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxFileBytes))
}

// isCode reports whether a file name is JavaScript the scanner reads.
func isCode(name string) bool {
	switch path.Ext(name) {
	case ".js", ".cjs", ".mjs":
		return true
	}
	return false
}

// collector groups hits into one finding per rule, naming the first file.
type collector struct {
	byRule map[string]*agg
	total  int64
}

type agg struct {
	sev   analyze.Severity
	files map[string]string // file -> what it does
}

// add scans one file; it reports false once the package's byte budget is spent.
func (c *collector) add(name string, data []byte) bool {
	if c.total += int64(len(data)); c.total > maxPackageBytes {
		return false
	}
	for _, h := range scanFile(string(data)) {
		a := c.byRule[h.rule]
		if a == nil {
			a = &agg{sev: h.sev, files: map[string]string{}}
			c.byRule[h.rule] = a
		}
		a.files[name] = h.what
	}
	return true
}

func (c *collector) findings() []analyze.Finding {
	var out []analyze.Finding
	for rule, a := range c.byRule {
		files := make([]string, 0, len(a.files))
		for f := range a.files {
			files = append(files, f)
		}
		sort.Strings(files)
		msg := fmt.Sprintf("%s %s", files[0], a.files[files[0]])
		if n := len(files) - 1; n > 0 {
			msg += fmt.Sprintf(" (and %d more file(s))", n)
		}
		out = append(out, analyze.Finding{Rule: rule, Severity: a.sev, Message: msg})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// Package scans the JavaScript files of the package installed in dir (not
// its nested node_modules) and returns one finding per rule triggered.
func Package(dir string) []analyze.Finding {
	c := &collector{byRule: map[string]*agg{}}
	// Every read goes through os.Root: nothing outside dir can be opened,
	// whatever symlinks the package ships.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	fsys := root.FS()
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != "." && (d.Name() == "node_modules" || d.Name() == ".git") {
				return fs.SkipDir
			}
			return nil
		}
		if !isCode(p) {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
			return nil // symlinks, devices, bundles
		}
		data, err := readCapped(fsys, p)
		if err != nil {
			return nil
		}
		if !c.add(p, data) {
			return fs.SkipAll
		}
		return nil
	})
	return c.findings()
}

// maxTarEntries bounds the archive entries read from one tarball.
const maxTarEntries = 50_000

// Tarball scans a package tarball (.tgz, as the registry serves it) in
// memory: nothing is extracted. Paths are taken relative to the archive's
// top directory ("package/"); absolute or escaping paths, links and
// non-regular entries are skipped.
func Tarball(r io.Reader) ([]analyze.Finding, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("reading tarball: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	c := &collector{byRule: map[string]*agg{}}
	for n := 0; n < maxTarEntries; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tarball: %w", err)
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxFileBytes {
			continue
		}
		name := path.Clean(strings.ReplaceAll(h.Name, "\\", "/"))
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			continue
		}
		// Drop the top directory (usually "package/").
		_, rel, ok := strings.Cut(name, "/")
		if !ok || !isCode(rel) || strings.Contains("/"+rel+"/", "/node_modules/") {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes))
		if err != nil {
			return nil, fmt.Errorf("reading tarball: %w", err)
		}
		if !c.add(rel, data) {
			break
		}
	}
	return c.findings(), nil
}
