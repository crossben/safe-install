package codescan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
)

// Python patterns: the same combinations as for JavaScript, in Python's
// vocabulary. Each runs only after a cheap substring check.
var (
	pyExecDownload = regexp.MustCompile(`\b(?:subprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)|os\.(?:system|popen|exec\w*|spawn\w*)|commands\.getoutput)\s*\(\s*[\[(]?\s*[rbuf]?['"][^)\n]{0,300}?\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|Net\.WebClient|certutil|bitsadmin)\b`)
	pyPipeShell    = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|;&\n'"]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|perl)\b`)
	pyNetCall      = regexp.MustCompile(`\burlopen\s*\(|\burllib\.request\.\w+\s*\(|\brequests\.(?:get|post|request|Session)\b|\bhttpx\.\w+\s*\(|\bhttp\.client\.HTTPS?Connection\b|\burllib3\.\w+|\baiohttp\.\w+|\bsocket\.socket\s*\(|\.recv\s*\(`)
	pyEvalCall     = regexp.MustCompile(`\b(?:exec|eval|compile)\s*\(|\bmarshal\.loads\s*\(|\b__import__\s*\(\s*['"]marshal`)
	pyNetSend      = regexp.MustCompile(`\brequests\.(?:post|put|request)\s*\(|\burlopen\s*\(|\burllib\.request\.Request\s*\(|\bhttp\.client\.HTTPS?Connection\b|\bhttpx\.(?:post|put|request)\s*\(|\.sendall?\s*\(|\bsmtplib\.\w+|\bsocket\.socket\s*\(`)
	pyBlobExec     = regexp.MustCompile(`\b(?:exec|eval)\s*\(\s*(?:\w+\.)*(?:b64decode|b32decode|a85decode|decompress|loads|unhexlify|fromhex|decode)\s*\([^)]{0,80}$`)
	pyArmor        = regexp.MustCompile(`__pyarmor__|\bpyarmor_runtime\b`)
)

// scanPython returns the code-scan rules a Python file triggers.
func scanPython(src string) []hit {
	var out []hit
	if pyCommandDownload(src) {
		out = append(out, hit{"SI-CODE-001", analyze.High, "runs a downloader from code"})
	} else if containsAny(src, "exec", "eval", "compile", "marshal") &&
		containsAny(src, "urlopen", "urllib", "requests", "httpx", "http.client", "aiohttp", "socket", ".recv") &&
		pyEvalAfterNetwork(src) {
		out = append(out, hit{"SI-CODE-001", analyze.High, "evaluates code right after a network call"})
	}
	if containsAny(src, ".ssh", "id_rsa", "id_ed25519", ".npmrc", ".pypirc", ".aws", ".git-credentials", "gcloud", "Login Data", "_TOKEN", "AWS_SECRET") &&
		pySecretNearSend(src) {
		out = append(out, hit{"SI-CODE-002", analyze.High, "reads credentials next to a network send"})
	}
	if pyArmor.MatchString(src) {
		out = append(out, hit{"SI-CODE-003", analyze.Medium, "is obfuscated (PyArmor)"})
	} else if pyEncodedBlob(src) {
		out = append(out, hit{"SI-CODE-003", analyze.Medium, "evaluates a large encoded blob"})
	}
	return out
}

func pyCommandDownload(src string) bool {
	if !containsAny(src, "curl", "wget", "iwr", "irm", "Invoke-", "Download", "WebClient", "certutil", "bitsadmin") {
		return false
	}
	return pyExecDownload.MatchString(src) || pyPipeShell.MatchString(src)
}

func pyEvalAfterNetwork(src string) bool {
	for _, loc := range pyEvalCall.FindAllStringIndex(src, 200) {
		if loc[0] > 0 && src[loc[0]-1] == '.' {
			continue // re.compile(…), obj.eval(…): a method, not the builtin
		}
		if evaluatesLiteral(src[loc[1]:]) {
			continue // compile("x + 1", …): nothing fetched is evaluated
		}
		if pyNetCall.MatchString(src[max(0, loc[0]-evalWindow):loc[0]]) {
			return true
		}
	}
	return false
}

// evaluatesLiteral reports whether the argument right after an eval/exec
// call's "(" is a plain string literal (optionally prefixed r, b, u).
func evaluatesLiteral(rest string) bool {
	rest = strings.TrimLeft(rest, " \t")
	rest = strings.TrimLeft(rest, "rbuRBU")
	return strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, "'")
}

var pySecretRef = regexp.MustCompile(`\.ssh[/\\'"]|\bid_rsa\b|\bid_ed25519\b|\.npmrc\b|\.pypirc\b|\.aws/credentials|\.git-credentials|\.config/gcloud|Login Data|\b(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|PYPI_TOKEN|AWS_SECRET_ACCESS_KEY)\b`)

func pySecretNearSend(src string) bool {
	return pySecretRef.MatchString(src) && nearEither(pySecretRef, pyNetSend, src, exfilWindow)
}

func pyEncodedBlob(src string) bool {
	if len(src) <= 4000 || !containsAny(src, "exec", "eval") {
		return false
	}
	for _, start := range base64Runs(src, 4000) {
		if pyBlobExec.MatchString(src[max(0, start-160):start]) {
			return true
		}
	}
	return false
}

// scanBuild returns SI-BLD-002 hits for build code (setup.py, build hooks):
// what is suspicious anywhere is worse when it runs at every build.
func scanBuild(src string) []hit {
	switch {
	case pyCommandDownload(src):
		return []hit{{"SI-BLD-002", analyze.Block, "downloads and runs a program at build time"}}
	case containsAny(src, "exec", "eval", "compile", "marshal") && pyEvalAfterNetwork(src):
		return []hit{{"SI-BLD-002", analyze.Block, "evaluates code fetched at build time"}}
	case pyEncodedBlob(src):
		return []hit{{"SI-BLD-002", analyze.High, "evaluates a large encoded blob at build time"}}
	case pySecretNearSend(src):
		return []hit{{"SI-BLD-002", analyze.High, "reads credentials next to a network send at build time"}}
	}
	return nil
}

// knownPth are .pth files that are known and harmless (package, file name).
var knownPth = map[string]bool{
	"setuptools/distutils-precedence.pth": true,
}

// scanPth flags .pth lines that run code at every interpreter start.
func scanPth(pkg, name, src string) []hit {
	if knownPth[pkg+"/"+path.Base(name)] {
		return nil
	}
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "import ") && !strings.HasPrefix(line, "import\t") {
			continue
		}
		// Dangerous on top of running at startup: network, evaluation, processes.
		if pyEvalCall.MatchString(line) || pyNetCall.MatchString(line) || strings.Contains(line, "subprocess") ||
			containsAny(line, "b64decode", "base64", "zlib", "marshal", "os.system") {
			return []hit{{"SI-PTH-001", analyze.High, "runs code at every Python start, and evaluates, downloads or starts processes"}}
		}
		return []hit{{"SI-PTH-001", analyze.Medium, "runs code at every Python start"}}
	}
	return nil
}

// pyCollector scans the files of one Python archive.
type pyCollector struct {
	*collector
	pkg string
}

func (c pyCollector) add(rel string, data []byte, buildFile bool) bool {
	if c.total += int64(len(data)); c.total > maxPackageBytes {
		return false
	}
	src := string(data)
	var hits []hit
	switch {
	case strings.HasSuffix(rel, ".pth"):
		hits = scanPth(c.pkg, rel, src)
	case strings.HasSuffix(rel, ".py"):
		hits = scanPython(src)
		if buildFile {
			hits = append(hits, scanBuild(src)...)
		}
	}
	for _, h := range hits {
		a := c.byRule[h.rule]
		if a == nil {
			a = &agg{sev: h.sev, files: map[string]string{}}
			c.byRule[h.rule] = a
		}
		if h.sev > a.sev {
			a.sev = h.sev
		}
		a.files[rel] = h.what
	}
	return true
}

// isBuildFile: code that runs when an sdist is built (paths relative to the
// sdist's top directory): setup.py, build hooks, and other top-level scripts.
func isBuildFile(rel string) bool {
	if !strings.HasSuffix(rel, ".py") {
		return false
	}
	base := path.Base(rel)
	return !strings.Contains(rel, "/") || base == "setup.py" || strings.HasSuffix(base, "_build.py") || base == "build.py"
}

// PythonArchive scans a Python distribution file in memory: a wheel (zip) or
// an sdist (.tar.gz or .zip). pkg is the normalized project name; name is
// the file name, which says how to read it. Nothing is extracted to disk.
func PythonArchive(pkg, name string, data []byte) ([]analyze.Finding, error) {
	c := pyCollector{&collector{byRule: map[string]*agg{}}, pkg}
	sdist := !strings.HasSuffix(name, ".whl")
	visit := func(entry string, size int64, open func() (io.Reader, error)) error {
		rel, ok := safeRel(entry)
		if !ok || size > maxFileBytes || (!strings.HasSuffix(rel, ".py") && !strings.HasSuffix(rel, ".pth")) {
			return nil
		}
		if sdist {
			// Drop the sdist's top directory ("name-1.0/").
			_, after, found := strings.Cut(rel, "/")
			if !found {
				return nil
			}
			rel = after
		}
		r, err := open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(r, maxFileBytes))
		if err != nil {
			return err
		}
		build := sdist && isBuildFile(rel)
		if sdist && !build && notInstalled(rel) {
			return nil // maintainer tooling, tests, docs: never installed
		}
		if !c.add(rel, data, build) {
			return errBudget
		}
		return nil
	}
	var err error
	switch {
	case strings.HasSuffix(name, ".whl") || strings.HasSuffix(name, ".zip"):
		err = walkZip(data, visit)
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz"):
		err = walkTarGz(data, visit)
	default:
		return nil, fmt.Errorf("%s: unsupported archive", name)
	}
	if err != nil && !errors.Is(err, errBudget) {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return c.findings(), nil
}

var errBudget = errors.New("package byte budget spent")

// notInstalled: sdist folders that hold maintainer tooling, tests or docs,
// not the code an install puts in site-packages.
func notInstalled(rel string) bool {
	top, _, _ := strings.Cut(rel, "/")
	switch top {
	case "tools", "scripts", "ci", ".github", "docs", "doc", "tests", "test", "benchmarks", "examples", "dev":
		return true
	}
	return false
}

// safeRel cleans an archive path; absolute or escaping paths are refused.
func safeRel(name string) (string, bool) {
	p := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") || p == "." {
		return "", false
	}
	return p, true
}

type visitFunc func(entry string, size int64, open func() (io.Reader, error)) error

func walkZip(data []byte, visit visitFunc) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for i, f := range zr.File {
		if i >= maxTarEntries {
			break
		}
		if !f.Mode().IsRegular() {
			continue
		}
		// A hostile archive can claim any size: clamp before converting.
		size := int64(maxFileBytes + 1)
		if f.UncompressedSize64 <= maxFileBytes {
			size = int64(f.UncompressedSize64)
		}
		err := visit(f.Name, size, func() (io.Reader, error) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			b, err := io.ReadAll(io.LimitReader(rc, maxFileBytes))
			return bytes.NewReader(b), err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func walkTarGz(data []byte, visit visitFunc) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for n := 0; n < maxTarEntries; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if err := visit(h.Name, h.Size, func() (io.Reader, error) { return tr, nil }); err != nil {
			return err
		}
	}
	return nil
}
