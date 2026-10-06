//go:build linux

package sandbox

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The sandbox is irreversible, so tests run it in a child: this test binary,
// re-executed with SANDBOX_TEST_SCRIPT set.
func TestMain(m *testing.M) {
	if script := os.Getenv("SANDBOX_TEST_SCRIPT"); script != "" {
		p := Policy{
			Project:  os.Getenv("SANDBOX_TEST_PROJECT"),
			Package:  os.Getenv("SANDBOX_TEST_PACKAGE"),
			AllowNet: os.Getenv("SANDBOX_TEST_NET") == "1",
		}
		err := Exec(p, script) // only returns on failure
		_, _ = os.Stderr.WriteString("sandbox: " + err.Error() + "\n")
		os.Exit(126)
	}
	os.Exit(m.Run())
}

type world struct {
	home, project, pkg, tmp, marker string
	connects                        *atomic.Int32
	addr                            string
}

func setup(t *testing.T) world {
	t.Helper()
	if ABI() < abiTCP {
		t.Skipf("Landlock ABI %d: files and TCP need ABI %d", ABI(), abiTCP)
	}
	// HOME must be outside the temp folder, which the sandbox leaves writable
	// on purpose (build tools need it). Real home folders are.
	home, err := os.MkdirTemp(".", ".sandbox-home-*")
	if err != nil {
		t.Fatal(err)
	}
	home, _ = filepath.Abs(home)
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	w := world{home: home, project: t.TempDir(), tmp: t.TempDir(), connects: &atomic.Int32{}}
	w.pkg = filepath.Join(w.project, "node_modules", "dep")
	w.marker = filepath.Join(w.tmp, "out")
	for _, d := range []string{filepath.Join(w.home, ".ssh"), w.pkg, w.marker} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(w.home, ".ssh", "id_rsa"): "PRIVATE KEY",
		filepath.Join(w.home, ".bashrc"):        "# original\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			w.connects.Add(1)
			_ = c.Close()
		}
	}()
	w.addr = ln.Addr().String()
	return w
}

// run executes script in the sandbox with HOME and TMPDIR pointed at the test world.
func (w world) run(t *testing.T, script string, allowNet bool) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Dir = w.pkg
	net := "0"
	if allowNet {
		net = "1"
	}
	cmd.Env = append(os.Environ(),
		"SANDBOX_TEST_SCRIPT="+script, "SANDBOX_TEST_PROJECT="+w.project, "SANDBOX_TEST_PACKAGE="+w.pkg,
		"SANDBOX_TEST_NET="+net, "HOME="+w.home, "TMPDIR="+w.tmp, "MARKER="+w.marker)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	return string(out), code
}

func TestSandboxBlocksSecretsPersistenceAndNetwork(t *testing.T) {
	w := setup(t)
	host, port, _ := strings.Cut(w.addr, ":")
	script := `
cat "$HOME/.ssh/id_rsa" > "$MARKER/stolen" 2>/dev/null && echo READ-SSH
echo pwned >> "$HOME/.bashrc" 2>/dev/null && echo WROTE-BASHRC
node -e "const s=require('net').connect(` + port + `,'` + host + `',()=>{console.log('CONNECTED');process.exit(0)});s.on('error',()=>process.exit(0));setTimeout(()=>process.exit(0),1500)"
echo ok > package-file && echo WROTE-PACKAGE
echo ok > "$MARKER/tmpfile" && echo WROTE-TMP
cat /etc/hostname > /dev/null && echo READ-ETC
node -e "console.log('NODE-RUNS')"
`
	out, code := w.run(t, script, false)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, blocked := range []string{"READ-SSH", "WROTE-BASHRC", "CONNECTED"} {
		if strings.Contains(out, blocked) {
			t.Errorf("sandbox allowed %s:\n%s", blocked, out)
		}
	}
	for _, allowed := range []string{"WROTE-PACKAGE", "WROTE-TMP", "READ-ETC", "NODE-RUNS"} {
		if !strings.Contains(out, allowed) {
			t.Errorf("sandbox blocked %s (should be allowed):\n%s", allowed, out)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(w.home, ".bashrc")); string(data) != "# original\n" {
		t.Errorf(".bashrc changed: %q", data)
	}
	time.Sleep(100 * time.Millisecond)
	if n := w.connects.Load(); n != 0 {
		t.Errorf("%d TCP connection(s) got through", n)
	}
}

func TestSandboxAllowNet(t *testing.T) {
	w := setup(t)
	host, port, _ := strings.Cut(w.addr, ":")
	out, _ := w.run(t, `node -e "require('net').connect(`+port+`,'`+host+`',()=>{console.log('CONNECTED');process.exit(0)}).on('error',e=>{console.log(e.code);process.exit(0)})"`, true)
	if !strings.Contains(out, "CONNECTED") {
		t.Fatalf("--sandbox-net should allow TCP:\n%s", out)
	}
	if out, _ := w.run(t, `cat "$HOME/.ssh/id_rsa" && echo READ-SSH`, true); strings.Contains(out, "READ-SSH") {
		t.Fatalf("files must stay confined with the network allowed:\n%s", out)
	}
}

func TestSandboxHidesUserNpmrc(t *testing.T) {
	w := setup(t)
	out, _ := w.run(t, `echo "$NPM_CONFIG_USERCONFIG"`, false)
	if strings.TrimSpace(out) != "/dev/null" {
		t.Fatalf("NPM_CONFIG_USERCONFIG = %q", out)
	}
}

// Cache folders that hold executables (on PATH, or run later by npx) must not
// be writable: a script could plant a binary that later runs unsandboxed.
func TestSandboxProtectsExecutablesInCaches(t *testing.T) {
	w := setup(t)
	for _, d := range []string{".bun/bin", ".bun/install/cache", ".npm/_npx", ".npm/_cacache", ".local/share/pnpm"} {
		if err := os.MkdirAll(filepath.Join(w.home, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	script := `
echo x > "$HOME/.bun/bin/bun" 2>/dev/null && echo WROTE-BUN-BIN
echo x > "$HOME/.npm/_npx/evil" 2>/dev/null && echo WROTE-NPX
echo x > "$HOME/.local/share/pnpm/pnpm" 2>/dev/null && echo WROTE-PNPM-HOME
echo x > "$HOME/.bun/install/cache/ok" && echo WROTE-BUN-CACHE
echo x > "$HOME/.npm/_cacache/ok" && echo WROTE-NPM-CACHE
`
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Dir = w.pkg
	cmd.Env = append(os.Environ(),
		"SANDBOX_TEST_SCRIPT="+script, "SANDBOX_TEST_PROJECT="+w.project, "SANDBOX_TEST_PACKAGE="+w.pkg,
		"SANDBOX_TEST_NET=0", "HOME="+w.home, "TMPDIR="+w.tmp,
		"PATH="+filepath.Join(w.home, ".bun/bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput()
	for _, blocked := range []string{"WROTE-BUN-BIN", "WROTE-NPX", "WROTE-PNPM-HOME"} {
		if strings.Contains(string(out), blocked) {
			t.Errorf("sandbox allowed %s:\n%s", blocked, out)
		}
	}
	for _, allowed := range []string{"WROTE-BUN-CACHE", "WROTE-NPM-CACHE"} {
		if !strings.Contains(string(out), allowed) {
			t.Errorf("sandbox blocked %s (a real cache):\n%s", allowed, out)
		}
	}
}
