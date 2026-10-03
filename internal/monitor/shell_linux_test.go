//go:build linux

package monitor

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func needStrace(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not installed")
	}
}

// shellEnv points HOME at a temp dir so the test never touches the real one.
func shellEnv(t *testing.T, mode Mode) (home, log string) {
	t.Helper()
	home = t.TempDir()
	f, err := os.CreateTemp("", logPattern)
	if err != nil {
		t.Fatal(err)
	}
	log = f.Name()
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(log) })
	t.Setenv("HOME", home)
	t.Setenv(envLog, log)
	t.Setenv(envMode, string(mode))
	t.Setenv(envProject, t.TempDir())
	t.Setenv("npm_package_name", "evil-dep")
	t.Setenv("npm_package_version", "1.0.0")
	t.Setenv("npm_lifecycle_event", "postinstall")
	return home, log
}

func TestShellReports(t *testing.T) {
	needStrace(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	home, log := shellEnv(t, ModeReport)

	script := `curl -s -m 2 http://` + ln.Addr().String() + `/ >/dev/null; echo pwned >> "$HOME/.bashrc"; exit 0`
	if code := RunShell([]string{"-c", script}); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	recs, err := ReadLog(log)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, r := range recs {
		rules[r.Rule] = true
		if r.Package != "evil-dep@1.0.0" || r.Stage != "postinstall" {
			t.Errorf("record context: %+v", r)
		}
	}
	for _, want := range []string{"SI-MON-001", "SI-MON-002", "SI-MON-004"} {
		if !rules[want] {
			t.Errorf("missing %s in %+v", want, recs)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(home, ".bashrc")); !strings.Contains(string(data), "pwned") {
		t.Error("report mode should not interfere with the script")
	}
}

func TestShellKills(t *testing.T) {
	needStrace(t)
	home, log := shellEnv(t, ModeKill)
	after := filepath.Join(home, "after")
	script := `echo pwned >> "$HOME/.bashrc"; sleep 2; touch "` + after + `"`
	if code := RunShell([]string{"-c", script}); code == 0 {
		t.Fatal("killed script reported success")
	}
	if _, err := os.Stat(after); !os.IsNotExist(err) {
		t.Fatal("script kept running after a high-risk action")
	}
	recs, _ := ReadLog(log)
	killed := false
	for _, r := range recs {
		killed = killed || r.Killed
	}
	if !killed {
		t.Fatalf("no kill recorded: %+v", recs)
	}
}

func TestShellPassesExitCode(t *testing.T) {
	needStrace(t)
	shellEnv(t, ModeReport)
	if code := RunShell([]string{"-c", "exit 7"}); code != 7 {
		t.Fatalf("exit = %d, want 7", code)
	}
}
