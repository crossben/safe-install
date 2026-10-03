//go:build linux

package monitor

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

var traced = "execve,execveat,connect,open,openat,openat2,creat,rename,renameat,renameat2,unlink,unlinkat"

// Supported reports whether monitoring can run here.
func Supported() error {
	if _, err := exec.LookPath("strace"); err != nil {
		return ErrNoStrace
	}
	return nil
}

// RunShell runs `/bin/sh -c <script>` (args: ["-c", script]) under strace,
// records findings to the session log and, in kill mode, stops the script's
// process group on the first high-risk event. Returns the script's exit code.
func RunShell(args []string) int {
	log, err := sessionLog()
	if err != nil {
		fmt.Fprintln(os.Stderr, "safe-install monitor:", err)
		return 1
	}
	mode := Mode(os.Getenv(envMode))
	stage := os.Getenv("npm_lifecycle_event")
	pkg := packageLabel()
	cwd, _ := os.Getwd()
	cls := NewClassifier(os.Getenv(envProject), cwd)

	r, w, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "safe-install monitor:", err)
		return 1
	}
	argv := append([]string{"-f", "-qq", "-s", "1024", "-e", "trace=" + traced, "-e", "signal=none", "-o", "/dev/fd/3", "--", "/bin/sh"}, args...)
	cmd := exec.Command("strace", argv...) // #nosec G204 -- fixed program; args are the approved script
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), envActive+"=1")
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-install monitor:", err)
		return 1
	}
	_ = w.Close()

	killed := false
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		ev, ok := Parse(sc.Text())
		if !ok {
			continue
		}
		f, ok := cls.Classify(ev)
		if !ok || seen[f.Rule+f.Message] {
			continue
		}
		seen[f.Rule+f.Message] = true
		rec := Record{Package: pkg, Stage: stage, Rule: f.Rule, Severity: f.Severity.String(), Message: f.Message}
		if mode == ModeKill && rec.High() && !killed {
			killed = true
			rec.Killed = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		if err := appendRecord(log, rec); err != nil {
			fmt.Fprintln(os.Stderr, "safe-install monitor:", err)
		}
		if killed {
			fmt.Fprintf(os.Stderr, "safe-install monitor: killed %s %s: %s\n", pkg, stage, f.Message)
		}
	}
	_ = r.Close()

	err = cmd.Wait()
	if killed {
		return 137
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}
