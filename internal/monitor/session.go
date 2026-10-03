package monitor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
)

// Mode is how the monitor reacts to high-risk behavior.
type Mode string

// Modes.
const (
	ModeReport Mode = "report" // record and continue
	ModeKill   Mode = "kill"   // stop the script's process group on the first high-risk event
)

// Environment passed from safe-install to itself running as the script shell.
const (
	envLog     = "SAFE_INSTALL_MONITOR_LOG"
	envMode    = "SAFE_INSTALL_MONITOR_MODE"
	envProject = "SAFE_INSTALL_MONITOR_PROJECT"
	envActive  = "SAFE_INSTALL_MONITOR_ACTIVE" // set inside a traced script
)

// logPattern names session logs; only such files in the temp dir are written.
const logPattern = "safe-install-monitor-*.jsonl"

// Errors from Supported.
var (
	ErrUnsupportedOS = errors.New("runtime monitoring is Linux-only")
	ErrNoStrace      = errors.New("runtime monitoring needs strace (e.g. `sudo apt install strace`)")
)

// Record is one finding, as written to the session log.
type Record struct {
	Package  string `json:"package"` // name@version
	Stage    string `json:"stage"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Killed   bool   `json:"killed,omitempty"`
}

// High reports whether the record is high risk or worse.
func (r Record) High() bool {
	return r.Severity == analyze.High.String() || r.Severity == analyze.Block.String()
}

// Session is one monitored run of approved scripts.
type Session struct {
	Mode    Mode
	log     string
	project string
}

// NewSession prepares a monitored run for the project in dir.
func NewSession(dir string, mode Mode) (*Session, error) {
	if err := Supported(); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", logPattern)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return &Session{Mode: mode, log: f.Name(), project: dir}, nil
}

// ScriptShell is the executable package managers should run scripts with.
func (s *Session) ScriptShell() (string, error) {
	return os.Executable()
}

// Env is the environment the script shell needs.
func (s *Session) Env() []string {
	return []string{envLog + "=" + s.log, envMode + "=" + string(s.Mode), envProject + "=" + s.project}
}

// Records returns what the monitor saw so far.
func (s *Session) Records() ([]Record, error) { return ReadLog(s.log) }

// Close removes the session log.
func (s *Session) Close() error { return os.Remove(s.log) }

// ReadLog parses a session log.
func ReadLog(path string) ([]Record, error) {
	f, err := os.Open(path) // #nosec G304 -- our own session log
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return out, fmt.Errorf("monitor log: %w", err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// MaybeRunAsShell handles safe-install being invoked by a package manager as
// the script shell (`<shell> -c <script>`) inside a monitored session.
func MaybeRunAsShell(args []string) (int, bool) {
	if os.Getenv(envLog) == "" || len(args) < 3 || args[1] != "-c" {
		return 0, false
	}
	if os.Getenv(envActive) != "" {
		// A nested `npm run` inside a traced script: the outer strace already
		// follows this process, and a second one could not attach.
		return runPlain(args[1:]), true
	}
	return RunShell(args[1:]), true
}

func runPlain(args []string) int {
	cmd := exec.Command("/bin/sh", args...) // #nosec G204 -- the script npm asked us to run
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

// sessionLog returns the log path from the environment, only if it is one
// of our session logs in the temp dir.
func sessionLog() (string, error) {
	p := filepath.Clean(os.Getenv(envLog))
	if ok, _ := filepath.Match(logPattern, filepath.Base(p)); !ok || filepath.Dir(p) != filepath.Clean(os.TempDir()) {
		return "", fmt.Errorf("unexpected monitor log path %q", p)
	}
	return p, nil
}

func appendRecord(path string, r Record) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 G703 -- validated by sessionLog
	if err != nil {
		return err
	}
	data, _ := json.Marshal(r)
	_, werr := f.Write(append(data, '\n'))
	return errors.Join(werr, f.Close())
}

func packageLabel() string {
	name, ver := os.Getenv("npm_package_name"), os.Getenv("npm_package_version")
	if name == "" {
		dir, _ := os.Getwd()
		return filepath.Base(dir)
	}
	return strings.TrimSuffix(name+"@"+ver, "@")
}
