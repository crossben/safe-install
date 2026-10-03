package monitor

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
)

// networkTools are programs an install script rarely needs and malware often uses.
var networkTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"ssh": true, "scp": true, "sftp": true, "ftp": true, "tftp": true, "telnet": true,
	"powershell": true, "pwsh": true,
}

// Secrets under $HOME (prefix match on the path relative to home).
var secrets = []string{
	".ssh/", ".npmrc", ".yarnrc", ".netrc", ".git-credentials", ".gnupg/",
	".aws/", ".azure/", ".config/gcloud/", ".kube/config", ".docker/config.json",
	".config/gh/hosts.yml", ".config/google-chrome/", ".config/chromium/",
	".config/BraveSoftware/", ".mozilla/", ".local/share/keyrings/",
}

// Persistence targets under $HOME: writing, moving or deleting them is how
// malware survives the install.
var persistence = []string{
	".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv",
	".config/fish/", ".ssh/", ".config/autostart/", ".config/systemd/", ".local/share/systemd/",
	".gitconfig", ".npmrc", ".yarnrc", ".pam_environment", ".xprofile", ".xinitrc",
}

// System locations no install script should write.
var systemDirs = []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/", "/var/spool/cron/", "/opt/"}

// Writable caches under $HOME used by package managers and native builds.
var homeCaches = []string{".npm/", ".cache/", ".yarn/", ".bun/", ".local/share/pnpm/", ".node-gyp/", ".pnpm-store/", ".electron/"}

// Finding is one monitored behavior.
type Finding struct {
	Rule     string
	Severity analyze.Severity
	Message  string
}

// Classifier turns events into findings for one script run.
type Classifier struct {
	Home, Project, Package, Temp string
}

// NewClassifier uses $HOME and the OS temp dir.
func NewClassifier(project, pkg string) *Classifier {
	home, _ := os.UserHomeDir()
	return &Classifier{Home: home, Project: project, Package: pkg, Temp: os.TempDir()}
}

// Classify returns the finding for ev, if it is worth reporting.
func (c *Classifier) Classify(ev Event) (Finding, bool) {
	switch ev.Kind {
	case Exec:
		name := filepath.Base(ev.Path)
		if networkTools[strings.TrimSuffix(name, ".exe")] {
			return Finding{"SI-MON-002", analyze.Medium, "runs " + clip(strings.Join(ev.Args, " "), 120)}, true
		}
	case Connect:
		host, port, err := net.SplitHostPort(ev.Addr)
		if err != nil || port == "53" {
			return Finding{}, false // DNS lookups
		}
		return Finding{"SI-MON-001", analyze.Medium, "connects to " + net.JoinHostPort(host, port)}, true
	case Open:
		if ev.Write {
			return c.write(ev.Path, "writes")
		}
		if c.under(ev.Path, secrets) {
			return Finding{"SI-MON-003", analyze.High, "reads " + c.pretty(ev.Path)}, true
		}
	case Rename:
		if f, ok := c.write(ev.Path, "moves"); ok && f.Severity == analyze.High {
			return f, ok
		}
		return c.write(ev.Path2, "writes")
	case Unlink:
		return c.write(ev.Path, "deletes")
	}
	return Finding{}, false
}

func (c *Classifier) write(path, verb string) (Finding, bool) {
	if !filepath.IsAbs(path) {
		return Finding{}, false // relative: inside the package's working directory
	}
	path = filepath.Clean(path)
	switch {
	case c.under(path, persistence), strings.Contains(path, "/.git/hooks/"), prefixed(path, systemDirs):
		return Finding{"SI-MON-004", analyze.High, fmt.Sprintf("%s %s", verb, c.pretty(path))}, true
	case c.allowed(path):
		return Finding{}, false
	}
	return Finding{"SI-MON-005", analyze.Medium, fmt.Sprintf("%s %s, outside the project", verb, c.pretty(path))}, true
}

func (c *Classifier) allowed(path string) bool {
	for _, root := range []string{c.Project, c.Package, c.Temp, "/tmp", "/dev", "/proc", "/run/user"} {
		if root != "" && within(path, root) {
			return true
		}
	}
	return c.under(path, homeCaches)
}

// under reports whether path is one of the $HOME-relative entries
// (a trailing "/" means anything inside that directory).
func (c *Classifier) under(path string, entries []string) bool {
	if c.Home == "" || !within(path, c.Home) {
		return false
	}
	rel := strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(c.Home)+"/")
	for _, e := range entries {
		if strings.HasSuffix(e, "/") {
			if strings.HasPrefix(rel+"/", e) {
				return true
			}
		} else if rel == e {
			return true
		}
	}
	return false
}

func (c *Classifier) pretty(path string) string {
	if c.Home != "" && within(path, c.Home) {
		return "~" + strings.TrimPrefix(path, c.Home)
	}
	return path
}

func within(path, root string) bool {
	root = filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func prefixed(path string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(path+"/", d) {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
