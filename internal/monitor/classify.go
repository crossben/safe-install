package monitor

import (
	"fmt"
	"net"
	"os"
	"path"
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
	// Resolvers are the system name servers (IPs). Only their DNS replies
	// name hosts: a script could otherwise send itself a forged reply to
	// make a connection look like it goes to a well-known host.
	Resolvers map[string]bool

	names map[string]string // IP -> host name, from DNS replies seen so far
}

// NewClassifier uses $HOME and the OS temp dir.
func NewClassifier(project, pkg string) *Classifier {
	home, _ := os.UserHomeDir()
	return &Classifier{Home: home, Project: project, Package: pkg, Temp: os.TempDir(), Resolvers: systemResolvers()}
}

// systemResolvers reads the nameserver lines of /etc/resolv.conf.
func systemResolvers() map[string]bool {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(string(data))
}

func parseResolvConf(data string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(strings.SplitN(f[1], "%", 2)[0]); ip != nil {
				out[ip.String()] = true
			}
		}
	}
	return out
}

// fromResolver reports whether a reply came from a system name server's
// port 53. Unprivileged processes cannot send from that address and port.
func (c *Classifier) fromResolver(from string) bool {
	host, port, err := net.SplitHostPort(from)
	if err != nil || port != "53" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && c.Resolvers[ip.String()]
}

// Classify returns the finding for ev, if it is worth reporting.
func (c *Classifier) Classify(ev Event) (Finding, bool) {
	switch ev.Kind {
	case Exec:
		name := path.Base(ev.Path)
		if networkTools[strings.TrimSuffix(name, ".exe")] {
			return Finding{"SI-MON-002", analyze.Medium, "runs " + clip(strings.Join(ev.Args, " "), 120)}, true
		}
	case DNS:
		if !c.fromResolver(ev.From) {
			return Finding{}, false
		}
		if c.names == nil {
			c.names = map[string]string{}
		}
		for ip, name := range ev.Answers {
			c.names[ip] = name
		}
		return Finding{}, false
	case Connect:
		host, port, err := net.SplitHostPort(ev.Addr)
		if err != nil || port == "53" {
			return Finding{}, false // DNS lookups
		}
		addr := net.JoinHostPort(host, port)
		if ip := net.ParseIP(host); ip != nil {
			// By name: one finding per host and port. (Address selection
			// connects to every resolved address, so a single request can
			// touch dozens of them.)
			if name := c.names[ip.String()]; name != "" {
				return Finding{"SI-MON-001", analyze.Medium, "connects to " + net.JoinHostPort(name, port)}, true
			}
		}
		return Finding{"SI-MON-001", analyze.Medium, "connects to " + addr}, true
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

// Paths come from strace, so they are always slash-separated Linux paths:
// the path package is used throughout, whatever OS this is compiled for.
func (c *Classifier) write(p, verb string) (Finding, bool) {
	if !path.IsAbs(p) {
		return Finding{}, false // relative: inside the package's working directory
	}
	p = path.Clean(p)
	switch {
	case c.under(p, persistence), strings.Contains(p, "/.git/hooks/"), prefixed(p, systemDirs):
		return Finding{"SI-MON-004", analyze.High, fmt.Sprintf("%s %s", verb, c.pretty(p))}, true
	case c.allowed(p):
		return Finding{}, false
	}
	return Finding{"SI-MON-005", analyze.Medium, fmt.Sprintf("%s %s, outside the project", verb, c.pretty(p))}, true
}

func (c *Classifier) allowed(p string) bool {
	for _, root := range []string{c.Project, c.Package, c.Temp, "/tmp", "/dev", "/proc", "/run/user"} {
		if root != "" && within(p, root) {
			return true
		}
	}
	return c.under(p, homeCaches)
}

// under reports whether p is one of the $HOME-relative entries
// (a trailing "/" means anything inside that directory).
func (c *Classifier) under(p string, entries []string) bool {
	if c.Home == "" || !within(p, c.Home) {
		return false
	}
	rel := strings.TrimPrefix(p, path.Clean(c.Home)+"/")
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

func (c *Classifier) pretty(p string) string {
	if c.Home != "" && within(p, c.Home) {
		return "~" + strings.TrimPrefix(p, path.Clean(c.Home))
	}
	return p
}

func within(p, root string) bool {
	root = path.Clean(root)
	return p == root || strings.HasPrefix(p, root+"/")
}

func prefixed(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p+"/", d) {
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
