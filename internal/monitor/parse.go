// Package monitor watches approved install scripts while they run (Linux,
// through strace) and reports, or stops, dangerous behavior.
package monitor

import (
	"regexp"
	"strconv"
	"strings"
)

// Kind of traced event.
type Kind int

// Event kinds.
const (
	Exec Kind = iota + 1
	Connect
	Open
	Rename
	Unlink
)

// Event is one relevant syscall made by a traced process.
type Event struct {
	PID   int
	Kind  Kind
	Path  string   // file, or executable for Exec
	Path2 string   // rename target
	Args  []string // Exec argv
	Addr  string   // Connect: ip:port
	Write bool     // Open: for writing or creating
}

var (
	lineRe   = regexp.MustCompile(`^(\d+)\s+([a-z0-9_]+)\((.*)$`)
	strRe    = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	portRe   = regexp.MustCompile(`sin6?_port=htons\((\d+)\)`)
	inet4Re  = regexp.MustCompile(`inet_addr\("([^"]+)"\)`)
	inet6Re  = regexp.MustCompile(`inet_pton\(AF_INET6, "([^"]+)"`)
	writeRe  = regexp.MustCompile(`\b(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b`)
	argvRe   = regexp.MustCompile(`^"(?:[^"\\]|\\.)*", \[(.*?)\](?:, |\))`)
	unescape = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t")
)

// Parse reads one line of `strace -f` output. Lines that are not a
// relevant syscall (resumptions, signals, exits, AF_UNIX sockets) are skipped.
func Parse(line string) (Event, bool) {
	m := lineRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	pid, _ := strconv.Atoi(m[1])
	ev := Event{PID: pid}
	args := m[3]
	strs := quoted(args)

	switch m[2] {
	case "execve", "execveat":
		if len(strs) == 0 {
			return Event{}, false
		}
		ev.Kind, ev.Path = Exec, strs[0]
		if a := argvRe.FindStringSubmatch(args); a != nil {
			ev.Args = quoted(a[1])
		}
	case "connect":
		port := portRe.FindStringSubmatch(args)
		if port == nil {
			return Event{}, false // AF_UNIX and friends
		}
		ev.Kind = Connect
		if ip := inet4Re.FindStringSubmatch(args); ip != nil {
			ev.Addr = ip[1] + ":" + port[1]
		} else if ip := inet6Re.FindStringSubmatch(args); ip != nil {
			ev.Addr = "[" + ip[1] + "]:" + port[1]
		} else {
			return Event{}, false
		}
	case "open", "openat", "openat2":
		if len(strs) == 0 {
			return Event{}, false
		}
		ev.Kind, ev.Path, ev.Write = Open, strs[0], writeRe.MatchString(args)
	case "creat":
		if len(strs) == 0 {
			return Event{}, false
		}
		ev.Kind, ev.Path, ev.Write = Open, strs[0], true
	case "rename", "renameat", "renameat2":
		if len(strs) < 2 {
			return Event{}, false
		}
		ev.Kind, ev.Path, ev.Path2 = Rename, strs[0], strs[1]
	case "unlink", "unlinkat":
		if len(strs) == 0 {
			return Event{}, false
		}
		ev.Kind, ev.Path = Unlink, strs[0]
	default:
		return Event{}, false
	}
	return ev, true
}

func quoted(s string) []string {
	var out []string
	for _, m := range strRe.FindAllStringSubmatch(s, -1) {
		out = append(out, unescape.Replace(m[1]))
	}
	return out
}
