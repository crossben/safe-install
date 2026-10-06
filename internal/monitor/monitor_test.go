package monitor

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
)

func TestParse(t *testing.T) {
	tests := []struct {
		line string
		want Event
	}{
		{`270315 execve("/usr/bin/curl", ["curl", "-s", "http://x/\"q\""], 0x6291 /* 140 vars */) = 0`,
			Event{PID: 270315, Kind: Exec, Path: "/usr/bin/curl", Args: []string{"curl", "-s", `http://x/"q"`}}},
		{`270315 connect(5, {sa_family=AF_INET, sin_port=htons(18765), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)`,
			Event{PID: 270315, Kind: Connect, Addr: "127.0.0.1:18765"}},
		{`12 connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::1", &sin6_addr), sin6_scope_id=0}, 28) = 0`,
			Event{PID: 12, Kind: Connect, Addr: "[2606:4700::1]:443"}},
		{`270314 openat(AT_FDCWD, "/home/u/.bashrc", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3`,
			Event{PID: 270314, Kind: Open, Path: "/home/u/.bashrc", Write: true}},
		{`270317 openat(AT_FDCWD, "/home/u/.ssh/id_rsa", O_RDONLY) = 3`,
			Event{PID: 270317, Kind: Open, Path: "/home/u/.ssh/id_rsa"}},
		{`5 open("/etc/hosts", O_RDONLY|O_CLOEXEC) = 3`,
			Event{PID: 5, Kind: Open, Path: "/etc/hosts"}},
		{`5 creat("/etc/cron.d/x", 0644) = -1 EACCES (Permission denied)`,
			Event{PID: 5, Kind: Open, Path: "/etc/cron.d/x", Write: true}},
		{`270318 renameat2(AT_FDCWD, "/home/u/.bashrc", AT_FDCWD, "/home/u/.profile", RENAME_NOREPLACE) = 0`,
			Event{PID: 270318, Kind: Rename, Path: "/home/u/.bashrc", Path2: "/home/u/.profile"}},
		{`9 rename("/a", "/b") = 0`, Event{PID: 9, Kind: Rename, Path: "/a", Path2: "/b"}},
		{`9 unlinkat(AT_FDCWD, "/home/u/.ssh/known_hosts", 0) = 0`, Event{PID: 9, Kind: Unlink, Path: "/home/u/.ssh/known_hosts"}},
	}
	for _, tt := range tests {
		got, ok := Parse(tt.line)
		if !ok {
			t.Errorf("Parse(%q) failed", tt.line)
			continue
		}
		if got.PID != tt.want.PID || got.Kind != tt.want.Kind || got.Path != tt.want.Path || got.Path2 != tt.want.Path2 ||
			got.Addr != tt.want.Addr || got.Write != tt.want.Write || !slices.Equal(got.Args, tt.want.Args) {
			t.Errorf("Parse(%q)\n got %+v\nwant %+v", tt.line, got, tt.want)
		}
	}
	for _, skip := range []string{
		`12 <... connect resumed>) = 0`,
		`12 connect(3, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 110) = 0`,
		`+++ exited with 0 +++`,
		`garbage`,
	} {
		if _, ok := Parse(skip); ok {
			t.Errorf("Parse(%q) should be skipped", skip)
		}
	}
}

func TestClassify(t *testing.T) {
	home := "/home/u"
	c := &Classifier{Home: home, Project: "/work/app", Package: "/work/app/node_modules/x", Temp: "/tmp"}
	tests := []struct {
		ev   Event
		rule string
		sev  analyze.Severity
	}{
		{Event{Kind: Exec, Path: "/usr/bin/curl", Args: []string{"curl", "-s", "https://x"}}, "SI-MON-002", analyze.Medium},
		{Event{Kind: Connect, Addr: "93.184.216.34:443"}, "SI-MON-001", analyze.Medium},
		{Event{Kind: Open, Path: home + "/.ssh/id_rsa"}, "SI-MON-003", analyze.High},
		{Event{Kind: Open, Path: home + "/.npmrc"}, "SI-MON-003", analyze.High},
		{Event{Kind: Open, Path: home + "/.aws/credentials"}, "SI-MON-003", analyze.High},
		{Event{Kind: Open, Path: home + "/.bashrc", Write: true}, "SI-MON-004", analyze.High},
		{Event{Kind: Open, Path: home + "/.config/systemd/user/x.service", Write: true}, "SI-MON-004", analyze.High},
		{Event{Kind: Open, Path: "/etc/cron.d/x", Write: true}, "SI-MON-004", analyze.High},
		{Event{Kind: Open, Path: "/work/app/.git/hooks/pre-commit", Write: true}, "SI-MON-004", analyze.High},
		{Event{Kind: Rename, Path: home + "/.bashrc", Path2: home + "/.bashrc.bak"}, "SI-MON-004", analyze.High},
		{Event{Kind: Unlink, Path: home + "/.ssh/known_hosts"}, "SI-MON-004", analyze.High},
		{Event{Kind: Open, Path: home + "/Documents/notes.txt", Write: true}, "SI-MON-005", analyze.Medium},
	}
	for _, tt := range tests {
		f, ok := c.Classify(tt.ev)
		if !ok || f.Rule != tt.rule || f.Severity != tt.sev {
			t.Errorf("Classify(%+v) = %+v, %v; want %s/%s", tt.ev, f, ok, tt.rule, tt.sev)
		}
	}
	ignored := []Event{
		{Kind: Exec, Path: "/bin/sh", Args: []string{"sh", "-c", "node install.js"}},
		{Kind: Exec, Path: "/usr/bin/node", Args: []string{"node", "install.js"}},
		{Kind: Connect, Addr: "127.0.0.53:53"}, // DNS
		{Kind: Open, Path: "/etc/hosts"},       // reading /etc is fine
		{Kind: Open, Path: "/work/app/node_modules/x/build/out.node", Write: true},
		{Kind: Open, Path: "/work/app/node_modules/.cache/y", Write: true},
		{Kind: Open, Path: "/tmp/abc", Write: true},
		{Kind: Open, Path: home + "/.cache/ms-playwright/x", Write: true},
		{Kind: Open, Path: home + "/.node-gyp/24/include.h", Write: true},
		{Kind: Open, Path: "/dev/null", Write: true},
		{Kind: Open, Path: "relative/out.o", Write: true},
	}
	for _, ev := range ignored {
		if f, ok := c.Classify(ev); ok {
			t.Errorf("Classify(%+v) = %+v, want ignored", ev, f)
		}
	}
}

func TestClassifierFromEnvHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the monitor only runs on Linux, where HOME is a slash path")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	c := NewClassifier("/p", "/p/node_modules/x")
	if f, ok := c.Classify(Event{Kind: Open, Path: filepath.Join(home, ".bashrc"), Write: true}); !ok || f.Rule != "SI-MON-004" {
		t.Fatalf("got %+v %v", f, ok)
	}
}

func TestSessionLogPathIsValidated(t *testing.T) {
	good := filepath.Join(os.TempDir(), "safe-install-monitor-123.jsonl")
	for path, ok := range map[string]bool{
		good:                                   true,
		"/home/u/.bashrc":                      false,
		filepath.Join(os.TempDir(), "x.jsonl"): false,
		"/elsewhere/safe-install-monitor-1.jsonl": false,
	} {
		t.Setenv(envLog, path)
		if _, err := sessionLog(); (err == nil) != ok {
			t.Errorf("sessionLog(%q) err = %v, want ok=%v", path, err, ok)
		}
	}
}

func readLine(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// Real strace output of a DNS lookup of registry.npmjs.org.
func TestParseDNSAnswers(t *testing.T) {
	ev, ok := Parse(readLine(t, "dns-a.txt"))
	if !ok || ev.Kind != DNS {
		t.Fatalf("A reply not parsed: %+v %v", ev, ok)
	}
	if ev.From != "127.0.0.53:53" {
		t.Fatalf("From = %q", ev.From)
	}
	if ev.Answers["104.16.1.34"] != "registry.npmjs.org" || len(ev.Answers) < 4 {
		t.Fatalf("answers = %v", ev.Answers)
	}
	ev, ok = Parse(readLine(t, "dns-aaaa.txt"))
	if !ok || ev.Answers["2606:4700::6810:122"] != "registry.npmjs.org" {
		t.Fatalf("AAAA answers = %v (%v)", ev.Answers, ok)
	}
	if _, ok := Parse(readLine(t, "netlink.txt")); ok {
		t.Fatal("a netlink recvmsg was taken for DNS")
	}
}

func TestConnectNamesTheHost(t *testing.T) {
	c := &Classifier{Home: "/home/u", Resolvers: map[string]bool{"127.0.0.53": true}}
	c.Classify(Event{Kind: DNS, From: "127.0.0.53:53", Answers: map[string]string{"104.16.1.34": "registry.npmjs.org", "2606:4700::6810:122": "registry.npmjs.org"}})
	for addr, want := range map[string]string{
		"104.16.1.34:443":           "connects to registry.npmjs.org:443",
		"[2606:4700::6810:122]:443": "connects to registry.npmjs.org:443",
		"93.184.216.34:80":          "connects to 93.184.216.34:80",
	} {
		f, ok := c.Classify(Event{Kind: Connect, Addr: addr})
		if !ok || f.Message != want {
			t.Errorf("%s: %q, want %q", addr, f.Message, want)
		}
	}
}

func TestDecodeCEscapes(t *testing.T) {
	got := decodeC(`a\0\10\271\x41\n\t\"\\z`)
	want := []byte{'a', 0, 8, 0o271, 'A', '\n', '\t', '"', '\\', 'z'}
	if string(got) != string(want) {
		t.Fatalf("decodeC = %v, want %v", got, want)
	}
}

func TestParseDNSHostile(_ *testing.T) {
	// Truncated, looping compression pointers, garbage: never panic.
	for _, b := range [][]byte{nil, {1, 2, 3}, append(make([]byte, 12), 0xc0, 0x0c), {0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2}} {
		_ = parseDNS(b)
	}
}

func FuzzParseDNS(f *testing.F) {
	for _, name := range []string{"dns-a.txt", "dns-aaaa.txt"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		if raw, _, ok := rawQuoted(string(data)); ok {
			f.Add(decodeC(raw))
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) { _ = parseDNS(b) })
}

// A script can send itself a DNS-shaped packet: only replies from a system
// resolver's port 53 may name a host.
func TestForgedDNSDoesNotNameHosts(t *testing.T) {
	c := &Classifier{Resolvers: parseResolvConf("# x\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\n")}
	if !c.Resolvers["fe80::1"] {
		t.Fatalf("resolvers = %v", c.Resolvers)
	}
	forged := map[string]string{"6.6.6.6": "registry.npmjs.org"}
	for _, from := range []string{"6.6.6.6:53", "127.0.0.53:5353", "127.0.0.1:53", ""} {
		c.Classify(Event{Kind: DNS, From: from, Answers: forged})
	}
	if f, _ := c.Classify(Event{Kind: Connect, Addr: "6.6.6.6:443"}); f.Message != "connects to 6.6.6.6:443" {
		t.Fatalf("forged reply named the host: %q", f.Message)
	}
	// The sender must come from strace's address, not from the payload.
	line := `5 recvfrom(3, "sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")", 64, 0, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("6.6.6.6")}, [16]) = 40`
	if ev, ok := Parse(line); ok && ev.From != "6.6.6.6:4444" {
		t.Fatalf("From taken from the payload: %q", ev.From)
	}
}
