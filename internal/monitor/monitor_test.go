package monitor

import (
	"os"
	"path/filepath"
	"slices"
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
