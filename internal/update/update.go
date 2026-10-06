// Package update tells the user when a newer safe-install release exists.
// It asks GitHub for the latest release at most once a day and sends
// nothing about the user or their project.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// LatestURL is GitHub's API for the newest published release.
const LatestURL = "https://api.github.com/repos/crossben/safe-install/releases/latest"

// ReleasesURL is where a release can be downloaded by hand.
const ReleasesURL = "https://github.com/crossben/safe-install/releases/latest"

// Interval between checks.
const Interval = 24 * time.Hour

type state struct {
	Checked time.Time `json:"checked"`
	Latest  string    `json:"latest"`
}

// Checker finds the latest release, through a small cache file.
type Checker struct {
	URL      string // LatestURL when empty
	CacheDir string // "" disables the cache (checks every time)
	HTTP     *http.Client
	Now      func() time.Time
}

// Latest returns the newest release's version ("0.3.0"), from the cache
// when it was checked less than Interval ago.
func (c *Checker) Latest(ctx context.Context) (string, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	file := ""
	if c.CacheDir != "" {
		file = filepath.Join(c.CacheDir, "latest.json")
		var st state
		if data, err := os.ReadFile(file); err == nil && json.Unmarshal(data, &st) == nil && // #nosec G304 -- our own cache file
			st.Latest != "" && now().Sub(st.Checked) < Interval && !now().Before(st.Checked) {
			return st.Latest, nil
		}
	}
	latest, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	if file != "" {
		data, _ := json.Marshal(state{Checked: now(), Latest: latest})
		if os.MkdirAll(c.CacheDir, 0o700) == nil {
			_ = os.WriteFile(file, data, 0o600)
		}
	}
	return latest, nil
}

func (c *Checker) fetch(ctx context.Context) (string, error) {
	url := c.URL
	if url == "" {
		url = LatestURL
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return "", err
	}
	v := strings.TrimPrefix(rel.TagName, "v")
	if _, ok := parse(v); !ok {
		return "", errors.New("unexpected release tag " + strconv.Quote(rel.TagName))
	}
	return v, nil
}

// Newer reports whether latest is a higher version than current. Anything
// that is not a plain x.y.z (dev builds, pre-releases) is never older.
func Newer(current, latest string) bool {
	c, ok1 := parse(strings.TrimPrefix(current, "v"))
	l, ok2 := parse(strings.TrimPrefix(latest, "v"))
	if !ok1 || !ok2 {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Hint says how to update a binary installed at exe.
func Hint(exe, goos string) string {
	p := strings.ToLower(strings.ReplaceAll(exe, `\`, "/"))
	switch {
	case strings.Contains(p, "/cellar/"), strings.Contains(p, "/caskroom/"),
		strings.Contains(p, "/homebrew/"), strings.Contains(p, "/linuxbrew/"):
		return "brew upgrade --cask safe-install"
	case strings.Contains(p, "/scoop/"):
		return "scoop update safe-install"
	case strings.Contains(p, "/go/bin/"):
		return "go install github.com/crossben/safe-install/cmd/safe-install@latest"
	case goos == "linux" && (p == "/usr/bin/safe-install" || p == "/usr/local/bin/safe-install"):
		return "download the .deb, .rpm or .apk from " + ReleasesURL
	}
	return "download it from " + ReleasesURL
}

// Notice is the message shown when latest is newer than current.
func Notice(current, latest string) string {
	exe, err := os.Executable()
	if err == nil {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
	}
	return fmt.Sprintf("safe-install %s is available (you have %s). Update: %s\n"+
		"(turn this check off with SAFE_INSTALL_NO_UPDATE_CHECK=1)",
		latest, current, Hint(exe, runtime.GOOS))
}
