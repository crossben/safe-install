package cli

import (
	"bufio"
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/crossben/safe-install/internal/lockfile"
)

// pythonIndexHosts returns the hosts of the package indexes a Python project
// is configured to use besides PyPI: pyproject.toml and uv.toml (uv),
// Pipfile sources, requirements.txt index options, and the UV_* and PIP_*
// environment variables. safe-install never contacts these indexes (no
// credentials are needed or used); the hosts only count as configured.
func pythonIndexHosts(dir string, getenv func(string) string) []string {
	var urls []string
	readTOML := func(name string, v any) bool {
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- the project's own config
		return err == nil && toml.Unmarshal(data, v) == nil
	}
	type index struct {
		URL string `toml:"url"`
	}
	var pp struct {
		Tool struct {
			UV struct {
				Index         []index  `toml:"index"`
				IndexURL      string   `toml:"index-url"`
				ExtraIndexURL []string `toml:"extra-index-url"`
			} `toml:"uv"`
			Poetry struct {
				Source []index `toml:"source"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if readTOML("pyproject.toml", &pp) {
		for _, i := range pp.Tool.UV.Index {
			urls = append(urls, i.URL)
		}
		for _, i := range pp.Tool.Poetry.Source {
			urls = append(urls, i.URL)
		}
		urls = append(append(urls, pp.Tool.UV.IndexURL), pp.Tool.UV.ExtraIndexURL...)
	}
	var uvToml struct {
		Index         []index  `toml:"index"`
		IndexURL      string   `toml:"index-url"`
		ExtraIndexURL []string `toml:"extra-index-url"`
	}
	if readTOML("uv.toml", &uvToml) {
		for _, i := range uvToml.Index {
			urls = append(urls, i.URL)
		}
		urls = append(append(urls, uvToml.IndexURL), uvToml.ExtraIndexURL...)
	}
	var pipfile struct {
		Source []index `toml:"source"`
	}
	if readTOML("Pipfile", &pipfile) {
		for _, i := range pipfile.Source {
			urls = append(urls, i.URL)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "requirements.txt")); err == nil { // #nosec G304 -- the project's own file
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			if m := indexOption.FindStringSubmatch(sc.Text()); m != nil {
				urls = append(urls, m[1])
			}
		}
	}
	for _, env := range []string{"UV_INDEX", "UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"} {
		for _, v := range strings.Fields(getenv(env)) {
			// UV_INDEX entries may be "name=url".
			if _, after, ok := strings.Cut(v, "="); ok && strings.Contains(after, "://") {
				v = after
			}
			urls = append(urls, v)
		}
	}
	var hosts []string
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Hostname() == "" {
			continue
		}
		if h := strings.ToLower(u.Hostname()); !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

var indexOption = regexp.MustCompile(`^\s*(?:-i|--index-url|--extra-index-url)[=\s]+(\S+)`)

// otherIndexPackages marks packages resolved from a configured non-PyPI
// index as not checkable against PyPI (they are skipped, not "unpublished"),
// and returns how many and from which hosts.
func otherIndexPackages(g *lockfile.Graph, indexHosts []string) (int, []string) {
	n := 0
	var seen []string
	for _, p := range g.Packages {
		u, err := url.Parse(p.Resolved)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "pypi.org" || host == "files.pythonhosted.org" || !slices.Contains(indexHosts, host) {
			continue
		}
		p.Resolved = "index:" + p.Resolved // not a registry URL: skipped by the analysis
		n++
		if !slices.Contains(seen, host) {
			seen = append(seen, host)
		}
	}
	slices.Sort(seen)
	return n, seen
}
