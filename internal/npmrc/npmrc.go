// Package npmrc reads registry settings the way npm, pnpm, bun and Yarn
// berry do: default and scoped registries, and per-host credentials.
//
// Credentials are matched like npm matches them: the longest configured
// "//host[:port]/path/" prefix of the request URL. Prefixes always end in
// "/", so a token is never sent to a look-alike host or anywhere else.
package npmrc

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// DefaultRegistry is the public npm registry.
const DefaultRegistry = "https://registry.npmjs.org"

// Config is the effective registry configuration for a project.
type Config struct {
	registry string            // default registry, no trailing slash
	scopes   map[string]string // "@scope" -> registry
	creds    map[string]*cred  // nerf-dart prefix ("//host/path/") -> credentials
}

type cred struct {
	token, auth, username, password string // password already decoded
}

// Load reads, lowest priority first: the user's .npmrc ($NPM_CONFIG_USERCONFIG
// or ~/.npmrc), the project's .npmrc, the project's .yarnrc.yml, then
// npm_config_registry. env looks up environment variables (os.Getenv).
func Load(dir string, env func(string) string) (*Config, error) {
	c := &Config{registry: DefaultRegistry, scopes: map[string]string{}, creds: map[string]*cred{}}

	user := firstNonEmpty(env("NPM_CONFIG_USERCONFIG"), env("npm_config_userconfig"))
	if user == "" {
		if home := firstNonEmpty(env("HOME"), env("USERPROFILE")); home != "" {
			user = filepath.Join(home, ".npmrc")
		}
	}
	for _, path := range []string{user, filepath.Join(dir, ".npmrc")} {
		if path == "" {
			continue
		}
		if err := c.readNpmrc(path, env); err != nil {
			return nil, err
		}
	}
	if err := c.readYarnrc(filepath.Join(dir, ".yarnrc.yml"), env); err != nil {
		return nil, err
	}
	if r := firstNonEmpty(env("npm_config_registry"), env("NPM_CONFIG_REGISTRY")); r != "" {
		c.registry = trimSlash(r)
	}
	return c, nil
}

// RegistryFor returns the registry serving package name.
func (c *Config) RegistryFor(name string) string {
	if scope, _, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		if r, ok := c.scopes[scope]; ok {
			return r
		}
	}
	return c.registry
}

// SetRegistry overrides the default registry (the --registry flag).
func (c *Config) SetRegistry(r string) { c.registry = trimSlash(r) }

// AuthFor returns the Authorization header value for rawURL, or "".
func (c *Config) AuthFor(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	target := "//" + strings.ToLower(u.Host) + u.EscapedPath()
	best := ""
	for prefix := range c.creds {
		if strings.HasPrefix(target, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best == "" {
		return ""
	}
	cr := c.creds[best]
	switch {
	case cr.token != "":
		return "Bearer " + cr.token
	case cr.auth != "":
		return "Basic " + cr.auth
	case cr.username != "" && cr.password != "":
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(cr.username+":"+cr.password))
	}
	return ""
}

// Hosts lists the hostnames of every configured registry.
func (c *Config) Hosts() []string {
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		if u, err := url.Parse(r); err == nil && u.Hostname() != "" && !seen[u.Hostname()] {
			seen[u.Hostname()] = true
			out = append(out, u.Hostname())
		}
	}
	add(c.registry)
	for _, r := range c.scopes {
		add(r)
	}
	sort.Strings(out)
	return out
}

func (c *Config) readNpmrc(path string, env func(string) string) error {
	f, err := os.Open(path) // #nosec G304 -- npm config file of the user or project
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		c.set(strings.TrimSpace(key), expand(unquote(strings.TrimSpace(value)), env))
	}
	return sc.Err()
}

func (c *Config) set(key, value string) {
	switch {
	case key == "registry":
		c.registry = trimSlash(value)
	case strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry"):
		c.scopes[strings.TrimSuffix(key, ":registry")] = trimSlash(value)
	case strings.HasPrefix(key, "//"):
		i := strings.LastIndex(key, ":")
		if i < 0 {
			return
		}
		cr := c.cred(key[:i])
		switch key[i+1:] {
		case "_authToken":
			cr.token = value
		case "_auth":
			cr.auth = value
		case "username":
			cr.username = value
		case "_password":
			if dec, err := base64.StdEncoding.DecodeString(value); err == nil {
				cr.password = string(dec)
			}
		}
	}
}

// cred returns the credentials for a nerf-dart prefix, normalized to end in "/".
func (c *Config) cred(prefix string) *cred {
	prefix = strings.ToLower(prefix)
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	cr, ok := c.creds[prefix]
	if !ok {
		cr = &cred{}
		c.creds[prefix] = cr
	}
	return cr
}

type yarnRegistry struct {
	Server string `yaml:"npmRegistryServer"`
	Token  string `yaml:"npmAuthToken"`
	Ident  string `yaml:"npmAuthIdent"` // "user:password"
}

func (c *Config) readYarnrc(path string, env func(string) string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- the project's .yarnrc.yml
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var y struct {
		Server     string                  `yaml:"npmRegistryServer"`
		Token      string                  `yaml:"npmAuthToken"`
		Ident      string                  `yaml:"npmAuthIdent"`
		Scopes     map[string]yarnRegistry `yaml:"npmScopes"`
		Registries map[string]yarnRegistry `yaml:"npmRegistries"`
	}
	if err := yaml.Unmarshal(data, &y); err != nil {
		return err
	}
	apply := func(server string, r yarnRegistry) {
		server = trimSlash(expand(server, env))
		if server == "" {
			return
		}
		cr := c.cred(nerfDart(server))
		if t := expand(r.Token, env); t != "" {
			cr.token = t
		}
		if id := expand(r.Ident, env); id != "" {
			cr.auth = base64.StdEncoding.EncodeToString([]byte(id))
		}
	}
	if y.Server != "" {
		c.registry = trimSlash(expand(y.Server, env))
	}
	apply(c.registry, yarnRegistry{Token: y.Token, Ident: y.Ident})
	for scope, r := range y.Scopes {
		server := c.registry
		if r.Server != "" {
			server = trimSlash(expand(r.Server, env))
		}
		c.scopes["@"+strings.TrimPrefix(scope, "@")] = server
		apply(server, r)
	}
	for server, r := range y.Registries {
		if strings.HasPrefix(server, "//") {
			server = "https:" + server
		}
		apply(server, r)
	}
	return nil
}

// nerfDart turns "https://host/path" into "//host/path/".
func nerfDart(registry string) string {
	u, err := url.Parse(registry)
	if err != nil {
		return ""
	}
	return "//" + u.Host + strings.TrimSuffix(u.EscapedPath(), "/") + "/"
}

var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expand(s string, env func(string) string) string {
	return envRe.ReplaceAllStringFunc(s, func(m string) string { return env(m[2 : len(m)-1]) })
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		if s[0] == '"' {
			if u, err := strconv.Unquote(s); err == nil {
				return u
			}
		}
		return s[1 : len(s)-1]
	}
	return s
}

func trimSlash(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
