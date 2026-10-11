package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/codescan"
	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/pm"
	"github.com/crossben/safe-install/internal/policy"
)

// Python installs (uv). The model mirrors npm's: nothing that runs code
// during install (building an sdist) happens unless it was reviewed and
// approved, approvals are pinned to the sdist's sha256, and every other
// package is installed from wheels only.

// uvCommand starts uv; replaced in tests.
var uvCommand = func(dir string, env []string, args ...string) *exec.Cmd {
	c := exec.Command("uv", args...) // #nosec G204 -- fixed binary, arguments built by safe-install
	c.Dir = dir
	c.Env = append(os.Environ(), env...)
	return c
}

// A build uv refused because of --no-build(-package).
var uvNoBuild = regexp.MustCompile("Distribution `([A-Za-z0-9._-]+)==[^ `]+[^`]*` can't be installed because it is marked as `--no-build`")

// maxBuildRounds bounds the sync → refused build → ask → sync loop.
const maxBuildRounds = 20

type pyBuild struct {
	pkg      *lockfile.Package
	sdistSHA string // hex, from the lockfile
	res      analyze.Result
	approved bool // recorded in the policy, or answered now
}

func runPythonInstall(cmd *cobra.Command, g *globalFlags, pmArgs []string, add bool, pol *policy.Policy, dir string, det pm.Detection) error {
	if det.Kind != pm.UV {
		return fmt.Errorf("installing %s projects is not supported yet: safe-install installs Python projects with uv (uv.lock). `safe-install check` works for %s", det.Kind, det.Source)
	}
	if _, err := exec.LookPath("uv"); err != nil {
		return errors.New("uv is not on your PATH: install it (https://docs.astral.sh/uv/) to install this project")
	}
	minAge, err := parseMinAge(g.minAge)
	if err != nil {
		return err
	}
	w := &lineWriter{w: cmd.ErrOrStderr()}
	gate := "release-age gate off"
	if minAge > 0 {
		gate = "new versions must be " + g.minAge + " old"
	}
	w.printf("safe-install: using uv (%s); source builds need approval; %s\n", det.Source, gate)

	run := func(env []string, args ...string) (string, error) {
		c := uvCommand(dir, env, args...)
		var stderr bytes.Buffer
		c.Stdout = cmd.OutOrStdout()
		c.Stderr = io.MultiWriter(cmd.ErrOrStderr(), &stderr)
		err := c.Run()
		return stderr.String(), err
	}
	// 1. Resolve without installing anything. uv's own --exclude-newer is
	// not used: uv records it in uv.lock, and every later sync without it
	// re-resolves. Instead, new resolutions are checked here and undone if
	// they picked a version younger than the minimum age.
	lockPath := filepath.Join(dir, "uv.lock")
	before := snapshot(lockPath, filepath.Join(dir, "pyproject.toml"))
	switch {
	case add:
		if _, err := run(nil, append([]string{"add", "--no-sync"}, pmArgs...)...); err != nil {
			before.restore()
			return fmt.Errorf("uv add: %w", err)
		}
	case !g.frozen:
		if _, err := run(nil, "lock"); err != nil {
			return fmt.Errorf("uv lock: %w", err)
		}
	}
	graph, err := lockfile.LoadFile(lockPath)
	if err != nil {
		return fmt.Errorf("uv.lock: %w", err)
	}
	if minAge > 0 {
		var old *lockfile.Graph
		if data, ok := before[lockPath]; ok && data != nil {
			old, _ = lockfile.Parse("uv.lock", data, dir)
		}
		if fresh := freshVersions(cmd, g, pol, lockfile.Changed(old, graph)); len(fresh) > 0 {
			before.restore()
			w.printf("safe-install: these versions are younger than %s, so nothing was changed or installed:\n", g.minAge)
			for _, f := range fresh {
				w.printf("  %s\n", f)
			}
			w.printf("Pin an older version, wait, or pass --min-age 0 if you are sure.\n")
			return &exitError{ExitPolicyFailure, fmt.Errorf("%d fresh version(s) refused (--min-age %s)", len(fresh), g.minAge)}
		}
	}

	// 2. Packages that will be built: no wheel at all in the lock (more may
	// turn up when uv finds no wheel for this platform).
	builds := map[string]*pyBuild{}
	for _, p := range graph.Sorted() {
		if sha, ok := sdistOnly(p); ok {
			builds[p.Name] = &pyBuild{pkg: p, sdistSHA: sha}
		}
	}
	session := &pySession{cmd: cmd, g: g, pol: pol, w: w}
	if err := session.review(builds); err != nil {
		return err
	}

	// 3. Sync from wheels, letting only approved packages build.
	for round := 0; ; round++ {
		deny := denyList(graph, builds)
		stderr, err := run([]string{"UV_NO_BUILD_PACKAGE=" + strings.Join(deny, " ")}, "sync", "--locked")
		if err == nil {
			break
		}
		m := uvNoBuild.FindStringSubmatch(stderr)
		if m == nil || round >= maxBuildRounds {
			return fmt.Errorf("uv sync: %w", err)
		}
		name := ecosystem.Normalize(ecosystem.PyPI, m[1])
		p := findByName(graph, name)
		if p == nil || builds[name] != nil {
			// Refused and already reviewed (declined), or unknown: stop here.
			w.printf("safe-install: %s needs to be built from source and was not approved; nothing else was installed\n", m[1])
			return &exitError{ExitPolicyFailure, fmt.Errorf("%s was not approved to build", m[1])}
		}
		// No wheel for this platform: review it like the others, then retry.
		sha, _ := sdistOf(p)
		b := &pyBuild{pkg: p, sdistSHA: sha}
		builds[name] = b
		if err := session.review(map[string]*pyBuild{name: b}); err != nil {
			return err
		}
	}

	// 4. After install: .pth files that run code at every Python start.
	pth := pthFindings(dir, projectName(dir))
	for _, f := range pth {
		w.printf("safe-install: %s  %s\n", f.Rule, f.Message)
	}
	var built []string
	for _, b := range builds {
		if b.approved {
			built = append(built, b.pkg.ID)
		}
	}
	sort.Strings(built)
	w.printf("safe-install: installed from wheels; built from source after approval: %s\n", listOrNone(built))
	if g.ci {
		for _, f := range pth {
			if f.Severity >= analyze.High {
				return &exitError{ExitPolicyFailure, errors.New(f.Message)}
			}
		}
	}
	return w.err
}

// sdistOnly: the lock pins only an sdist for p (no wheel), with its sha256.
func sdistOnly(p *lockfile.Package) (string, bool) {
	sha, ok := sdistOf(p)
	if !ok {
		return "", false
	}
	for _, f := range p.Files {
		if strings.HasSuffix(f.Name, ".whl") {
			return "", false
		}
	}
	return sha, true
}

func sdistOf(p *lockfile.Package) (string, bool) {
	for _, f := range p.Files {
		if strings.HasSuffix(f.Name, ".tar.gz") || strings.HasSuffix(f.Name, ".zip") {
			_, sum, _ := strings.Cut(f.Hash, ":")
			return strings.ToLower(sum), true
		}
	}
	return "", false
}

func findByName(g *lockfile.Graph, name string) *lockfile.Package {
	for _, p := range g.Sorted() {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// denyList is every locked package except those approved to build: uv may
// build nothing else, whatever wheels exist for this platform.
func denyList(g *lockfile.Graph, builds map[string]*pyBuild) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range g.Sorted() {
		if b := builds[p.Name]; (b != nil && b.approved) || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, p.Name)
	}
	return out
}

type pySession struct {
	cmd *cobra.Command
	g   *globalFlags
	pol *policy.Policy
	w   *lineWriter
}

// review analyzes the packages that would be built (registry rules and a
// scan of the sdist's build code) and approves them from the policy, the
// --yes flag, or the person at the terminal.
func (s *pySession) review(builds map[string]*pyBuild) error {
	if len(builds) == 0 {
		return nil
	}
	sub := &lockfile.Graph{Format: lockfile.UV, Packages: map[string]*lockfile.Package{}}
	for _, b := range builds {
		sub.Packages[b.pkg.ID] = b.pkg
	}
	minAge, _ := parseMinAge(s.g.minAge)
	fetcher, err := newFetcherFor(s.g, ecosystem.PyPI)
	if err != nil {
		return err
	}
	cfg := analysisConfig(s.g, s.pol, minAge)
	cfg.RegistryHosts, cfg.Downloads = pypiHosts(), nil
	rep := analyze.Analyze(s.cmd.Context(), sub, fetcher, cfg)
	deepScan(s.cmd, s.g, rep)
	for _, w := range rep.Warnings {
		s.w.printf("safe-install: %s\n", w)
	}
	byID := map[string]analyze.Result{}
	for _, r := range rep.Results {
		byID[r.Package.ID] = r
	}

	var pending []*pyBuild
	names := make([]string, 0, len(builds))
	for n := range builds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := builds[n]
		b.res = byID[b.pkg.ID]
		if a, _, ok := s.pol.Lookup(b.pkg.Name); ok && a.Hash == "sha256:"+b.sdistSHA && !a.Expired(time.Now()) && !s.pol.Blocked(b.pkg.Name) {
			b.approved = true
			continue
		}
		pending = append(pending, b)
	}
	if len(pending) == 0 {
		return nil
	}
	w := s.w
	switch {
	case s.g.yes:
		for _, b := range pending {
			b.approved = b.res.Level < analyze.LevelHigh
		}
	case !s.g.ci && isInteractive():
		in := bufio.NewReader(s.cmd.InOrStdin())
		w.printf("\n%d package(s) must be built from source (their build code runs on your machine).\n", len(pending))
		for _, b := range pending {
			describePyBuild(w, b)
			w.printf("Build it? [y]es and remember / [o]nce / [N]o: ")
			line, err := in.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				if err := policy.Approve(s.pol.ProjectPath, b.pkg.Name, policy.Approval{Version: b.pkg.Version, Hash: "sha256:" + b.sdistSHA}); err != nil {
					return err
				}
				b.approved = true
			case "o", "once":
				b.approved = true
			}
		}
	default:
		for _, b := range pending {
			w.printf("\nsafe-install: %s must be built from source and is not approved\n", b.pkg.ID)
			describePyBuild(w, b)
		}
		w.printf("Review and approve with `safe-install approve <package>` after checking the findings above.\n")
	}
	if s.g.ci {
		for _, b := range pending {
			if !b.approved && b.res.Level >= analyze.LevelHigh {
				return &exitError{ExitPolicyFailure, fmt.Errorf("%s is %s risk and must be built from source", b.pkg.ID, b.res.Level)}
			}
		}
	}
	return w.err
}

func describePyBuild(w *lineWriter, b *pyBuild) {
	w.printf("\n%s  risk: %s\n", b.pkg.ID, strings.ToUpper(b.res.Level.String()))
	for _, f := range b.res.Findings {
		if f.Rule != "SI-BLD-001" {
			w.printf("  ! %s  %s\n", f.Rule, f.Message)
		}
	}
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

// projectName reads [project].name from pyproject.toml (normalized).
func projectName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")) // #nosec G304 -- the project's manifest
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([^"']+)["']`).FindSubmatch(data)
	if m == nil {
		return ""
	}
	return ecosystem.Normalize(ecosystem.PyPI, string(m[1]))
}

// pthFindings checks the .pth files at the top of the environment's
// site-packages (only those are processed at startup), naming the package
// whose RECORD lists each. The project's own (an editable install) is skipped.
func pthFindings(dir, project string) []analyze.Finding {
	var sites []string
	for _, pattern := range []string{".venv/lib/python*/site-packages", ".venv/Lib/site-packages"} {
		m, _ := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
		sites = append(sites, m...)
	}
	var out []analyze.Finding
	for _, site := range sites {
		owners := pthOwners(site)
		pths, _ := filepath.Glob(filepath.Join(site, "*.pth"))
		for _, p := range pths {
			info, err := os.Lstat(p)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
				continue
			}
			owner := owners[filepath.Base(p)]
			if owner == "" {
				owner = "an unknown package"
			}
			if project != "" && owner == project {
				continue
			}
			data, err := os.ReadFile(p) // #nosec G304 -- a file of the project's own environment
			if err != nil {
				continue
			}
			// uv/virtualenv create this one with the environment itself.
			if owners[filepath.Base(p)] == "" && filepath.Base(p) == "_virtualenv.pth" && strings.TrimSpace(string(data)) == "import _virtualenv" {
				continue
			}
			out = append(out, codescan.Pth(owner, filepath.Base(p), string(data))...)
		}
	}
	return out
}

// pthOwners maps top-level .pth file names to the distribution that installed them.
func pthOwners(site string) map[string]string {
	out := map[string]string{}
	records, _ := filepath.Glob(filepath.Join(site, "*.dist-info", "RECORD"))
	for _, rec := range records {
		dist := strings.TrimSuffix(filepath.Base(filepath.Dir(rec)), ".dist-info")
		name, _, _ := strings.Cut(dist, "-")
		data, err := os.ReadFile(rec) // #nosec G304 -- the environment's own metadata
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			file, _, _ := strings.Cut(line, ",")
			if strings.HasSuffix(file, ".pth") && !strings.ContainsAny(file, "/\\") {
				out[file] = ecosystem.Normalize(ecosystem.PyPI, name)
			}
		}
	}
	return out
}

// fileSnapshot holds files' contents (nil: the file did not exist) so a
// refused resolution can be undone exactly.
type fileSnapshot map[string][]byte

func snapshot(paths ...string) fileSnapshot {
	s := fileSnapshot{}
	for _, p := range paths {
		data, err := os.ReadFile(p) // #nosec G304 -- the project's own files
		if err != nil {
			s[p] = nil
			continue
		}
		s[p] = data
	}
	return s
}

func (s fileSnapshot) restore() {
	for p, data := range s {
		if data == nil {
			_ = os.Remove(p)
			continue
		}
		_ = os.WriteFile(p, data, 0o600) // #nosec G703 -- restoring the project's own file
	}
}

// freshVersions returns the new or changed packages published less than
// --min-age ago (SI-REC-001), as "name@version (published 5h ago)".
func freshVersions(cmd *cobra.Command, g *globalFlags, pol *policy.Policy, changed *lockfile.Graph) []string {
	if len(changed.Packages) == 0 {
		return nil
	}
	minAge, _ := parseMinAge(g.minAge)
	fetcher, err := newFetcherFor(g, ecosystem.PyPI)
	if err != nil {
		return nil
	}
	cfg := analysisConfig(g, pol, minAge)
	cfg.RegistryHosts, cfg.Downloads, cfg.OSV = pypiHosts(), nil, nil
	rep := analyze.Analyze(cmd.Context(), changed, fetcher, cfg)
	var out []string
	for _, r := range rep.Results {
		for _, f := range r.Findings {
			if f.Rule == "SI-REC-001" {
				out = append(out, r.Package.ID+": "+f.Message)
			}
		}
	}
	sort.Strings(out)
	return out
}

// pyInstalled lists the distributions installed in the project's virtual
// environment: ID ("name@version") -> its site-packages and RECORD files.
func pyInstalled(dir string) map[string]pyDist {
	out := map[string]pyDist{}
	for _, pattern := range []string{".venv/lib/python*/site-packages", ".venv/Lib/site-packages"} {
		sites, _ := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
		for _, site := range sites {
			records, _ := filepath.Glob(filepath.Join(site, "*.dist-info", "RECORD"))
			for _, rec := range records {
				dist := strings.TrimSuffix(filepath.Base(filepath.Dir(rec)), ".dist-info")
				name, version, ok := strings.Cut(dist, "-")
				if !ok {
					continue
				}
				data, err := os.ReadFile(rec) // #nosec G304 -- the environment's own metadata
				if err != nil {
					continue
				}
				var files []string
				for _, line := range strings.Split(string(data), "\n") {
					if f, _, _ := strings.Cut(line, ","); f != "" {
						files = append(files, f)
					}
				}
				id := ecosystem.Normalize(ecosystem.PyPI, name) + "@" + version
				out[id] = pyDist{site: site, name: ecosystem.Normalize(ecosystem.PyPI, name), files: files}
			}
		}
	}
	return out
}

type pyDist struct {
	site, name string
	files      []string
}
