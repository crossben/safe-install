package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/codescan"
	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
	"github.com/crossben/safe-install/internal/popularity"
	"github.com/crossben/safe-install/internal/registry"
	"github.com/crossben/safe-install/internal/scripts"
)

// acceptTerminal reports whether stdin is a terminal. Only a human at a
// terminal may accept or revoke a finding; tests replace it.
var acceptTerminal = func() bool { return isInteractive() }

// contextLines is how many lines around a flagged line `accept` shows.
const contextLines = 3

// maxShownFile caps how much of a file `accept` reads to show lines.
const maxShownFile = 8 << 20

type acceptFlags struct {
	file, reason, expires string
	global, revoke, force bool
}

func newAcceptCmd(g *globalFlags) *cobra.Command {
	var f acceptFlags
	cmd := &cobra.Command{
		Use:   "accept <package>@<version> <rule> --reason \"...\" [--file <path>] [--expires 90d|YYYY-MM-DD] [--global] [--revoke] [--force]",
		Short: "Record a reviewed finding as accepted (humans only)",
		Long: "Record that a human reviewed a finding and judged it harmless. The acceptance is pinned to what was\n" +
			"reviewed and written to .safe-install.json:\n\n" +
			"  with --file    a code finding: pinned to the version, rule, file and the file's sha256\n" +
			"  without --file a package-level finding (registry rules): pinned to the lockfile integrity and the evidence\n\n" +
			"It re-checks the package, shows the finding and asks for confirmation. It requires an interactive terminal\n" +
			"and asks for confirmation. It is a speed bump, not a security boundary. Block findings and known-malware advisories can never be accepted.",
		Example: "  safe-install accept vite@8.3.8 SI-CODE-001 --file dist/node/chunks/node.js --reason \"reads a local index\" --expires 90d\n" +
			"  safe-install accept tslib@2.9.1 SI-REC-002 --reason \"Microsoft's release account\"",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccept(cmd, g, args[0], args[1], f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.file, "file", "", "package-relative file of a code finding (omit for a package-level finding)")
	fl.StringVar(&f.reason, "reason", "", "why the finding is safe (required unless --revoke)")
	fl.StringVar(&f.expires, "expires", "", "expiry: a duration (90d) or a date (YYYY-MM-DD)")
	fl.BoolVar(&f.global, "global", false, "store in your user config instead of .safe-install.json")
	fl.BoolVar(&f.revoke, "revoke", false, "remove the acceptance instead of adding one")
	fl.BoolVar(&f.force, "force", false, "allow accepting a high-severity vulnerability (never block or malware findings)")
	return cmd
}

// parsePackageVersion splits "name@version" on the last "@", so
// "@scope/name@1.2.3" gives "@scope/name" and "1.2.3".
func parsePackageVersion(s string) (name, version string, err error) {
	i := strings.LastIndex(s, "@")
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("expected <package>@<version>, got %q", s)
	}
	return s[:i], s[i+1:], nil
}

func runAccept(cmd *cobra.Command, g *globalFlags, spec, rule string, f acceptFlags) error {
	name, version, err := parsePackageVersion(spec)
	if err != nil {
		return err
	}
	if !acceptTerminal() {
		return errors.New("accept needs a terminal: only a human may accept or revoke a finding (it asks for confirmation on an interactive terminal)")
	}
	if f.reason == "" && !f.revoke {
		return errors.New("--reason is required: say why the finding is safe")
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	target := filepath.Join(dir, policy.FileName)
	if f.global {
		if target, err = policy.GlobalPath(); err != nil {
			return fmt.Errorf("user config path: %w", err)
		}
	}
	out := cmd.OutOrStdout()

	if f.revoke {
		ok, err := policy.RevokeFinding(target, name, version, rule, f.file)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no acceptance for %s@%s %s%s in %s", name, version, rule, fileSuffix(f.file), target)
		}
		_, _ = fmt.Fprintf(out, "Revoked %s@%s %s%s in %s\nCommit %s so the team sees it.\n", name, version, rule, fileSuffix(f.file), target, policy.FileName)
		return nil
	}

	pol, err := loadPolicy(cmd, g)
	if err != nil {
		return err
	}
	if pol.AcceptForbidden(rule) {
		return fmt.Errorf("the organization policy forbids accepting %s findings", rule)
	}
	if ok, why := analyze.Acceptable(analyze.Finding{Rule: rule, Severity: analyze.Low}, f.force); !ok {
		return fmt.Errorf("cannot accept %s: %s", rule, why)
	}
	det, err := detectSupported(dir, g.pm, ecosystem.PyPI, ecosystem.Packagist)
	if err != nil {
		return err
	}
	eco := det.Ecosystem()
	path, err := lockfile.FindFor(dir, eco)
	if err != nil {
		return err
	}
	graph, err := lockfile.LoadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	var pkg *lockfile.Package
	for _, p := range graph.Sorted() {
		if p.Name == name && p.Version == version {
			pkg = p
			break
		}
	}
	if pkg == nil {
		return fmt.Errorf("%s@%s is not in %s", name, version, filepath.Base(path))
	}

	var entries []policy.Acceptance
	if f.file != "" {
		entries, err = codeAcceptances(cmd, dir, eco, pkg, rule, f)
	} else {
		entries, err = packageAcceptances(cmd, g, dir, eco, pkg, rule, f, pol)
	}
	if err != nil {
		return err
	}

	by := acceptor()
	_, _ = fmt.Fprintf(out, "\nReason:  %s\n", f.reason)
	if f.expires != "" {
		_, _ = fmt.Fprintf(out, "Expires: %s\n", f.expires)
	}
	_, _ = fmt.Fprintf(out, "Accept? [y/N] ")
	if !confirmed(cmd.InOrStdin()) {
		_, _ = fmt.Fprintln(out, "\nNot accepted; nothing was written.")
		return nil
	}
	for _, e := range entries {
		e.Reason, e.By, e.Expires = f.reason, by, f.expires
		if err := policy.AcceptFinding(target, name, e); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintf(out, "\nAccepted %s@%s %s%s (%d entr%s) in %s.\n", name, version, rule, fileSuffix(f.file), len(entries), plural(len(entries)), target)
	if !f.global {
		_, _ = fmt.Fprintf(out, "Commit %s so the team shares it.\n", policy.FileName)
	}
	return nil
}

// maxConfirm bounds the confirmation read.
const maxConfirm = 1024

// confirmed reads one line of at most maxConfirm bytes and reports whether it
// is "y" or "yes". A longer line, or none, counts as "no".
func confirmed(in io.Reader) bool {
	line, err := bufio.NewReaderSize(io.LimitReader(in, maxConfirm), maxConfirm).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	if len(line) >= maxConfirm {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func fileSuffix(file string) string {
	if file == "" {
		return ""
	}
	return " (" + file + ")"
}

// checkAcceptable refuses findings that can never be accepted.
func checkAcceptable(fs []analyze.Finding, force bool) error {
	for _, f := range fs {
		if ok, why := analyze.Acceptable(f, force); !ok {
			return fmt.Errorf("cannot accept %s: %s", f.Rule, why)
		}
	}
	return nil
}

// codeAcceptances re-scans the installed package and returns the entry for
// the finding of rule in f.file, after showing the flagged lines.
func codeAcceptances(cmd *cobra.Command, dir string, eco ecosystem.Ecosystem, pkg *lockfile.Package, rule string, f acceptFlags) ([]policy.Acceptance, error) {
	pdir, found, ok := rescanPackage(dir, eco, pkg)
	if !ok {
		return nil, fmt.Errorf("%s is not installed here: install it first, so the code that runs can be reviewed", pkg.ID)
	}
	file := filepath.ToSlash(filepath.Clean(filepath.FromSlash(f.file)))
	var matches []analyze.Finding
	var others []string
	for _, fi := range found {
		if fi.Rule != rule {
			continue
		}
		if fi.File == file {
			matches = append(matches, fi)
		} else {
			others = append(others, fi.File)
		}
	}
	if len(matches) == 0 {
		msg := fmt.Sprintf("no %s finding in %s of %s", rule, file, pkg.ID)
		if len(others) > 0 {
			msg += "; it is flagged in: " + strings.Join(others, ", ")
		}
		return nil, errors.New(msg)
	}
	if err := checkAcceptable(matches, f.force); err != nil {
		return nil, err
	}
	hash, err := sha256File(pdir, file)
	if err != nil {
		return nil, fmt.Errorf("hash %s: %w", file, err)
	}
	out := cmd.OutOrStdout()
	for _, m := range matches {
		_, _ = fmt.Fprintf(out, "%s@%s  %s (%s)\n  %s\n  file: %s\n  hash: %s\n", pkg.Name, pkg.Version, m.Rule, m.Severity, m.Message, file, hash)
	}
	showLines(out, pdir, file, rule)
	return []policy.Acceptance{{Version: pkg.Version, Rule: rule, File: file, Hash: hash}}, nil
}

// rescanPackage returns the installed dir of pkg and its code findings; ok is
// false when the package is not installed.
func rescanPackage(dir string, eco ecosystem.Ecosystem, pkg *lockfile.Package) (pdir string, fs []analyze.Finding, ok bool) {
	switch eco {
	case ecosystem.PyPI:
		d, found := pyInstalled(dir)[pkg.ID]
		if !found {
			return "", nil, false
		}
		return d.site, codescan.PythonInstalled(d.site, d.name, d.files), true
	case ecosystem.Packagist:
		d, found := composerInstalled(dir)[pkg.ID]
		if !found {
			return "", nil, false
		}
		return d, codescan.ComposerInstalled(d), true
	}
	d, found := scripts.Installed(dir)[pkg.ID]
	if !found {
		return "", nil, false
	}
	return d, codescan.Package(d), true
}

// showLines prints the lines of file that trigger rule, with context.
func showLines(w io.Writer, pdir, file, rule string) {
	root, err := os.OpenRoot(pdir)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	fh, err := root.Open(filepath.FromSlash(file))
	if err != nil {
		return
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxShownFile))
	if err != nil {
		return
	}
	src := string(data)
	flagged := codescan.FlaggedLines(src, rule)
	if len(flagged) == 0 {
		_, _ = fmt.Fprintln(w, "  (the flagged lines could not be located; review the whole file)")
		return
	}
	lines := strings.Split(src, "\n")
	shown := map[int]bool{}
	for _, n := range flagged {
		for i := max(1, n-contextLines); i <= min(len(lines), n+contextLines); i++ {
			shown[i] = true
		}
	}
	isFlagged := func(n int) bool { return slices.Contains(flagged, n) }
	_, _ = fmt.Fprintf(w, "\nFlagged lines in %s:\n", file)
	prev := 0
	for i := 1; i <= len(lines); i++ {
		if !shown[i] {
			continue
		}
		if prev != 0 && i != prev+1 {
			_, _ = fmt.Fprintln(w, "      ...")
		}
		prev = i
		mark := " "
		if isFlagged(i) {
			mark = ">"
		}
		text := lines[i-1]
		if len(text) > 200 {
			text = text[:200] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s %4d | %s\n", mark, i, text)
	}
}

// packageAcceptances runs the registry check of one package and returns an
// entry per finding of rule, pinned to the tarball integrity and evidence.
func packageAcceptances(cmd *cobra.Command, g *globalFlags, dir string, eco ecosystem.Ecosystem, pkg *lockfile.Package, rule string, f acceptFlags, pol *policy.Policy) ([]policy.Acceptance, error) {
	res, err := checkOne(cmd, g, dir, eco, pkg, pol)
	if err != nil {
		return nil, err
	}
	var matches []analyze.Finding
	for _, fi := range res.Findings {
		if fi.Rule == rule && fi.File == "" {
			matches = append(matches, fi)
		}
	}
	if len(matches) == 0 {
		if _, code, ok := rescanPackage(dir, eco, pkg); ok {
			var files []string
			for _, fi := range code {
				if fi.Rule == rule {
					files = append(files, fi.File)
				}
			}
			if len(files) > 0 {
				return nil, fmt.Errorf("%s is a code finding: pass --file <path>. It is flagged in: %s", rule, strings.Join(files, ", "))
			}
		}
		return nil, fmt.Errorf("no %s finding for %s", rule, pkg.ID)
	}
	if err := checkAcceptable(matches, f.force); err != nil {
		return nil, err
	}
	pin := AcceptancePin(pkg, res.RegistryIntegrity)
	if pin == "" {
		return nil, fmt.Errorf("%s has no integrity in the lockfile or the registry to pin the acceptance to", pkg.ID)
	}
	out := cmd.OutOrStdout()
	var entries []policy.Acceptance
	for _, m := range matches {
		_, _ = fmt.Fprintf(out, "%s@%s  %s (%s)\n  %s\n  evidence: %s\n  pinned to: %s\n", pkg.Name, pkg.Version, m.Rule, m.Severity, m.Message, m.Evidence, pin)
		entries = append(entries, policy.Acceptance{Version: pkg.Version, Rule: rule, Integrity: pin, Evidence: m.Evidence})
	}
	return entries, nil
}

// checkOne runs the registry rules on one package, as `check` does.
func checkOne(cmd *cobra.Command, g *globalFlags, dir string, eco ecosystem.Ecosystem, p *lockfile.Package, pol *policy.Policy) (analyze.Result, error) {
	minAge, err := parseMinAge(g.minAge)
	if err != nil {
		return analyze.Result{}, err
	}
	fetcher, err := newFetcherFor(g, eco)
	if err != nil {
		return analyze.Result{}, err
	}
	cfg := analysisConfig(g, pol, minAge)
	switch eco {
	case ecosystem.PyPI:
		cfg.RegistryHosts = append(pypiHosts(), pythonIndexHosts(dir, os.Getenv)...)
		cfg.Popular = popularity.For(ecosystem.PyPI)
		cfg.Downloads = nil
		if py, ok := fetcher.(*registry.PyPI); ok {
			cfg.Provenance = py
		}
	case ecosystem.Packagist:
		cfg.RegistryHosts = append(composerHosts(), composerRepositoryHosts(dir)...)
		cfg.Popular = popularity.For(ecosystem.Packagist)
		cfg.Downloads = nil
	}
	sub := &lockfile.Graph{Packages: map[string]*lockfile.Package{p.ID: p}}
	rep := analyze.Analyze(cmd.Context(), sub, fetcher, cfg)
	if len(rep.Results) == 0 {
		return analyze.Result{}, fmt.Errorf("%s was not checked (excluded by policy?)", p.ID)
	}
	res := rep.Results[0]
	if res.Err != nil {
		return res, fmt.Errorf("check %s: %w", p.ID, res.Err)
	}
	return res, nil
}

// acceptor names who accepted: git's user.name, else the OS user.
func acceptor() string {
	if out, err := exec.Command("git", "config", "user.name").Output(); err == nil {
		if n := strings.TrimSpace(string(out)); n != "" {
			return n
		}
	}
	if u, err := user.Current(); err == nil {
		if u.Username != "" {
			return u.Username
		}
		return u.Name
	}
	return os.Getenv("USER")
}
