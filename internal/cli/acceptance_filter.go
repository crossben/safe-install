package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
)

// sha256File returns "sha256:<hex>" of the file rel inside dir. The read goes
// through os.Root, so a symlink in the package cannot point it elsewhere.
func sha256File(dir, rel string) (string, error) {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return "", fmt.Errorf("path %q is not inside the package", rel)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.FromSlash(rel))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// AcceptancePin is what a package-level acceptance is pinned to: the lockfile
// integrity of the tarball, else the registry's (dist.integrity), else the
// Composer commit, else the lockfile's pinned file hashes. "" means there is
// nothing to pin to, and nothing can be accepted.
func AcceptancePin(p *lockfile.Package, registryIntegrity string) string {
	switch {
	case p.Integrity != "":
		return p.Integrity
	case registryIntegrity != "":
		return registryIntegrity
	case p.Ref != "":
		return "ref:" + p.Ref
	}
	var hashes []string
	for _, f := range p.Files {
		hashes = append(hashes, f.Hash)
	}
	sort.Strings(hashes)
	return strings.Join(hashes, " ")
}

// applyAcceptances marks the findings of rep that match a recorded acceptance
// and recomputes each result's score and level from the unaccepted findings,
// so --fail-on and rep.Worst() ignore accepted ones.
//
// A code finding (it has a File) matches on package, version, rule, file and
// the sha256 of that file: pkgDir(id) is the installed package's directory.
// Where it returns "" (check --deep, which reads a tarball), the content hash
// the scanner computed is used instead; it equals the installed file's, since
// the package manager unpacks the tarball unchanged. A package-level finding
// matches on package, version, rule, the tarball integrity and its evidence.
//
// An entry that is expired or no longer matches (changed file, other tarball,
// other evidence) is not applied and a line saying why goes to warn. Findings
// that can never be accepted, or that the organization forbids accepting, are
// not marked.
func applyAcceptances(rep *analyze.Report, pol *policy.Policy, pkgDir func(id string) string, warn io.Writer) {
	seen := map[string]bool{}
	warnOnce := func(line string) {
		if warn != nil && !seen[line] {
			seen[line] = true
			_, _ = fmt.Fprintln(warn, line)
		}
	}
	for i := range rep.Results {
		res := &rep.Results[i]
		if res.Err != nil || res.Package == nil {
			continue
		}
		dir := ""
		if pkgDir != nil {
			dir = pkgDir(res.Package.ID)
		}
		acceptFindings(res.Package, res.RegistryIntegrity, res.Findings, pol, dir, warnOnce)
		res.Score, res.Level = analyze.Score(res.Findings)
	}
}

// acceptFindings marks the findings of one package in place.
func acceptFindings(p *lockfile.Package, registryIntegrity string, fs []analyze.Finding, pol *policy.Policy, dir string, warn func(string)) {
	now := time.Now()
	for i := range fs {
		f := &fs[i]
		f.Accepted = nil
		entries := pol.FindAcceptances(p.Name, p.Version, f.Rule, f.File)
		if len(entries) == 0 {
			continue
		}
		label := fmt.Sprintf("%s %s", p.ID, f.Rule)
		if f.File != "" {
			label += " " + f.File
		}
		// A recorded entry means the human already passed the --force check in
		// `accept`, so a high vulnerability is applied; block findings and
		// known-malware advisories are still refused.
		if ok, why := analyze.Acceptable(*f, true); !ok {
			warn(fmt.Sprintf("safe-install: acceptance for %s not applied: %s", label, why))
			continue
		}
		if pol.AcceptForbidden(f.Rule) {
			warn(fmt.Sprintf("safe-install: acceptance for %s not applied: the organization policy forbids accepting %s findings", label, f.Rule))
			continue
		}
		var problems []string
		for _, e := range entries {
			if why := mismatch(e, p, registryIntegrity, f, dir, now); why != "" {
				problems = append(problems, why)
				continue
			}
			acc := e
			f.Accepted = &acc
			break
		}
		if f.Accepted == nil {
			for _, why := range slices.Compact(problems) {
				warn(fmt.Sprintf("safe-install: acceptance for %s not applied: %s", label, why))
			}
		}
	}
}

// mismatch returns why acceptance e does not cover finding f, or "".
func mismatch(e policy.Acceptance, p *lockfile.Package, registryIntegrity string, f *analyze.Finding, dir string, now time.Time) string {
	if e.Expired(now) {
		return "it expired on " + e.Expires
	}
	if f.File != "" {
		got := f.FileHash
		if dir != "" {
			var err error
			if got, err = sha256File(dir, f.File); err != nil {
				return "the file could not be read: " + err.Error()
			}
		}
		switch {
		case got == "":
			return "there is no file content to compare"
		case e.Hash == "" || got != e.Hash:
			return "the file changed since it was reviewed (hash mismatch)"
		}
		return ""
	}
	pin := AcceptancePin(p, registryIntegrity)
	switch {
	case f.Evidence == "" || e.Evidence == "":
		return "a package-level finding can only be accepted with the evidence it reported"
	case pin == "" || e.Integrity == "" || e.Integrity != pin:
		return "the package tarball changed since it was reviewed (integrity mismatch)"
	case e.Evidence != f.Evidence:
		return fmt.Sprintf("the evidence changed since it was reviewed (accepted %q, now %q)", e.Evidence, f.Evidence)
	}
	return ""
}

// staleAcceptances lists the project file's acceptFindings entries whose
// package version is not in the lockfile, as name@version, sorted.
func staleAcceptances(pol *policy.Policy, present func(pkg, ver string) bool) []string {
	f, err := policy.Read(pol.ProjectPath)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for pkg, accs := range f.AcceptFindings {
		for _, a := range accs {
			if !present(pkg, a.Version) {
				set[pkg+"@"+a.Version] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// lockfilePresent reports whether name@version is in the lockfile graph.
func lockfilePresent(g *lockfile.Graph) func(pkg, ver string) bool {
	return func(pkg, ver string) bool {
		_, ok := g.Packages[pkg+"@"+ver]
		return ok
	}
}

// warnStale prints a warning listing acceptFindings entries whose package
// version is not in the lockfile.
func warnStale(w io.Writer, pol *policy.Policy, g *lockfile.Graph) {
	if stale := staleAcceptances(pol, lockfilePresent(g)); len(stale) > 0 {
		_, _ = fmt.Fprintf(w, "safe-install: %s lists acceptFindings for %s, which are not in the lockfile; remove them with `safe-install scan --prune-accepted`\n",
			filepath.Base(pol.ProjectPath), strings.Join(stale, ", "))
	}
}
