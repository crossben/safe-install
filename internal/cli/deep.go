package cli

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- Composer's own dist checksum format, compared with the lockfile; not used for signing
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/codescan"
	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/registry"
)

// deepScan downloads each checked package's tarball, verifies it, and scans
// its code in memory (check --deep). Findings are added to the report; a
// tarball that does not match its integrity is a blocking SI-INT-001 and is
// not scanned; download failures become one warning.
func deepScan(cmd *cobra.Command, g *globalFlags, rep *analyze.Report) {
	ctx := cmd.Context()
	if g.offline {
		rep.Warnings = append(rep.Warnings, "--deep skipped: --offline")
		return
	}
	client := &registry.Client{Config: registryConfig(g)}
	scanner := &codescan.Scanner{CacheDir: codescan.DefaultCacheDir()}

	var mu sync.Mutex
	var failed []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	bar := startProgress(cmd, g, "Downloading and scanning", len(rep.Results))
	defer bar.Stop()
	for i := range rep.Results {
		res := &rep.Results[i]
		if res.Err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem; bar.Done() }()
			fs, err := deepOne(ctx, client, scanner, res)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s (%v)", res.Package.ID, err))
				return
			}
			res.Findings = append(res.Findings, fs...)
			res.Score, res.Level = analyze.Score(res.Findings)
		}()
	}
	wg.Wait()
	if len(failed) > 0 {
		sort.Strings(failed)
		rep.Warnings = append(rep.Warnings, "--deep could not scan "+strings.Join(failed, "; "))
	}
}

func deepOne(ctx context.Context, client *registry.Client, scanner *codescan.Scanner, res *analyze.Result) ([]analyze.Finding, error) {
	p := res.Package
	if p.Ecosystem == ecosystem.PyPI {
		return deepPython(ctx, client, scanner, res)
	}
	if p.Ecosystem == ecosystem.Packagist {
		return deepComposer(ctx, client, scanner, res)
	}
	for _, f := range res.Findings {
		if f.Rule == "SI-INT-001" {
			return nil, nil // already blocked for integrity: nothing to gain from its code
		}
	}
	integrity := p.Integrity
	if integrity == "" {
		integrity = res.RegistryIntegrity
	}
	target := codescan.Target{ID: p.ID, Integrity: integrity}
	if fs, ok := scanner.Lookup(target); ok {
		return fs, nil
	}
	url := p.Resolved
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		url = res.Tarball
	}
	if url == "" {
		return nil, fmt.Errorf("no tarball URL")
	}
	data, err := client.Tarball(ctx, url)
	if err != nil {
		return nil, err
	}
	if integrity != "" {
		if err := registry.VerifyIntegrity(data, integrity); err != nil {
			return []analyze.Finding{{Rule: "SI-INT-001", Severity: analyze.Block,
				Message: "downloaded tarball does not match the lockfile integrity; its code was not scanned"}}, nil
		}
	}
	fs, err := codescan.Tarball(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	scanner.Store(target, fs)
	return fs, nil
}

// deepPython scans a Python package's sdist (its build code and source) and
// one wheel (preferring the pure-Python one, which is what most installs
// get): each is checked against PyPI's sha256 and, when the lockfile pins
// hashes, against those too, then scanned in memory.
func deepPython(ctx context.Context, client *registry.Client, scanner *codescan.Scanner, res *analyze.Result) ([]analyze.Finding, error) {
	for _, f := range res.Findings {
		if f.Rule == "SI-INT-001" {
			return nil, nil
		}
	}
	pinned := map[string]bool{}
	for _, f := range res.Package.Files {
		if algo, sum, ok := strings.Cut(f.Hash, ":"); ok && algo == "sha256" {
			pinned[strings.ToLower(sum)] = true
		}
	}
	var picks []registry.DistFile
	var sdist, pure, anyWheel *registry.DistFile
	for i := range res.DistFiles {
		f := &res.DistFiles[i]
		if f.URL == "" || f.SHA256 == "" || (len(pinned) > 0 && !pinned[f.SHA256]) {
			continue // not a file this lockfile can install
		}
		switch {
		case f.Sdist:
			sdist = f
		case strings.HasSuffix(f.Name, "-none-any.whl"):
			pure = f
		case anyWheel == nil:
			anyWheel = f
		}
	}
	for _, f := range []*registry.DistFile{sdist, pure, anyWheel} {
		if f != nil && (f != anyWheel || pure == nil) {
			picks = append(picks, *f)
		}
	}
	if len(picks) == 0 {
		return nil, fmt.Errorf("no distribution file to scan")
	}
	var out []analyze.Finding
	for _, f := range picks {
		target := codescan.Target{ID: res.Package.ID + "/" + f.Name, Integrity: "sha256:" + f.SHA256}
		if fs, ok := scanner.Lookup(target); ok {
			out = append(out, fs...)
			continue
		}
		data, err := client.Tarball(ctx, f.URL)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return []analyze.Finding{{Rule: "SI-INT-001", Severity: analyze.Block,
				Message: f.Name + " does not match the registry's sha256; its code was not scanned"}}, nil
		}
		fs, err := codescan.PythonArchive(res.Package.Name, f.Name, data)
		if err != nil {
			return nil, err
		}
		scanner.Store(target, fs)
		out = append(out, fs...)
	}
	return mergeFindings(out), nil
}

// mergeFindings keeps one finding per rule (the most severe), as the
// scanner does within one archive.
func mergeFindings(fs []analyze.Finding) []analyze.Finding {
	best := map[string]analyze.Finding{}
	for _, f := range fs {
		if cur, ok := best[f.Rule]; !ok || f.Severity > cur.Severity {
			best[f.Rule] = f
		}
	}
	out := make([]analyze.Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// deepComposer scans a Composer package's dist. GitHub zipballs carry no
// checksum: the anchor is the commit. SI-INT-001 has already checked that
// the lockfile pins the commit Packagist serves, and the download must be
// the zipball of exactly that commit (or match the sha1 when there is one).
func deepComposer(ctx context.Context, client *registry.Client, scanner *codescan.Scanner, res *analyze.Result) ([]analyze.Finding, error) {
	for _, f := range res.Findings {
		if f.Rule == "SI-INT-001" {
			return nil, nil
		}
	}
	p := res.Package
	url := p.Resolved
	if !strings.HasPrefix(url, "https://") {
		url = res.Tarball
	}
	if url == "" {
		return nil, fmt.Errorf("no dist URL")
	}
	if p.Ref != "" && !strings.Contains(url, p.Ref) {
		return nil, fmt.Errorf("dist URL does not name the locked commit")
	}
	target := codescan.Target{ID: p.ID, Integrity: "ref:" + p.Ref}
	if fs, ok := scanner.Lookup(target); ok {
		return fs, nil
	}
	data, err := client.Tarball(ctx, url)
	if err != nil {
		return nil, err
	}
	for _, f := range p.Files {
		if algo, sum, _ := strings.Cut(f.Hash, ":"); algo == "sha1" {
			got := sha1.Sum(data) // #nosec G401 -- Composer's own checksum format, compared, not trusted for signing
			if !strings.EqualFold(hex.EncodeToString(got[:]), sum) {
				return []analyze.Finding{{Rule: "SI-INT-001", Severity: analyze.Block,
					Message: "downloaded dist does not match the lockfile sha1; its code was not scanned"}}, nil
			}
		}
	}
	fs, err := codescan.ComposerDist(data)
	if err != nil {
		return nil, err
	}
	scanner.Store(target, fs)
	return fs, nil
}
