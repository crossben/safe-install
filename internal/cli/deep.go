package cli

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/codescan"
	"github.com/crossben/safe-install/internal/registry"
)

// deepScan downloads each checked package's tarball, verifies it, and scans
// its code in memory (check --deep). Findings are added to the report; a
// tarball that does not match its integrity is a blocking SI-INT-001 and is
// not scanned; download failures become one warning.
func deepScan(ctx context.Context, g *globalFlags, rep *analyze.Report) {
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
	for i := range rep.Results {
		res := &rep.Results[i]
		if res.Err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
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
