package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/ecosystem"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
)

type approveFlags struct {
	revoke, global, force bool
	trust, expires        string
}

// approveOther approves Python source builds (pinned to the sdist's sha256)
// and Composer plugins (pinned to their commit). Nothing runs now: the next
// `safe-install install` builds or enables what is approved.
func approveOther(cmd *cobra.Command, g *globalFlags, dir string, e ecosystem.Ecosystem, names []string, f approveFlags) error {
	pol, err := loadPolicy(cmd, g)
	if err != nil {
		return err
	}
	w := &lineWriter{w: cmd.ErrOrStderr()}
	policyPath := pol.ProjectPath
	if f.global {
		if policyPath, err = policy.GlobalPath(); err != nil {
			return err
		}
	}
	if f.revoke {
		for _, name := range names {
			name = ecosystem.Normalize(e, name)
			removed, err := policy.Revoke(policyPath, name)
			if err != nil {
				return err
			}
			if removed {
				w.printf("revoked %s\n", name)
			} else {
				w.printf("%s was not approved in %s\n", name, policyPath)
			}
		}
		return w.err
	}
	if f.trust != policy.TrustHash {
		return errors.New("--trust provenance is for npm packages; Python and Composer approvals are pinned to a hash or commit")
	}
	expiry, err := expiryDate(f.expires)
	if err != nil {
		return err
	}
	path, err := lockfile.FindFor(dir, e)
	if err != nil {
		return err
	}
	graph, err := lockfile.LoadFile(path)
	if err != nil {
		return err
	}
	for _, raw := range names {
		if strings.ContainsAny(raw, "*?[") {
			return fmt.Errorf("%s: globs are for npm provenance approvals only", raw)
		}
		name := ecosystem.Normalize(e, raw)
		p := findByName(graph, name)
		if p == nil {
			return fmt.Errorf("%s is not in %s", raw, path)
		}
		var hash, what string
		switch e {
		case ecosystem.PyPI:
			sha, ok := sdistOf(p)
			if !ok {
				return fmt.Errorf("%s has no source distribution in the lockfile: there is nothing to build", p.ID)
			}
			hash, what = "sha256:"+sha, "may be built from source"
		case ecosystem.Packagist:
			if !p.Plugin || p.Ref == "" {
				return fmt.Errorf("%s is not a Composer plugin: there is nothing to approve (dependencies' scripts never run)", p.ID)
			}
			hash, what = "ref:"+p.Ref, "plugin may be enabled"
		}
		res, err := assessOne(cmd, g, pol, e, p)
		if err != nil {
			return err
		}
		if res.Level >= analyze.LevelHigh && !f.force {
			describeResult(w, res)
			return fmt.Errorf("%s is %s risk; review the findings above and use --force to approve anyway", p.ID, res.Level)
		}
		if err := policy.Approve(policyPath, name, policy.Approval{Version: p.Version, Hash: hash, Expires: expiry}); err != nil {
			return err
		}
		w.printf("approved %s (%s)%s; run `safe-install install` to apply it\n", p.ID, what, approvalNote(policy.Approval{Expires: expiry}))
	}
	return w.err
}

// assessOne runs the registry rules and the code scan on one package.
func assessOne(cmd *cobra.Command, g *globalFlags, pol *policy.Policy, e ecosystem.Ecosystem, p *lockfile.Package) (analyze.Result, error) {
	minAge, _ := parseMinAge(g.minAge)
	fetcher, err := newFetcherFor(g, e)
	if err != nil {
		return analyze.Result{}, err
	}
	cfg := analysisConfig(g, pol, minAge)
	cfg.Downloads = nil
	if e == ecosystem.PyPI {
		cfg.RegistryHosts = pypiHosts()
	} else {
		cfg.RegistryHosts = composerHosts()
	}
	sub := &lockfile.Graph{Packages: map[string]*lockfile.Package{p.ID: p}}
	rep := analyze.Analyze(cmd.Context(), sub, fetcher, cfg)
	deepScan(cmd, g, rep)
	if len(rep.Results) == 0 {
		return analyze.Result{Package: p}, nil
	}
	return rep.Results[0], nil
}
