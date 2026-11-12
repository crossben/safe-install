package cli

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/policy"
)

// ApplyAcceptances marks findings with Accepted field where they match a recorded acceptance.
// Block-level findings are never accepted. Expired acceptances are skipped.
func ApplyAcceptances(findings []analyze.Finding, p *policy.Policy, pkg, ver, file, hash string) []analyze.Finding {
	for i := range findings {
		f := &findings[i]

		// Block findings cannot be accepted
		if f.Severity == analyze.Block {
			continue
		}

		// Look for matching acceptance
		if acc, ok := p.LookupAcceptance(pkg, ver, f.Rule, file, hash); ok {
			// Check if it's expired
			if !acc.Expired(time.Now()) {
				f.Accepted = &acc
			}
		}
	}
	return findings
}

// ComputeFileHash returns sha256:hexdigest of a file's contents
func ComputeFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// CountByStatus returns counts of findings grouped by severity and acceptance status.
// Returns map[severity][status] where status is "accepted" or "unaccepted"
func CountByStatus(findings []analyze.Finding) map[string]map[string]int {
	counts := make(map[string]map[string]int)

	for _, f := range findings {
		sev := f.Severity.String()
		if _, ok := counts[sev]; !ok {
			counts[sev] = make(map[string]int)
		}

		if f.Accepted != nil {
			counts[sev]["accepted"]++
		} else {
			counts[sev]["unaccepted"]++
		}
	}

	return counts
}

// WorstUnacceptedLevel returns the worst severity level of unaccepted findings in a report.
// Accepted findings are excluded from the calculation.
func WorstUnacceptedLevel(results []analyze.Result) analyze.Level {
	worstLevel := analyze.LevelNone
	for _, res := range results {
		for _, f := range res.Findings {
			// Skip accepted findings
			if f.Accepted != nil {
				continue
			}
			level := f.Severity.String()
			fLevel, _ := analyze.ParseLevel(level)
			if fLevel > worstLevel {
				worstLevel = fLevel
			}
		}
	}
	return worstLevel
}
