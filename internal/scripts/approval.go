package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/policy"
)

// Hash identifies exactly what would run: each stage's command and the
// contents of the files those commands run with node.
func (c *Candidate) Hash() string {
	h := sha256.New()
	for _, stage := range c.Stages() {
		cmd := c.Scripts[stage]
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", stage, cmd) // hash writes never fail
		for _, f := range nodeFiles(c.Dir, cmd) {
			body := readCapped(filepath.Join(c.Dir, f))
			_, _ = fmt.Fprintf(h, "%s\x00%d\x00", f, len(body))
			h.Write(body)
		}
	}
	return "sha256-" + hex.EncodeToString(h.Sum(nil))
}

// State is a candidate's approval status.
type State int

// Approval states.
const (
	Unapproved           State = iota
	Approved                   // scripts match the recorded hash
	Changed                    // approved before, but the scripts are different now
	Expired                    // the approval's last valid day has passed
	ApprovedByProvenance       // scripts changed, but built by the trusted repository's CI
)

// Key is the state's stable machine-readable name (JSON output).
func (s State) Key() string {
	return [...]string{"unapproved", "approved", "changed", "expired", "provenance"}[s]
}

func (s State) String() string {
	return [...]string{"not approved", "approved", "changed since approval", "approval expired", "approved by provenance"}[s]
}

// Runs reports whether the state lets the scripts run without asking.
func (s State) Runs() bool { return s == Approved || s == ApprovedByProvenance }

// Provenance returns the source repository of a version's npm provenance,
// or "" when it has none.
type Provenance func(name, version string) string

// ApprovalState checks c against the policy (exact name, then globs). With
// trust "provenance", changed scripts are still approved when the installed
// version was built from the recorded repository. A change that is not
// covered yields an SI-SCR-005 finding.
func ApprovalState(c *Candidate, pol *policy.Policy, now time.Time, provenance Provenance) (State, *analyze.Finding) {
	a, key, ok := pol.Lookup(c.Package.Name)
	if !ok {
		return Unapproved, nil
	}
	if a.Expired(now) {
		return Expired, nil
	}
	if a.Hash != "" && a.Hash == c.Hash() {
		return Approved, nil
	}
	msg := fmt.Sprintf("install scripts changed since they were approved (for %s)", a.Version)
	if a.TrustMode() == policy.TrustProvenance {
		got := ""
		if provenance != nil {
			got = provenance(c.Package.Name, c.Package.Version)
		}
		if got != "" && got == a.Repository {
			return ApprovedByProvenance, nil
		}
		from := "has no npm provenance"
		if got != "" {
			from = "was built from " + got
		}
		msg = fmt.Sprintf("approval %q trusts builds from %s, but this version %s", key, a.Repository, from)
	}
	return Changed, &analyze.Finding{Rule: "SI-SCR-005", Severity: analyze.High, Message: msg}
}
