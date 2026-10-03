package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"

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
	Unapproved State = iota
	Approved         // matches a recorded approval
	Changed          // approved before, but the scripts are different now
)

func (s State) String() string {
	return [...]string{"not approved", "approved", "changed since approval"}[s]
}

// ApprovalState checks c against recorded approvals (by package name). A
// changed script yields an SI-SCR-005 finding.
func ApprovalState(c *Candidate, approvals map[string]policy.Approval) (State, *analyze.Finding) {
	a, ok := approvals[c.Package.Name]
	if !ok {
		return Unapproved, nil
	}
	if a.Hash == c.Hash() {
		return Approved, nil
	}
	return Changed, &analyze.Finding{Rule: "SI-SCR-005", Severity: analyze.High,
		Message: fmt.Sprintf("install scripts changed since they were approved (for %s)", a.Version)}
}
