package cli

import (
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
)

// Ordinary advisories are not a reason to refuse an install script; known
// malware is.
func TestScriptRelevantFindings(t *testing.T) {
	in := []analyze.Finding{
		{Rule: "SI-SCR-001", Severity: analyze.Medium},
		{Rule: "SI-VUL-001", Severity: analyze.Medium, Message: "GHSA-1: libvips"},
		{Rule: "SI-VUL-001", Severity: analyze.High, Message: "GHSA-2: critical"},
		{Rule: "SI-VUL-001", Severity: analyze.Block, Message: "known malicious package (MAL-1)"},
		{Rule: "SI-REC-001", Severity: analyze.Medium},
	}
	got := scriptRelevant(in)
	var rules []string
	for _, f := range got {
		rules = append(rules, f.Rule+"/"+f.Severity.String())
	}
	want := []string{"SI-SCR-001/medium", "SI-VUL-001/block", "SI-REC-001/medium"}
	if len(rules) != len(want) {
		t.Fatalf("got %v, want %v", rules, want)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Fatalf("got %v, want %v", rules, want)
		}
	}
}
