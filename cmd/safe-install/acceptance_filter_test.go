package main

import (
	"testing"
	"time"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/policy"
)

func TestApplyAcceptancesMarksMatching(t *testing.T) {
	// Setup: policy with one acceptance
	p := &policy.Policy{
		File: policy.File{
			AcceptFindings: map[string][]policy.Acceptance{
				"vite": {
					{
						Version: "8.3.8",
						Rule:    "SI-CODE-001",
						File:    "dist/node/chunks/node.js",
						Hash:    "sha256:abc123",
						Reason:  "registry read only",
					},
				},
			},
		},
	}

	// Create a finding that matches
	findings := []analyze.Finding{
		{
			Rule:     "SI-CODE-001",
			Severity: analyze.High,
			Message:  "test message",
		},
	}

	// Apply acceptances with matching package, version, rule, file, hash
	result := ApplyAcceptances(findings, p, "vite", "8.3.8", "dist/node/chunks/node.js", "sha256:abc123")

	if len(result) != 1 {
		t.Errorf("ApplyAcceptances returned %d findings, want 1", len(result))
	}

	if result[0].Accepted == nil {
		t.Errorf("Accepted field is nil, want acceptance object")
	} else if acc, ok := result[0].Accepted.(*policy.Acceptance); ok {
		if acc.Reason != "registry read only" {
			t.Errorf("Accepted reason = %q, want %q", acc.Reason, "registry read only")
		}
	}
}

func TestApplyAcceptancesSkipsExpired(t *testing.T) {
	_ = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	p := &policy.Policy{
		File: policy.File{
			AcceptFindings: map[string][]policy.Acceptance{
				"vite": {
					{
						Version: "8.3.8",
						Rule:    "SI-CODE-001",
						File:    "dist/node/chunks/node.js",
						Hash:    "sha256:abc123",
						Reason:  "registry read only",
						Expires: "2026-11-11", // expired
					},
				},
			},
		},
	}

	findings := []analyze.Finding{
		{
			Rule:     "SI-CODE-001",
			Severity: analyze.High,
			Message:  "test message",
		},
	}

	result := ApplyAcceptances(findings, p, "vite", "8.3.8", "dist/node/chunks/node.js", "sha256:abc123")

	if len(result) != 1 {
		t.Errorf("ApplyAcceptances returned %d findings, want 1", len(result))
	}

	if result[0].Accepted != nil {
		t.Errorf("Accepted field should be nil for expired acceptance, but got %v", result[0].Accepted)
	}
}

func TestApplyAcceptancesDoesNotAcceptBlockFindings(t *testing.T) {
	p := &policy.Policy{
		File: policy.File{
			AcceptFindings: map[string][]policy.Acceptance{
				"bad-pkg": {
					{
						Version: "1.0.0",
						Rule:    "SI-INT-001",
						File:    "package.json",
						Hash:    "sha256:def456",
						Reason:  "integrity issue reviewed",
					},
				},
			},
		},
	}

	// Block findings cannot be accepted
	findings := []analyze.Finding{
		{
			Rule:     "SI-INT-001",
			Severity: analyze.Block,
			Message:  "integrity mismatch",
		},
	}

	result := ApplyAcceptances(findings, p, "bad-pkg", "1.0.0", "package.json", "sha256:def456")

	if len(result) != 1 {
		t.Errorf("ApplyAcceptances returned %d findings, want 1", len(result))
	}

	if result[0].Accepted != nil {
		t.Errorf("Block finding should not be accepted, but Accepted is %v", result[0].Accepted)
	}
}

func TestCountByStatusSeparatesAccepted(t *testing.T) {
	findings := []analyze.Finding{
		{Rule: "SI-CODE-001", Severity: analyze.High, Message: "high 1"},
		{
			Rule:     "SI-CODE-002",
			Severity: analyze.High,
			Message:  "high 2 accepted",
			Accepted: &policy.Acceptance{Reason: "approved"},
		},
		{Rule: "SI-POP-002", Severity: analyze.Medium, Message: "medium 1"},
		{Rule: "SI-REC-001", Severity: analyze.Low, Message: "low 1"},
		{Rule: "SI-INT-001", Severity: analyze.Block, Message: "block 1"},
	}

	counts := CountByStatus(findings)

	if counts["high"]["unaccepted"] != 1 {
		t.Errorf("high unaccepted count = %d, want 1", counts["high"]["unaccepted"])
	}
	if counts["high"]["accepted"] != 1 {
		t.Errorf("high accepted count = %d, want 1", counts["high"]["accepted"])
	}
	if counts["medium"]["unaccepted"] != 1 {
		t.Errorf("medium unaccepted count = %d, want 1", counts["medium"]["unaccepted"])
	}
	if counts["low"]["unaccepted"] != 1 {
		t.Errorf("low unaccepted count = %d, want 1", counts["low"]["unaccepted"])
	}
	if counts["block"]["unaccepted"] != 1 {
		t.Errorf("block unaccepted count = %d, want 1", counts["block"]["unaccepted"])
	}
}

func TestFindingNotAcceptedWhenHashDiffers(t *testing.T) {
	p := &policy.Policy{
		File: policy.File{
			AcceptFindings: map[string][]policy.Acceptance{
				"vite": {
					{
						Version: "8.3.8",
						Rule:    "SI-CODE-001",
						File:    "dist/node/chunks/node.js",
						Hash:    "sha256:abc123",
						Reason:  "registry read only",
					},
				},
			},
		},
	}

	findings := []analyze.Finding{
		{
			Rule:     "SI-CODE-001",
			Severity: analyze.High,
			Message:  "test message",
		},
	}

	// Apply with different hash
	result := ApplyAcceptances(findings, p, "vite", "8.3.8", "dist/node/chunks/node.js", "sha256:xyz999")

	if len(result) != 1 {
		t.Errorf("ApplyAcceptances returned %d findings, want 1", len(result))
	}

	if result[0].Accepted != nil {
		t.Errorf("Finding with different hash should not be accepted, but got %v", result[0].Accepted)
	}
}

func TestFindingNotAcceptedWhenVersionDiffers(t *testing.T) {
	p := &policy.Policy{
		File: policy.File{
			AcceptFindings: map[string][]policy.Acceptance{
				"vite": {
					{
						Version: "8.3.8",
						Rule:    "SI-CODE-001",
						File:    "dist/node/chunks/node.js",
						Hash:    "sha256:abc123",
						Reason:  "registry read only",
					},
				},
			},
		},
	}

	findings := []analyze.Finding{
		{
			Rule:     "SI-CODE-001",
			Severity: analyze.High,
			Message:  "test message",
		},
	}

	// Apply with different version
	result := ApplyAcceptances(findings, p, "vite", "8.3.7", "dist/node/chunks/node.js", "sha256:abc123")

	if len(result) != 1 {
		t.Errorf("ApplyAcceptances returned %d findings, want 1", len(result))
	}

	if result[0].Accepted != nil {
		t.Errorf("Finding with different version should not be accepted, but got %v", result[0].Accepted)
	}
}
