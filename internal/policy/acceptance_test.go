package policy

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestAcceptanceExpired(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		expires string
		want    bool
	}{
		{"no expiry", "", false},
		{"future date", "2027-05-12", false},
		{"today", "2026-11-12", false},
		{"yesterday", "2026-11-11", true},
		{"far past", "2026-01-01", true},
		{"invalid format", "not-a-date", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Acceptance{Expires: tt.expires}
			if got := a.Expired(now); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAcceptanceValidate(t *testing.T) {
	tests := []struct {
		name    string
		acc     Acceptance
		wantErr bool
		errMsg  string
	}{
		{
			"valid with all fields",
			Acceptance{Rule: "SI-CODE-001", File: "dist/index.js", Hash: "sha256:abc", Reason: "safe"},
			false,
			"",
		},
		{
			"valid with expiry",
			Acceptance{Rule: "SI-CODE-001", File: "dist/index.js", Hash: "sha256:abc", Reason: "safe", Expires: "2027-05-12"},
			false,
			"",
		},
		{
			"missing rule",
			Acceptance{File: "dist/index.js", Hash: "sha256:abc", Reason: "safe"},
			true,
			"rule required",
		},
		{
			"missing reason",
			Acceptance{Rule: "SI-CODE-001", File: "dist/index.js", Hash: "sha256:abc"},
			true,
			"reason required",
		},
		{
			"invalid expiry format",
			Acceptance{Rule: "SI-CODE-001", File: "dist/index.js", Hash: "sha256:abc", Reason: "safe", Expires: "not-a-date"},
			true,
			"invalid expires format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.acc.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && !contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %q, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestLookupAcceptance(t *testing.T) {
	p := &Policy{
		File: File{
			AcceptFindings: map[string][]Acceptance{
				"vite": {
					{
						Version: "8.3.8",
						Rule:    "SI-CODE-001",
						File:    "dist/node/chunks/node.js",
						Hash:    "sha256:abc123",
						Reason:  "registry read only",
					},
				},
				"sharp": {
					{
						Version: "0.33.0",
						Rule:    "SI-CODE-002",
						File:    "dist/index.js",
						Hash:    "sha256:def456",
						Reason:  "safe pattern",
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		pkg     string
		ver     string
		rule    string
		file    string
		hash    string
		wantOk  bool
		wantReason string
	}{
		{
			"exact match",
			"vite", "8.3.8", "SI-CODE-001", "dist/node/chunks/node.js", "sha256:abc123",
			true, "registry read only",
		},
		{
			"different package",
			"esbuild", "8.3.8", "SI-CODE-001", "dist/node/chunks/node.js", "sha256:abc123",
			false, "",
		},
		{
			"different version",
			"vite", "8.3.7", "SI-CODE-001", "dist/node/chunks/node.js", "sha256:abc123",
			false, "",
		},
		{
			"different rule",
			"vite", "8.3.8", "SI-CODE-002", "dist/node/chunks/node.js", "sha256:abc123",
			false, "",
		},
		{
			"different file",
			"vite", "8.3.8", "SI-CODE-001", "dist/other.js", "sha256:abc123",
			false, "",
		},
		{
			"different hash",
			"vite", "8.3.8", "SI-CODE-001", "dist/node/chunks/node.js", "sha256:xyz999",
			false, "",
		},
		{
			"sharp package match",
			"sharp", "0.33.0", "SI-CODE-002", "dist/index.js", "sha256:def456",
			true, "safe pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc, ok := p.LookupAcceptance(tt.pkg, tt.ver, tt.rule, tt.file, tt.hash)
			if ok != tt.wantOk {
				t.Errorf("LookupAcceptance() ok = %v, want %v", ok, tt.wantOk)
				return
			}
			if ok && acc.Reason != tt.wantReason {
				t.Errorf("LookupAcceptance() reason = %q, want %q", acc.Reason, tt.wantReason)
			}
		})
	}
}

func TestAcceptFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".safe-install.json")

	// Step 1: Accept a new finding
	err := AcceptFinding(path, "vite", "8.3.8", "SI-CODE-001", "dist/node/chunks/node.js", "sha256:abc123", "registry read only", "2027-05-12")
	if err != nil {
		t.Fatalf("AcceptFinding() error = %v", err)
	}

	// Step 2: Verify it was written
	f, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if len(f.AcceptFindings["vite"]) != 1 {
		t.Errorf("AcceptFindings[vite] length = %d, want 1", len(f.AcceptFindings["vite"]))
		return
	}

	acc := f.AcceptFindings["vite"][0]
	if acc.Reason != "registry read only" {
		t.Errorf("Reason = %q, want %q", acc.Reason, "registry read only")
	}
	if acc.Rule != "SI-CODE-001" {
		t.Errorf("Rule = %q, want %q", acc.Rule, "SI-CODE-001")
	}
	if acc.Hash != "sha256:abc123" {
		t.Errorf("Hash = %q, want %q", acc.Hash, "sha256:abc123")
	}
	if acc.Expires != "2027-05-12" {
		t.Errorf("Expires = %q, want %q", acc.Expires, "2027-05-12")
	}
	if acc.Version != "8.3.8" {
		t.Errorf("Version = %q, want %q", acc.Version, "8.3.8")
	}
	if acc.At == "" {
		t.Errorf("At is empty, want current date")
	}

	// Step 3: Add another for same package, different rule
	err = AcceptFinding(path, "vite", "8.3.8", "SI-CODE-002", "dist/other.js", "sha256:def456", "another reason", "")
	if err != nil {
		t.Fatalf("Second AcceptFinding() error = %v", err)
	}

	f, err = Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if len(f.AcceptFindings["vite"]) != 2 {
		t.Errorf("AcceptFindings[vite] length after second = %d, want 2", len(f.AcceptFindings["vite"]))
	}

	// Step 4: Invalid expiry should error
	err = AcceptFinding(path, "esbuild", "0.25.10", "SI-CODE-001", "dist/index.js", "sha256:xyz", "test", "not-a-date")
	if err == nil {
		t.Errorf("AcceptFinding() with invalid expiry should error")
	}
}

func TestRevokeFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".safe-install.json")

	// Setup: write two acceptances
	AcceptFinding(path, "vite", "8.3.8", "SI-CODE-001", "dist/node/chunks/node.js", "sha256:abc123", "reason1", "")
	AcceptFinding(path, "vite", "8.3.8", "SI-CODE-002", "dist/other.js", "sha256:def456", "reason2", "")

	// Test revoke first one
	ok, err := RevokeFinding(path, "vite", "8.3.8", "SI-CODE-001", "dist/node/chunks/node.js")
	if err != nil {
		t.Fatalf("RevokeFinding() error = %v", err)
	}
	if !ok {
		t.Errorf("RevokeFinding() ok = %v, want true", ok)
	}

	f, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if len(f.AcceptFindings["vite"]) != 1 {
		t.Errorf("AcceptFindings[vite] after revoke = %d, want 1", len(f.AcceptFindings["vite"]))
	}
	if f.AcceptFindings["vite"][0].Rule != "SI-CODE-002" {
		t.Errorf("Remaining rule = %q, want %q", f.AcceptFindings["vite"][0].Rule, "SI-CODE-002")
	}

	// Test revoke non-existent
	ok, err = RevokeFinding(path, "esbuild", "0.25.10", "SI-CODE-001", "dist/index.js")
	if err != nil {
		t.Fatalf("RevokeFinding() non-existent error = %v", err)
	}
	if ok {
		t.Errorf("RevokeFinding() non-existent ok = %v, want false", ok)
	}

	// Test revoke last one
	ok, err = RevokeFinding(path, "vite", "8.3.8", "SI-CODE-002", "dist/other.js")
	if err != nil {
		t.Fatalf("RevokeFinding() last error = %v", err)
	}
	if !ok {
		t.Errorf("RevokeFinding() last ok = %v, want true", ok)
	}

	f, err = Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(f.AcceptFindings["vite"]) != 0 {
		t.Errorf("AcceptFindings[vite] after revoking all = %d, want 0", len(f.AcceptFindings["vite"]))
	}
}

func TestFileBackwardsCompatibility(t *testing.T) {
	// Test that old .safe-install.json without acceptFindings field parses OK
	data := []byte(`{
  "minReleaseAge": "3d",
  "failOn": "high",
  "allowScripts": {
    "esbuild": { "version": "0.25.10", "hash": "sha256-..." }
  }
}`)

	var f File
	err := json.Unmarshal(data, &f)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if f.AcceptFindings == nil {
		f.AcceptFindings = map[string][]Acceptance{} // should be OK to initialize
	}

	if f.MinReleaseAge != "3d" {
		t.Errorf("MinReleaseAge = %q, want %q", f.MinReleaseAge, "3d")
	}
	if f.FailOn != "high" {
		t.Errorf("FailOn = %q, want %q", f.FailOn, "high")
	}
}

func TestAcceptFindingsOverlay(t *testing.T) {
	// Test that org policy acceptFindings are overlaid correctly
	orgPolicy := &File{
		AcceptFindings: map[string][]Acceptance{
			"vite": {
				{Rule: "SI-CODE-001", File: "dist/index.js", Hash: "sha256:org", Reason: "org acceptance"},
			},
		},
	}

	projectFile := &File{
		AcceptFindings: map[string][]Acceptance{
			"vite": {
				{Rule: "SI-CODE-002", File: "dist/other.js", Hash: "sha256:proj", Reason: "project acceptance"},
			},
		},
	}

	p := &Policy{File: File{AcceptFindings: map[string][]Acceptance{}}}
	p.overlay(orgPolicy)
	p.overlay(projectFile)

	if len(p.AcceptFindings["vite"]) != 2 {
		t.Errorf("AcceptFindings[vite] after overlay = %d, want 2", len(p.AcceptFindings["vite"]))
	}

	// Both should be present
	hasOrg := false
	hasProj := false
	for _, acc := range p.AcceptFindings["vite"] {
		if acc.Rule == "SI-CODE-001" {
			hasOrg = true
		}
		if acc.Rule == "SI-CODE-002" {
			hasProj = true
		}
	}
	if !hasOrg {
		t.Errorf("Org policy acceptance not found in overlay")
	}
	if !hasProj {
		t.Errorf("Project acceptance not found in overlay")
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findIn(s, substr)))
}

func findIn(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
