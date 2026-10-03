package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
)

const lock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/evil": {
      "version": "1.0.0"
    },
    "node_modules/fresh": {
      "version": "2.0.0"
    }
  }
}
`

func TestSARIF(t *testing.T) {
	rep := &analyze.Report{Format: lockfile.NPMv3, Results: []analyze.Result{
		{Package: &lockfile.Package{ID: "evil@1.0.0", Name: "evil", Version: "1.0.0"}, Level: analyze.LevelBlock,
			Findings: []analyze.Finding{{Rule: "SI-VUL-001", Severity: analyze.Block, Message: "known malicious package (MAL-1)"}}},
		{Package: &lockfile.Package{ID: "fresh@2.0.0", Name: "fresh", Version: "2.0.0"}, Level: analyze.LevelMedium,
			Findings: []analyze.Finding{{Rule: "SI-REC-001", Severity: analyze.Medium, Message: "published 2h ago"}}},
		{Package: &lockfile.Package{ID: "clean@1.0.0", Name: "clean", Version: "1.0.0"}},
	}}
	var buf bytes.Buffer
	if err := SARIF(&buf, rep, "web/package-lock.json", []byte(lock), "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }    `json:"artifactLocation"`
						Region           struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Version != "2.1.0" || doc.Schema == "" || len(doc.Runs) != 1 {
		t.Fatalf("envelope: %+v", doc)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "safe-install" || run.Tool.Driver.Version != "1.2.3" || len(run.Tool.Driver.Rules) != len(analyze.Explanations()) {
		t.Fatalf("driver: %+v", run.Tool.Driver)
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	evil, fresh := run.Results[0], run.Results[1]
	if evil.RuleID != "SI-VUL-001" || evil.Level != "error" || evil.Message.Text != "evil@1.0.0: known malicious package (MAL-1)" {
		t.Errorf("evil: %+v", evil)
	}
	loc := evil.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "web/package-lock.json" || loc.Region.StartLine != 5 {
		t.Errorf("evil location: %+v", loc)
	}
	if fresh.Level != "warning" || fresh.Locations[0].PhysicalLocation.Region.StartLine != 8 {
		t.Errorf("fresh: %+v", fresh)
	}
	if evil.PartialFingerprints["safeInstall/v1"] == "" {
		t.Error("missing fingerprint")
	}
}

func TestFindLine(t *testing.T) {
	tests := []struct {
		content, name, version string
		want                   int
	}{
		{lock, "fresh", "2.0.0", 8},
		{"lockfileVersion: '9.0'\npackages:\n  ms@2.1.3:\n    resolution: x\n", "ms", "2.1.3", 3},
		{"# yarn\n\n\"@esbuild/linux-x64@0.25.10\":\n  version \"0.25.10\"\n", "@esbuild/linux-x64", "0.25.10", 3},
		{"nothing here", "ms", "1.0.0", 1},
	}
	for _, tt := range tests {
		if got := findLine([]byte(tt.content), tt.name, tt.version); got != tt.want {
			t.Errorf("findLine(%s) = %d, want %d", tt.name, got, tt.want)
		}
	}
}
