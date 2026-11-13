package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
	"github.com/crossben/safe-install/internal/policy"
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

func TestFindLineOtherLockfiles(t *testing.T) {
	cases := []struct {
		data, name, version string
		want                int
	}{
		{"version = 1\n\n[[package]]\nname = \"flask\"\nversion = \"3.0.3\"\n", "flask", "3.0.3", 4},
		{"# hdr\nblinker==1.9.0 \\\n    --hash=sha256:aa\nZope.Interface == 6.0\n", "zope-interface", "6.0", 4},
		{"{\n    \"packages\": [\n        {\n            \"name\": \"monolog/monolog\",\n            \"version\": \"3.7.0\",\n", "monolog/monolog", "3.7.0", 4},
		{"{\n  \"default\": {\n    \"flask\": {\n      \"version\": \"==3.0.3\"\n", "flask", "3.0.3", 3},
	}
	for _, c := range cases {
		if got := findLine([]byte(c.data), c.name, c.version); got != c.want {
			t.Errorf("%s@%s: line %d, want %d", c.name, c.version, got, c.want)
		}
	}
}

func acceptedReport() *analyze.Report {
	acc := &policy.Acceptance{Reason: "Microsoft", By: "ben", Expires: "2999-01-01"}
	mk := func(id string, fs ...analyze.Finding) analyze.Result {
		name, ver, _ := strings.Cut(id, "@")
		res := analyze.Result{Package: &lockfile.Package{ID: id, Name: name, Version: ver}, Findings: fs}
		res.Score, res.Level = analyze.Score(fs)
		return res
	}
	return &analyze.Report{Format: lockfile.NPMv3, Results: []analyze.Result{
		// Two accepted highs in one package: counted as findings, never subtracted from packages.
		mk("a@1.0.0",
			analyze.Finding{Rule: "SI-CODE-001", Severity: analyze.High, Message: "x.js bad", File: "x.js", Accepted: acc},
			analyze.Finding{Rule: "SI-CODE-002", Severity: analyze.High, Message: "y.js bad", File: "y.js", Accepted: acc}),
		mk("b@1.0.0", analyze.Finding{Rule: "SI-REC-002", Severity: analyze.High, Message: "m"}),
		mk("c@1.0.0"),
	}}
}

func TestTextAcceptedAndSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, acceptedReport(), "package-lock.json"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"ACCEPTED (Microsoft, by ben, until 2999-01-01)", "0 block, 1 high (2 accepted), 0 medium, 0 low, 2 clean"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestMarkdownAcceptedSection(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, acceptedReport(), "package-lock.json"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<details>", "2 accepted finding(s)", "`a@1.0.0` `SI-CODE-001` `x.js`", "`Microsoft, by ben, until 2999-01-01`", "1 high (2 accepted)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "| HIGH | `a@1.0.0`") {
		t.Errorf("fully accepted package listed as risky:\n%s", out)
	}
}

func TestJSONAndSARIFAccepted(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, acceptedReport(), "package-lock.json"); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, `"accepted": {`) || !strings.Contains(out, `"file": "x.js"`) || !strings.Contains(out, `"worst": "high"`) {
		t.Errorf("json:\n%s", out)
	}
	buf.Reset()
	if err := SARIF(&buf, acceptedReport(), "package-lock.json", []byte("{}"), "test"); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); strings.Count(out, `"kind": "external"`) != 2 || !strings.Contains(out, `"justification": "Microsoft"`) {
		t.Errorf("sarif:\n%s", out)
	}
}

func TestAcceptedNoteNeutralisesControlCharacters(t *testing.T) {
	note := AcceptedNote(&policy.Acceptance{Reason: "ok\nfake line \x1b[31mred", By: "me\r\x9b", Expires: "2999\x00"})
	for _, r := range note {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			t.Fatalf("control character %q left in %q", r, note)
		}
	}
	if !strings.Contains(note, "ok fake line") || !strings.Contains(note, "[31mred") {
		t.Errorf("note %q", note)
	}
}
