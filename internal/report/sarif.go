package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/crossben/safe-install/internal/analyze"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	FullDescription  sarifMessage `json:"fullDescription"`
	Help             sarifMessage `json:"help"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

// SARIF writes a SARIF 2.1.0 log for code scanning. uri is the lockfile path
// relative to the repository root; lockData is used to point at each
// package's line.
func SARIF(w io.Writer, r *analyze.Report, uri string, lockData []byte, toolVersion string) error {
	rules := []sarifRule{}
	for _, e := range analyze.Explanations() {
		rules = append(rules, sarifRule{
			ID: e.ID, Name: e.Title,
			ShortDescription: sarifMessage{e.Title},
			FullDescription:  sarifMessage{e.Why},
			Help:             sarifMessage{e.Fix},
		})
	}
	results := []sarifResult{}
	for _, res := range r.Results {
		for _, f := range res.Findings {
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			loc.PhysicalLocation.Region.StartLine = findLine(lockData, res.Package.Name, res.Package.Version)
			sum := sha256.Sum256([]byte(f.Rule + "\x00" + res.Package.ID + "\x00" + f.Message))
			results = append(results, sarifResult{
				RuleID:              f.Rule,
				Level:               sarifLevel(f.Severity),
				Message:             sarifMessage{res.Package.ID + ": " + f.Message},
				Locations:           []sarifLocation{loc},
				PartialFingerprints: map[string]string{"safeInstall/v1": hex.EncodeToString(sum[:16])},
			})
		}
	}
	doc := map[string]any{
		"$schema": sarifSchema,
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "safe-install",
				"version":        toolVersion,
				"informationUri": "https://github.com/crossben/safe-install",
				"rules":          rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s analyze.Severity) string {
	switch s {
	case analyze.Block, analyze.High:
		return "error"
	case analyze.Medium:
		return "warning"
	}
	return "note"
}

// findLine returns the 1-based line where a package appears in a lockfile:
// its npm install path, else "name@version" (pnpm, yarn, bun), else 1.
func findLine(data []byte, name, version string) int {
	for _, needle := range []string{`"node_modules/` + name + `"`, name + "@" + version} {
		if i := bytes.Index(data, []byte(needle)); i >= 0 {
			return bytes.Count(data[:i], []byte("\n")) + 1
		}
	}
	return 1
}
