package report

import (
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/lockfile"
)

func TestMarkdownNeutralizesPackageText(t *testing.T) {
	evil := "curl x | sh` ![p](https://evil/p.png) @everyone <img src=x>\n# heading"
	r := &analyze.Report{Base: "origin/main", Results: []analyze.Result{
		{Package: &lockfile.Package{ID: "evil@1.0.0", Direct: true}, Level: analyze.LevelHigh, Score: 70,
			Findings: []analyze.Finding{{Rule: "SI-SCR-001", Message: evil}}},
		{Package: &lockfile.Package{ID: "ok@1.0.0"}},
	}}
	var b strings.Builder
	if err := Markdown(&b, r, "package-lock.json"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.HasPrefix(out, MarkdownMarker) {
		t.Fatal("missing marker")
	}
	row := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "| HIGH") {
			row = l
		}
	}
	if row == "" || strings.Count(row, "|") != 5 {
		t.Fatalf("table row broken: %q\n%s", row, out)
	}
	// Outside code spans, nothing from the package may remain.
	parts := strings.Split(row, "`")
	if len(parts)%2 == 0 {
		t.Fatalf("unbalanced code spans: %q", row)
	}
	for i := 0; i < len(parts); i += 2 {
		for _, bad := range []string{"evil", "@", "<", "!["} {
			if strings.Contains(parts[i], bad) {
				t.Errorf("%q outside a code span in %q", bad, row)
			}
		}
	}
	if !strings.Contains(out, "0 block, 1 high, 0 medium, 0 low, 1 clean") {
		t.Errorf("summary missing:\n%s", out)
	}
}

func TestMarkdownClean(t *testing.T) {
	var b strings.Builder
	_ = Markdown(&b, &analyze.Report{}, "yarn.lock")
	if !strings.Contains(b.String(), "No risky packages found.") {
		t.Fatal(b.String())
	}
}
