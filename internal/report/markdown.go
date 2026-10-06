package report

import (
	"io"
	"strings"
	"unicode"

	"github.com/crossben/safe-install/internal/analyze"
)

// MarkdownMarker starts every Markdown report, so a CI job can find and
// update its earlier pull request comment.
const MarkdownMarker = "<!-- safe-install-report -->"

// maxMarkdownPackages keeps a comment readable (and under GitHub's size limit).
const maxMarkdownPackages = 50

// Markdown writes a short report for a pull request comment or job summary:
// the risky packages, worst first. Package names and finding messages come
// from the packages themselves, so every one is put in a code span: a
// malicious package cannot add links, images, HTML or @mentions.
func Markdown(w io.Writer, r *analyze.Report, source string) error {
	ew := &errWriter{w: w}
	ew.printf("%s\n### safe-install\n\n", MarkdownMarker)
	if r.Base != "" {
		ew.printf("Checked %d new or changed package(s) in %s versus %s.\n\n", len(r.Results), code(source), code(r.Base))
	} else {
		ew.printf("Checked %d package(s) in %s.\n\n", len(r.Results), code(source))
	}

	counts := map[analyze.Level]int{}
	var risky []analyze.Result
	for lvl := analyze.LevelBlock; lvl > analyze.LevelNone; lvl-- {
		for _, res := range r.Results {
			if res.Err == nil && res.Level == lvl {
				risky = append(risky, res)
			}
		}
	}
	for _, res := range r.Results {
		if res.Err == nil {
			counts[res.Level]++
		}
	}

	if len(risky) == 0 {
		ew.printf("No risky packages found.\n")
	} else {
		ew.printf("| Level | Package | Score | Findings |\n|---|---|---|---|\n")
		for i, res := range risky {
			if i == maxMarkdownPackages {
				ew.printf("\n…and %d more; run `safe-install check` for the full list.\n", len(risky)-i)
				break
			}
			var fs []string
			for _, f := range res.Findings {
				fs = append(fs, code(f.Rule)+" "+code(clip(f.Message, 160)))
			}
			ew.printf("| %s | %s%s | %d | %s |\n", strings.ToUpper(res.Level.String()), code(res.Package.ID), tags(res), res.Score, strings.Join(fs, "<br>"))
		}
	}
	for _, warn := range r.Warnings {
		ew.printf("\n> warning: %s\n", code(warn))
	}
	if failed := r.Failed(); failed > 0 {
		ew.printf("\nCould not check %d package(s).\n", failed)
	}
	ew.printf("\n%d block, %d high, %d medium, %d low, %d clean\n",
		counts[analyze.LevelBlock], counts[analyze.LevelHigh], counts[analyze.LevelMedium],
		counts[analyze.LevelLow], counts[analyze.LevelNone])
	return ew.err
}

// code renders s as an inline code span, which Markdown shows literally.
// Backticks become ', and pipes and control characters (which would break
// the table or the span) are replaced, so s cannot end the span early.
func code(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '`':
			return '\''
		case r == '|':
			return '¦'
		case unicode.IsControl(r), r == ' ', r == ' ':
			return ' '
		}
		return r
	}, s)
	return "`" + strings.TrimSpace(s) + "`"
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
