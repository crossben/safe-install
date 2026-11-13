package codescan

import (
	"regexp"
	"sort"
	"strings"
)

// maxFlaggedLines caps how many lines FlaggedLines returns.
const maxFlaggedLines = 10

// FlaggedLines returns the 1-based line numbers in src that trigger rule
// (the lines holding the patterns the rule looks for), ascending and capped.
// It returns nil for a rule it has no line-level patterns for, such as the
// Python and Composer rules. Findings carry no line numbers, so `accept` uses
// this to show a human what to review.
func FlaggedLines(src, rule string) []int {
	var pats []*regexp.Regexp
	switch rule {
	case "SI-CODE-001":
		pats = []*regexp.Regexp{execDownload, evalCall}
	case "SI-CODE-002":
		pats = []*regexp.Regexp{secretRef, netSend}
	case "SI-CODE-003":
		pats = []*regexp.Regexp{obfName, evalCall}
	default:
		return nil
	}
	seen := map[int]bool{}
	for _, re := range pats {
		for _, loc := range re.FindAllStringIndex(src, -1) {
			seen[1+strings.Count(src[:loc[0]], "\n")] = true
		}
	}
	lines := make([]int, 0, len(seen))
	for n := range seen {
		lines = append(lines, n)
	}
	sort.Ints(lines)
	if len(lines) > maxFlaggedLines {
		lines = lines[:maxFlaggedLines]
	}
	return lines
}
