// Package popularity knows which npm packages are popular (an embedded,
// download-ranked list) and fetches weekly download counts.
package popularity

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"
)

//go:embed top.txt
var topTxt string

// typosquatTargets is how many of the most popular names are protected.
const typosquatTargets = 1000

// List is a ranked list of popular package names.
type List struct {
	names []string
	rank  map[string]int
}

var (
	defaultOnce sync.Once
	defaultList *List
)

// Default returns the embedded list.
func Default() *List {
	defaultOnce.Do(func() {
		l := &List{rank: map[string]int{}}
		sc := bufio.NewScanner(strings.NewReader(topTxt))
		for sc.Scan() {
			name := strings.TrimSpace(sc.Text())
			if name == "" || strings.HasPrefix(name, "#") {
				continue
			}
			if _, dup := l.rank[name]; !dup {
				l.rank[name] = len(l.names)
				l.names = append(l.names, name)
			}
		}
		defaultList = l
	})
	return defaultList
}

// Len is the number of names in the list.
func (l *List) Len() int { return len(l.names) }

// Popular reports whether name is on the list.
func (l *List) Popular(name string) bool {
	_, ok := l.rank[name]
	return ok
}

// Rank returns name's position, 0 being the most downloaded.
func (l *List) Rank(name string) (int, bool) {
	r, ok := l.rank[name]
	return r, ok
}

// Typosquat returns the popular package name looks like an imitation of:
// identical once case and separators are ignored, or one edit away
// (insertion, deletion, substitution or swap). Popular names and scoped
// names are never flagged; short targets are skipped as too ambiguous.
func (l *List) Typosquat(name string) (string, bool) {
	if l.Popular(name) || strings.Contains(name, "/") {
		return "", false
	}
	lower := strings.ToLower(name)
	norm := normalize(lower)
	for _, t := range l.names[:min(typosquatTargets, len(l.names))] {
		if len(t) < 4 || strings.Contains(t, "/") {
			continue
		}
		if normalize(t) == norm {
			return t, true
		}
		if d := len(t) - len(lower); d >= -1 && d <= 1 && distance(lower, t, 1) == 1 {
			return t, true
		}
	}
	return "", false
}

func normalize(s string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(s))
}

// distance is the optimal-string-alignment edit distance between a and b,
// returning limit+1 as soon as it is known to exceed limit.
func distance(a, b string, limit int) int {
	if a == b {
		return 0
	}
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		best := cur[0]
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
			best = min(best, cur[j])
		}
		if best > limit {
			return limit + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(b)]
}
