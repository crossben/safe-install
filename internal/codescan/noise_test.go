package codescan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNoise scans every package of a real node_modules and prints what it
// finds. Run it when tuning rules:
//
//	SAFE_INSTALL_NOISE_DIR=/path/to/project/node_modules go test ./internal/codescan -run Noise -v
func TestNoise(t *testing.T) {
	root := os.Getenv("SAFE_INSTALL_NOISE_DIR")
	if root == "" {
		t.Skip("set SAFE_INSTALL_NOISE_DIR to a node_modules directory")
	}
	var dirs []string
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		switch {
		case !e.IsDir() || strings.HasPrefix(e.Name(), "."):
		case strings.HasPrefix(e.Name(), "@"):
			scoped, _ := os.ReadDir(filepath.Join(root, e.Name()))
			for _, s := range scoped {
				dirs = append(dirs, filepath.Join(root, e.Name(), s.Name()))
			}
		default:
			dirs = append(dirs, filepath.Join(root, e.Name()))
		}
	}
	start := time.Now()
	flagged := 0
	for _, d := range dirs {
		if fs := Package(d); len(fs) > 0 {
			flagged++
			rel, _ := filepath.Rel(root, d)
			for _, f := range fs {
				t.Logf("%-40s %s %s  %s", rel, f.Rule, f.Severity, f.Message)
			}
		}
	}
	t.Logf("%d packages, %d flagged, %s", len(dirs), flagged, time.Since(start).Round(time.Millisecond))
}
