package scripts

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
)

// maxScanBytes bounds how much of a script file is read.
const maxScanBytes = 2 << 20

type pattern struct {
	rule string
	sev  analyze.Severity
	what string
	re   *regexp.Regexp
}

var patterns = []pattern{
	{"SI-SCR-002", analyze.Block, "downloads and executes code",
		regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|node|python3?|perl)\b`)},
	{"SI-SCR-002", analyze.Block, "downloads and executes code",
		regexp.MustCompile(`(?i)\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*(iex|invoke-expression)\b`)},
	{"SI-SCR-002", analyze.Block, "runs encoded PowerShell",
		regexp.MustCompile(`(?i)\bpowershell(\.exe)?\b[^\n]*\s-e(nc|ncodedcommand)?\s`)},
	{"SI-SCR-003", analyze.High, "evaluates dynamic code",
		regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(`)},
	{"SI-SCR-003", analyze.High, "contains a long encoded blob",
		regexp.MustCompile(`[A-Za-z0-9+/]{300,}={0,2}|(\\x[0-9a-fA-F]{2}){40,}`)},
	{"SI-SCR-004", analyze.High, "touches credentials",
		regexp.MustCompile(`(?i)\.ssh\b|id_rsa|id_ed25519|\.npmrc|\.git-credentials|\.aws/credentials|\.config/gcloud|\.docker/config\.json|Login Data|\bNPM_TOKEN\b|\bGITHUB_TOKEN\b|\bGH_TOKEN\b|\bAWS_SECRET_ACCESS_KEY\b`)},
}

// Scan flags the candidate's scripts and the files they run with node.
func Scan(c *Candidate) []analyze.Finding {
	var out []analyze.Finding
	seen := map[string]bool{}
	add := func(rule string, sev analyze.Severity, msg string) {
		if !seen[rule+msg] {
			seen[rule+msg] = true
			out = append(out, analyze.Finding{Rule: rule, Severity: sev, Message: msg})
		}
	}

	stages := c.Stages()
	if len(stages) > 0 {
		add("SI-SCR-001", analyze.Medium, "runs install scripts: "+strings.Join(stages, ", "))
	}
	for _, stage := range stages {
		cmd := c.Scripts[stage]
		for _, p := range patterns {
			if p.re.MatchString(cmd) {
				add(p.rule, p.sev, fmt.Sprintf("%s script %s", stage, p.what))
			}
		}
		for _, f := range nodeFiles(c.Dir, cmd) {
			body := readCapped(filepath.Join(c.Dir, f))
			for _, p := range patterns {
				if p.re.Match(body) {
					add(p.rule, p.sev, fmt.Sprintf("%s (run by %s) %s", f, stage, p.what))
				}
			}
		}
	}
	return out
}

// nodeFiles returns the files a command runs with node ("node install.js",
// "node ./scripts/postinstall"), relative to dir and never outside it.
func nodeFiles(dir, cmd string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	for _, part := range regexp.MustCompile(`&&|\|\||;`).Split(cmd, -1) {
		fields := strings.Fields(part)
		if len(fields) < 2 || fields[0] != "node" {
			continue
		}
		for _, arg := range fields[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			rel := filepath.Clean(filepath.FromSlash(arg))
			if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				break
			}
			for _, cand := range []string{rel, rel + ".js", filepath.Join(rel, "index.js")} {
				if st, err := os.Stat(filepath.Join(dir, cand)); err == nil && st.Mode().IsRegular() {
					out = append(out, filepath.ToSlash(cand))
					break
				}
			}
			break
		}
	}
	return out
}

func readCapped(path string) []byte {
	f, err := os.Open(path) // #nosec G304 -- file inside an installed package, checked by nodeFiles
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, maxScanBytes))
	return b
}
