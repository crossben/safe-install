package codescan

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/crossben/safe-install/internal/analyze"
)

// PHP patterns: the same combinations, in PHP's vocabulary.
var (
	phpExecDownload = regexp.MustCompile("(?i)\\b(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\\s*\\(\\s*[\\[(]?\\s*['\"][^)\\n]{0,300}?\\b(?:curl|wget|iwr|Invoke-WebRequest|DownloadString|certutil|bitsadmin)\\b|`[^`\\n]{0,300}\\b(?:curl|wget)\\b[^`\\n]*\\|\\s*(?:sh|bash|php)\\b")
	phpNetCall      = regexp.MustCompile(`(?i)\bfile_get_contents\s*\(\s*['"]https?:|\bcurl_exec\s*\(|\bfsockopen\s*\(|\bstream_socket_client\s*\(|\bfopen\s*\(\s*['"]https?:|\bGuzzleHttp\\Client\b`)
	phpEvalCall     = regexp.MustCompile(`(?i)\b(?:eval|assert|create_function)\s*\(`)
	phpNetSend      = regexp.MustCompile(`(?i)\bcurl_exec\s*\(|\bfsockopen\s*\(|\bstream_socket_client\s*\(|\bmail\s*\(|\bfile_get_contents\s*\(\s*['"]https?:[^)]*stream_context_create`)
	phpSecretRef    = regexp.MustCompile(`\.ssh[/\\'"]|\bid_rsa\b|\bid_ed25519\b|\.npmrc\b|auth\.json\b|\.aws/credentials|\.git-credentials|\.config/gcloud|\b(?:COMPOSER_AUTH|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY)\b`)
	phpDecodeEval   = regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(\s*(?:@?\s*)?(?:gzinflate|gzuncompress|gzdecode|base64_decode|str_rot13|strrev|hex2bin|convert_uudecode)\s*\(`)
)

// scanPHP returns the code-scan rules a PHP file triggers.
func scanPHP(src string) []hit {
	var out []hit
	lower := strings.ToLower(src)
	if containsAny(lower, "curl", "wget", "iwr", "invoke-", "downloadstring", "certutil", "bitsadmin") && phpExecDownload.MatchString(src) {
		out = append(out, hit{"SI-CODE-001", analyze.High, "runs a downloader from code"})
	} else if containsAny(lower, "eval", "assert", "create_function") && phpEvalAfterNetwork(src) {
		out = append(out, hit{"SI-CODE-001", analyze.High, "evaluates code right after a network call"})
	}
	if containsAny(src, ".ssh", "id_rsa", "id_ed25519", ".npmrc", "auth.json", ".aws", ".git-credentials", "gcloud", "_TOKEN", "COMPOSER_AUTH", "AWS_SECRET") &&
		phpSecretRef.MatchString(src) && nearEither(phpSecretRef, phpNetSend, src, exfilWindow) {
		out = append(out, hit{"SI-CODE-002", analyze.High, "reads credentials next to a network send"})
	}
	if containsAny(lower, "eval", "assert") && phpDecodeEval.MatchString(src) {
		out = append(out, hit{"SI-CODE-003", analyze.Medium, "evaluates decoded or decompressed data (eval(base64_decode(…)))"})
	}
	return out
}

func phpEvalAfterNetwork(src string) bool {
	for _, loc := range phpEvalCall.FindAllStringIndex(src, 200) {
		if loc[0] > 0 && (src[loc[0]-1] == '>' || src[loc[0]-1] == ':') {
			continue // $obj->eval(…), Foo::assert(…): methods, not the builtin
		}
		if evaluatesLiteral(src[loc[1]:]) {
			continue
		}
		if phpNetCall.MatchString(src[max(0, loc[0]-evalWindow):loc[0]]) {
			return true
		}
	}
	return false
}

// ComposerDist scans a Composer dist (a zip, usually a GitHub zipball) in
// memory: its PHP files, minus tests and docs.
func ComposerDist(data []byte) ([]analyze.Finding, error) {
	c := &collector{byRule: map[string]*agg{}}
	err := walkZip(data, func(entry string, size int64, open func() (io.Reader, error)) error {
		rel, ok := safeRel(entry)
		if !ok || size > maxFileBytes || !strings.HasSuffix(strings.ToLower(rel), ".php") {
			return nil
		}
		// Drop the archive's top directory ("vendor-name-<commit>/").
		if _, after, found := strings.Cut(rel, "/"); found {
			rel = after
		}
		if notInstalled(rel) {
			return nil
		}
		r, err := open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(r, maxFileBytes))
		if err != nil {
			return err
		}
		if c.total += int64(len(data)); c.total > maxPackageBytes {
			return errBudget
		}
		for _, h := range scanPHP(string(data)) {
			a := c.byRule[h.rule]
			if a == nil {
				a = &agg{sev: h.sev, files: map[string]string{}}
				c.byRule[h.rule] = a
			}
			a.files[rel] = h.what
		}
		return nil
	})
	if err != nil && !errors.Is(err, errBudget) {
		return nil, fmt.Errorf("reading Composer dist: %w", err)
	}
	return c.findings(), nil
}
