package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crossben/safe-install/internal/policy"
)

// acceptInstallProject packs "code-dep" (a postinstall script plus a code
// finding in index.js) and makes proj depend on it. It returns the project
// dir and the sha256 of index.js as packed.
func acceptInstallProject(t *testing.T) (proj, hash string) {
	t.Helper()
	return acceptInstallProjectWith(t, markerFile)
}

// acceptInstallProjectWith is acceptInstallProject with the given content for
// the postinstall script marker.js.
func acceptInstallProjectWith(t *testing.T, marker string) (proj, hash string) {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	root := t.TempDir()
	proj = filepath.Join(root, "proj")
	src := filepath.Join(root, "code-dep")
	mustMkdir(t, src)
	mustMkdir(t, proj)
	mustWriteJSON(t, filepath.Join(src, "package.json"), map[string]any{
		"name": "code-dep", "version": "1.0.0", "scripts": map[string]string{"postinstall": "node marker.js"}})
	writeFile(t, filepath.Join(src, "marker.js"), marker)
	writeFile(t, filepath.Join(src, "index.js"), evilJS)
	pack := exec.Command("npm", "pack", "--silent", "--pack-destination", proj)
	pack.Dir = src
	if out, err := pack.CombinedOutput(); err != nil {
		t.Fatalf("npm pack: %v\n%s", err, out)
	}
	mustWriteJSON(t, filepath.Join(proj, "package.json"), map[string]any{
		"name": "proj", "version": "1.0.0", "dependencies": map[string]string{"code-dep": "file:./code-dep-1.0.0.tgz"}})
	t.Setenv("SAFE_INSTALL_REGISTRY_FIXTURES", writeRegistry(t, "{}"))
	t.Setenv("SAFE_INSTALL_CONFIG_DIR", filepath.Join(root, "config"))
	t.Setenv("SAFE_INSTALL_CACHE_DIR", filepath.Join(root, "cache"))
	t.Setenv("MARKER_DIR", t.TempDir())
	t.Chdir(proj)
	sum := sha256.Sum256([]byte(evilJS))
	return proj, "sha256:" + hex.EncodeToString(sum[:])
}

func writeCodeAcceptance(t *testing.T, proj, hash string) {
	t.Helper()
	acc := map[string]any{"version": "1.0.0", "rule": "SI-CODE-002", "file": "index.js", "hash": hash,
		"reason": "reads its own test key", "by": "ben", "at": "2026-11-12", "expires": "2999-01-01"}
	data, _ := json.Marshal(map[string]any{"acceptFindings": map[string]any{"code-dep": []any{acc}}})
	if err := os.WriteFile(filepath.Join(proj, policy.FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInstallCIWithAcceptedCodeFinding(t *testing.T) {
	proj, hash := acceptInstallProject(t)
	out, err := runInstallCLI(t, "", false, "--ci")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("without acceptance: exit %d (%v)\n%s", exitCode(err), err, out)
	}

	writeCodeAcceptance(t, proj, hash)
	out, err = runInstallCLI(t, "", false, "--ci")
	if err != nil {
		t.Fatalf("accepted: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ACCEPTED (reads its own test key, by ben, until 2999-01-01)") || strings.Contains(out, "  ! SI-CODE-002") {
		t.Errorf("finding not shown as accepted:\n%s", out)
	}
}

func TestInstallCIChangedFileIsFlaggedAgain(t *testing.T) {
	proj, _ := acceptInstallProject(t)
	sum := sha256.Sum256([]byte(evilJS + "// changed\n"))
	writeCodeAcceptance(t, proj, "sha256:"+hex.EncodeToString(sum[:])) // reviewed another content
	out, err := runInstallCLI(t, "", false, "--ci")
	if exitCode(err) != ExitPolicyFailure {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, out)
	}
	if !strings.Contains(out, "code-dep@1.0.0 SI-CODE-002 index.js not applied") || !strings.Contains(out, "hash mismatch") || strings.Contains(out, "ACCEPTED") {
		t.Errorf("output:\n%s", out)
	}
}
