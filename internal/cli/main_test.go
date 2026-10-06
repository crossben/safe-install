package cli

import (
	"os"
	"testing"

	"github.com/crossben/safe-install/internal/scriptshell"
)

// The runtime monitor re-runs the current executable as the script shell; in
// tests that is this test binary.
func TestMain(m *testing.M) {
	if code, ok := scriptshell.Run(os.Args); ok {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
