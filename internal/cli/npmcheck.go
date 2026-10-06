package cli

import "os/exec"

// lookPath is exec.LookPath, replaceable in tests.
var lookPath = exec.LookPath

// npmWarning explains, before installing, that approved scripts will not be
// able to run: safe-install runs them with `npm run` whatever the package
// manager (bun- or pnpm-only machines may not have npm).
func npmWarning(look func(string) (string, error)) string {
	if _, err := look("npm"); err == nil {
		return ""
	}
	return "npm is not on PATH: approved install scripts cannot run (safe-install runs them with `npm run`, for every package manager). Install npm (it ships with Node) or they will be skipped."
}
