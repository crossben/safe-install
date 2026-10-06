// Package scriptshell is safe-install running as a package manager's script
// shell (`<shell> -c <script>`): it applies the sandbox and/or the runtime
// monitor to exactly the approved script, then runs it.
package scriptshell

import (
	"fmt"
	"os"
	"strings"

	"github.com/crossben/safe-install/internal/monitor"
	"github.com/crossben/safe-install/internal/sandbox"
)

// Environment passed by safe-install to itself.
const (
	envSandbox       = "SAFE_INSTALL_SANDBOX_PROJECT" // set: sandbox the script
	envSandboxNet    = "SAFE_INSTALL_SANDBOX_NET"     // "1": leave the network open
	envSandboxRO     = "SAFE_INSTALL_SANDBOX_RO"      // extra readable paths (path list)
	envSandboxActive = "SAFE_INSTALL_SANDBOX_ACTIVE"  // set inside a sandboxed script
)

// SandboxEnv is the environment that asks the script shell to sandbox scripts.
func SandboxEnv(project string, allowNet bool, readOnly []string) []string {
	net := "0"
	if allowNet {
		net = "1"
	}
	return []string{envSandbox + "=" + project, envSandboxNet + "=" + net,
		envSandboxRO + "=" + strings.Join(readOnly, string(os.PathListSeparator))}
}

// Run handles an invocation as script shell. ok is false when this process
// is not one (normal CLI use).
func Run(args []string) (code int, ok bool) {
	if len(args) < 3 || args[1] != "-c" {
		return 0, false
	}
	project := os.Getenv(envSandbox)
	if project == "" || os.Getenv(envSandboxActive) != "" {
		// Not sandboxed, or a nested script already inside the sandbox
		// (inherited): only the monitor may apply.
		return monitor.MaybeRunAsShell(args)
	}
	_ = os.Setenv(envSandboxActive, "1")
	cwd, _ := os.Getwd()
	p := sandbox.Policy{
		Project:  project,
		Package:  cwd, // package managers run scripts in the package directory
		AllowNet: os.Getenv(envSandboxNet) == "1",
	}
	if ro := os.Getenv(envSandboxRO); ro != "" {
		p.ReadOnly = strings.Split(ro, string(os.PathListSeparator))
	}
	if code, monitored := monitor.WillRun(args); monitored {
		if err := sandbox.Apply(p); err != nil {
			fmt.Fprintln(os.Stderr, "safe-install sandbox:", err)
			return 126, true
		}
		return code(), true
	}
	err := sandbox.Exec(p, args[2]) // only returns on failure
	fmt.Fprintln(os.Stderr, "safe-install sandbox:", err)
	return 126, true
}
