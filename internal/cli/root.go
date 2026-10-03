// Package cli wires the safe-install commands.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes (plan §8).
const (
	ExitOK            = 0
	ExitPolicyFailure = 1
	ExitAborted       = 2
	ExitToolError     = 3
)

// Global flags shared by every command.
type globalFlags struct {
	pm       string
	yes      bool
	ci       bool
	format   string
	offline  bool
	registry string
	minAge   string
}

// exitError carries a specific exit code up to Execute.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func newRootCmd() *cobra.Command {
	var g globalFlags

	root := &cobra.Command{
		Use:           "safe-install",
		Short:         "Install dependencies. Not malware.",
		Long:          "safe-install analyzes your dependency tree, installs with lifecycle scripts\ndisabled, and runs only the scripts you approved.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          installArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, &g, args)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&g.pm, "pm", "", "package manager to use (npm, pnpm, yarn, bun); detected when empty")
	pf.BoolVarP(&g.yes, "yes", "y", false, "answer yes to prompts")
	pf.BoolVar(&g.ci, "ci", false, "non-interactive mode; fail on policy violations")
	pf.StringVar(&g.format, "format", "text", "output format: text, json, sarif")
	pf.BoolVar(&g.offline, "offline", false, "use cached registry data only")
	pf.StringVar(&g.registry, "registry", "", "registry URL (default https://registry.npmjs.org)")
	pf.StringVar(&g.minAge, "min-age", "72h", "minimum release age, e.g. 72h or 3d; 0 disables")

	root.AddCommand(newInstallCmd(&g), newCheckCmd(&g), newVersionCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "safe-install:", err)
		var ee *exitError
		if errors.As(err, &ee) {
			return ee.code
		}
		return ExitToolError
	}
	return ExitOK
}
