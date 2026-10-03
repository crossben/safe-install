package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/pm"
)

func newInstallCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "install [-- <package manager args>]",
		Short: "Install dependencies with lifecycle scripts disabled",
		Example: "  safe-install install\n" +
			"  safe-install install -- --omit=dev",
		Args: installArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, g, args)
		},
	}
}

// installArgs accepts arguments only after "--"; they go to the package manager.
func installArgs(cmd *cobra.Command, args []string) error {
	if dash := cmd.ArgsLenAtDash(); len(args) > 0 && dash != 0 {
		return errors.New("unexpected arguments; to add a package use `safe-install add`, to pass flags to the package manager put them after --")
	}
	return nil
}

func runInstall(cmd *cobra.Command, g *globalFlags, pmArgs []string) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	det, err := pm.Detect(dir, g.pm)
	if err != nil {
		return err
	}
	adapter, err := pm.For(det.Kind)
	if err != nil {
		return err
	}

	stderr := cmd.ErrOrStderr()
	if _, err := fmt.Fprintf(stderr, "safe-install: using %s (%s); lifecycle scripts disabled\n", det.Kind, det.Source); err != nil {
		return err
	}
	if err := adapter.InstallNoScripts(cmd.Context(), dir, pmArgs, cmd.OutOrStdout(), stderr); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stderr, "safe-install: done; no install scripts were run")
	return err
}
