package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/policy"
)

func newAcceptCmd() *cobra.Command {
	var (
		file    string
		reason  string
		expires string
		global  bool
		revoke  bool
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "accept <package>@<version> <rule> [--file <path>] --reason \"...\" [--expires 90d|YYYY-MM-DD] [--global] [--revoke] [--force]",
		Short: "Record a code finding as reviewed and accepted",
		Long: "Mark a code finding as accepted after review. Accepted findings don't fail scans but remain visible.\n" +
			"Requires a TTY (not available in CI). Specify the file path if multiple files contain the finding.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccept(cmd, args, file, reason, expires, global, revoke, force)
		},
	}

	cmd.Flags().StringVar(&file, "file", "", "relative path to file in package (required if ambiguous)")
	cmd.Flags().StringVar(&reason, "reason", "", "why this finding is safe (required)")
	cmd.Flags().StringVar(&expires, "expires", "", "expiry date (YYYY-MM-DD) or duration (90d)")
	cmd.Flags().BoolVar(&global, "global", false, "write to user config instead of project .safe-install.json")
	cmd.Flags().BoolVar(&revoke, "revoke", false, "remove the acceptance instead of adding it")
	cmd.Flags().BoolVar(&force, "force", false, "override org policy block acceptance (requires explicit confirmation)")

	return cmd
}

func runAccept(cmd *cobra.Command, args []string, file, reason, expires string, global, revoke, force bool) error {
	// TTY check: only humans can accept findings
	st, err := os.Stdin.Stat()
	if err != nil || (st.Mode()&os.ModeCharDevice) == 0 {
		return errors.New("cannot accept findings without a terminal (not available in CI)")
	}

	pkg := args[0]
	rule := args[1]

	// Parse package@version
	parts := strings.Split(pkg, "@")
	if len(parts) != 2 {
		return fmt.Errorf("package must be in format package@version, got %q", pkg)
	}
	name, version := parts[0], parts[1]

	// Determine policy file path
	var policyPath string
	if global {
		var err error
		policyPath, err = policy.GlobalPath()
		if err != nil {
			return fmt.Errorf("could not determine global config path: %w", err)
		}
	} else {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		policyPath = fmt.Sprintf("%s/.safe-install.json", dir)
	}

	if revoke {
		// Revoke mode
		ok, err := policy.RevokeFinding(policyPath, name, version, rule, file)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no acceptance found for %s@%s rule %s file %s", name, version, rule, file)
		}
		fmt.Printf("Revoked acceptance for %s@%s %s\n", name, version, rule)
		return nil
	}

	// Accept mode
	if reason == "" {
		return errors.New("--reason is required to accept a finding")
	}

	// For now, show a simple confirmation
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Accept %s@%s %s?\n", name, version, rule)
	fmt.Printf("Reason: %s\n", reason)
	if expires != "" {
		fmt.Printf("Expires: %s\n", expires)
	}
	fmt.Print("Continue? [y/N] ")

	input, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	if strings.ToLower(strings.TrimSpace(input)) != "y" {
		return errors.New("acceptance cancelled")
	}

	// Accept the finding
	err = policy.AcceptFinding(policyPath, name, version, rule, file, "", reason, expires)
	if err != nil {
		return err
	}

	fmt.Printf("Accepted %s@%s %s in %s\n", name, version, rule, policyPath)
	return nil
}
