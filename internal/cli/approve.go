package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crossben/safe-install/internal/analyze"
	"github.com/crossben/safe-install/internal/policy"
	"github.com/crossben/safe-install/internal/scripts"
)

func newApproveCmd(g *globalFlags) *cobra.Command {
	var revoke, global, force, noRun bool
	cmd := &cobra.Command{
		Use:   "approve <package>...",
		Short: "Approve packages' install scripts and run them",
		Long: "Records an approval pinned to the scripts' content (and the files they run),\n" +
			"then runs them. A later change to the scripts needs a new approval.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, names []string) error {
			s, err := newSession(cmd, g)
			if err != nil {
				return err
			}
			path := s.pol.ProjectPath
			if global {
				if path, err = policy.GlobalPath(); err != nil {
					return err
				}
			}
			if revoke {
				for _, name := range names {
					removed, err := policy.Revoke(path, name)
					if err != nil {
						return err
					}
					if removed {
						s.w.printf("revoked %s\n", name)
					} else {
						s.w.printf("%s was not approved in %s\n", name, path)
					}
				}
				return s.w.err
			}

			cands, graph, err := s.candidates()
			if err != nil {
				return err
			}
			var chosen []*scripts.Candidate
			for _, name := range names {
				found := false
				for _, c := range cands {
					if c.Package.Name != name {
						continue
					}
					found = true
					if c.Level >= analyze.LevelHigh && !force {
						describe(s.w, c)
						return fmt.Errorf("%s is %s risk; review the findings above and use --force to approve anyway", c.Package.ID, c.Level)
					}
					chosen = append(chosen, c)
				}
				if !found {
					return fmt.Errorf("%s has no install scripts in this project (installed with safe-install?)", name)
				}
			}
			for _, c := range chosen {
				if err := policy.Approve(path, c.Package.Name, policy.Approval{Version: c.Package.Version, Hash: c.Hash()}); err != nil {
					return err
				}
				s.w.printf("approved %s (%s)\n", c.Package.ID, strings.Join(c.Stages(), ", "))
			}
			if noRun {
				return s.w.err
			}
			return s.run(scripts.Order(chosen, graph))
		},
	}
	f := cmd.Flags()
	f.BoolVar(&revoke, "revoke", false, "remove the approvals instead")
	f.BoolVar(&global, "global", false, "record in the user config instead of the project's "+policy.FileName)
	f.BoolVar(&force, "force", false, "approve even high or blocking risk")
	f.BoolVar(&noRun, "no-run", false, "record the approval without running the scripts now")
	addMonitorFlag(cmd, g)
	return cmd
}

func newScriptsCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "scripts",
		Short: "List installed packages with install scripts and their approval state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := newSession(cmd, g)
			if err != nil {
				return err
			}
			cands, _, err := s.candidates()
			if err != nil {
				return err
			}
			w := &lineWriter{w: cmd.OutOrStdout()}
			if len(cands) == 0 {
				w.printf("No installed package has install scripts.\n")
				return w.err
			}
			for _, c := range cands {
				w.printf("\n%s  risk: %s  %s\n", c.Package.ID, strings.ToUpper(c.Level.String()), c.State)
				describeScripts(w, c)
			}
			return w.err
		},
	}
}

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain [rule-id]",
		Short: "Explain a rule, or list all rules",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w := &lineWriter{w: cmd.OutOrStdout()}
			if len(args) == 0 {
				for _, e := range analyze.Explanations() {
					w.printf("%s  %s\n", e.ID, e.Title)
				}
				return w.err
			}
			e, ok := analyze.Explain(args[0])
			if !ok {
				return fmt.Errorf("unknown rule %q; `safe-install explain` lists them", args[0])
			}
			w.printf("%s  %s\n\nWhy: %s\n\nWhat to do: %s\n", e.ID, e.Title, e.Why, e.Fix)
			return w.err
		},
	}
}
