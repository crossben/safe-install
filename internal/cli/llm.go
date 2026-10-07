package cli

import (
	_ "embed"
	"io"

	"github.com/spf13/cobra"
)

// llmGuide is the guide `safe-install llm` prints, for AI coding agents.
//
//go:embed llm.md
var llmGuide string

func newLLMCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "llm",
		Short: "Print instructions for AI coding agents (paste into AGENTS.md or CLAUDE.md)",
		Long: "Prints a Markdown guide that tells an AI coding agent how to install packages\n" +
			"through safe-install and why it must never approve install scripts itself.\n" +
			"Example: safe-install llm >> AGENTS.md",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), llmGuide)
			return err
		},
	}
}
