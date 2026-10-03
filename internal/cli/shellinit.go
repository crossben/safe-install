package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Subcommands routed through safe-install, per package manager. Bare `yarn`
// installs too.
var wrapped = []struct {
	pm, install, add string // space-separated subcommands
	bare             bool
}{
	{"npm", "install i", "", false}, // npm adds with install
	{"pnpm", "install i", "add", false},
	{"yarn", "install", "add", true},
	{"bun", "install i", "add", false},
}

func newShellInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell-init <bash|zsh|fish|pwsh>",
		Short: "Print shell functions that route installs through safe-install",
		Long: "Prints functions wrapping npm, pnpm, yarn and bun so their install and add\n" +
			"commands go through safe-install. Nothing is changed for you; add it yourself:\n\n" +
			"  bash/zsh:  eval \"$(safe-install shell-init bash)\"   in ~/.bashrc or ~/.zshrc\n" +
			"  fish:      safe-install shell-init fish | source     in config.fish\n" +
			"  pwsh:      safe-install shell-init pwsh | Invoke-Expression   in $PROFILE",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "pwsh"},
		RunE: func(cmd *cobra.Command, args []string) error {
			var b strings.Builder
			for _, w := range wrapped {
				switch args[0] {
				case "bash", "zsh":
					posixFunc(&b, w.pm, w.install, w.add, w.bare)
				case "fish":
					fishFunc(&b, w.pm, w.install, w.add, w.bare)
				case "pwsh":
					pwshFunc(&b, w.pm, w.install, w.add, w.bare)
				default:
					return fmt.Errorf("unsupported shell %q (bash, zsh, fish, pwsh)", args[0])
				}
			}
			_, err := fmt.Fprint(cmd.OutOrStdout(), b.String())
			return err
		},
	}
}

func posixFunc(b *strings.Builder, pm, install, add string, bare bool) {
	fmt.Fprintf(b, "%s() {\n  case \"$1\" in\n", pm)
	installCase := strings.ReplaceAll(install, " ", "|")
	if bare {
		installCase = `""|` + installCase
	}
	fmt.Fprintf(b, "    %s) [ $# -gt 0 ] && shift; command safe-install install --pm %s -- \"$@\" ;;\n", installCase, pm)
	if add != "" {
		fmt.Fprintf(b, "    %s) shift; command safe-install add --pm %s -- \"$@\" ;;\n", strings.ReplaceAll(add, " ", "|"), pm)
	}
	fmt.Fprintf(b, "    *) command %s \"$@\" ;;\n  esac\n}\n", pm)
}

func fishFunc(b *strings.Builder, pm, install, add string, bare bool) {
	fmt.Fprintf(b, "function %s\n", pm)
	if bare {
		fmt.Fprintf(b, "  if test (count $argv) -eq 0\n    safe-install install --pm %s\n    return\n  end\n", pm)
	}
	fmt.Fprintf(b, "  switch $argv[1]\n    case %s\n      safe-install install --pm %s -- $argv[2..-1]\n", install, pm)
	if add != "" {
		fmt.Fprintf(b, "    case %s\n      safe-install add --pm %s -- $argv[2..-1]\n", add, pm)
	}
	fmt.Fprintf(b, "    case '*'\n      command %s $argv\n  end\nend\n", pm)
}

func pwshFunc(b *strings.Builder, pm, install, add string, bare bool) {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, " ", "','") + "'" }
	fmt.Fprintf(b, "function %s {\n", pm)
	fmt.Fprintf(b, "  $rest = @($args | Select-Object -Skip 1)\n")
	cond := fmt.Sprintf("@(%s) -contains $args[0]", quote(install))
	if bare {
		cond = "$args.Count -eq 0 -or " + cond
	}
	fmt.Fprintf(b, "  if (%s) { safe-install install --pm %s -- @rest }\n", cond, pm)
	if add != "" {
		fmt.Fprintf(b, "  elseif (@(%s) -contains $args[0]) { safe-install add --pm %s -- @rest }\n", quote(add), pm)
	}
	fmt.Fprintf(b, "  else { & (Get-Command %s -CommandType Application | Select-Object -First 1) @args }\n}\n", pm)
}
