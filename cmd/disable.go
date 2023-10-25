package cmd

import (
	"github.com/spf13/cobra"
	GitConfig "github.com/zricethezav/gitleaks/v8/lib"
)

func init() {
	rootCmd.AddCommand(disableCmd)
}

var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable gitleaks in pre-commit script",
	Run:   runDisable,
}

func runDisable(cmd *cobra.Command, args []string) {
	GitConfig.SetGitleaksConfig("enable", "false")
	GitConfig.SetGitleaksConfig("url", "")

	GitConfig.DisableGitHooks(GitConfig.PreCommitScriptPath, GitConfig.PreCommitScript)
	GitConfig.DisableGitHooks(GitConfig.PostCommitScriptPath, GitConfig.PostCommitScript)
}
