package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	GitConfig "github.com/zricethezav/gitleaks/v8/lib"
)

func init() {
	enableCmd.Flags().String("url", "", "Backend URL")
	rootCmd.AddCommand(enableCmd)
}

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable gitleaks in pre-commit script",
	Run:   runEnable,
}

const PreCommitScript = `
#!/bin/sh
gitleaks protect --no-banner --verbose --staged
`

func runEnable(cmd *cobra.Command, args []string) {

	// Initialize Git Configs
	backendUrl, _ := cmd.Flags().GetString("url")
	GitConfig.SetGitleaksConfig("url", backendUrl)
	GitConfig.SetGitleaksConfig("enable", "true")

	GitConfig.EnableGitHooks(GitConfig.PreCommitScriptPath, GitConfig.PreCommitScript)
	GitConfig.EnableGitHooks(GitConfig.PostCommitScriptPath, GitConfig.PostCommitScript)

	fmt.Println("Gitleaks Version: ", Version)
}
