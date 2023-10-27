package cmd

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	Lib "github.com/zricethezav/gitleaks/v8/lib"
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
	if Lib.GetGitleaksConfigBoolean("debug") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Remove Config in .git/config : Gitleaks.enable to false
	// Lib.SetGitleaksConfig("enable", "false")
	Lib.DeleteGitleaksConfig("enable")

	// Remove Config in .git/config : Gitleaks.url to null
	// Lib.SetGitleaksConfig("url", "")
	Lib.DeleteGitleaksConfig("url")

	// Remove Config in .git/config : Gitleaks.debug to false
	// Lib.SetGitleaksConfig("debug", "false")
	Lib.DeleteGitleaksConfig("debug")

	// Remove Script in .git/hooks/pre-commit
	Lib.DisableGitHooks(Lib.PreCommitScriptPath, Lib.PreCommitScript)

	// Remove Script in .git/hooks/post-commit
	Lib.DisableGitHooks(Lib.PostCommitScriptPath, Lib.PostCommitScript)

	log.Debug().Msg("Gitleaks Disable")
}
