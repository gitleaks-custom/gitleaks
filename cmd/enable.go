package cmd

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	Lib "github.com/zricethezav/gitleaks/v8/lib"
	"strconv"
)

func init() {
	enableCmd.Flags().String("url", "", "Backend URL")
	enableCmd.Flags().Bool("debug", false, "Enable debug output")
	rootCmd.AddCommand(enableCmd)
}

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable gitleaks in pre-commit script",
	Run:   runEnable,
}

func runEnable(cmd *cobra.Command, args []string) {
	// Setting .git/config : Gitleaks.url
	urlFlag, _ := cmd.Flags().GetString("url")
	Lib.SetGitleaksConfig("url", urlFlag)

	debugFlag, _ := cmd.Flags().GetBool("debug")
	if debugFlag {
		// If enable command with --debug flag, set Gitleaks.debug to true
		// Using this flag, print the all commands logs
		Lib.SetGitleaksConfig("debug", strconv.FormatBool(debugFlag))
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Setting .git/config : Gitleaks.enable
	Lib.SetGitleaksConfig("enable", "true")

	// Setting .git/hooks/pre-commit
	Lib.EnableGitHooks(Lib.PreCommitScriptPath, Lib.PreCommitScript)

	// Setting .git/hooks/post-commit
	Lib.EnableGitHooks(Lib.PostCommitScriptPath, Lib.PostCommitScript)

	log.Debug().Msg("Gitleaks Enabled")
}
