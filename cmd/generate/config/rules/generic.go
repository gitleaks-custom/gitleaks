package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func GenericCredential() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "generic-api-key",
		Description: "Generic API Key",
		Regex: generateSemiGenericRegex([]string{
			"key",
			"api[^Version]",
			"token",
			"pat",
			"secret",
			"client",
			"password",
			"auth",
		}, `[0-9a-z\-_.=]{10,150}`),
		SecretGroup: 1,
		Keywords: []string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"pat",
			"password",
			"auth",
		},
		Entropy: 3.7,
	}

	// validate
	tps := []string{
		generateSampleSecret("generic", "***REMOVED***"),
		generateSampleSecret("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),
	}
	return validate(r, tps)
}
