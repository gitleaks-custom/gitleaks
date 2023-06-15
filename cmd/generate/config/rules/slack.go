package rules

import (
	"fmt"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://api.slack.com/authentication/token-types#bot
func SlackBotToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack Bot token",
		RuleID:      "slack-bot-token",
		Regex: regexp.MustCompile(
			`(xoxb-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9-]*)`),
		Keywords: []string{
			"xoxb",
		},
	}

	// validate
	tps := []string{
		// https://github.com/metabase/metabase/blob/74cfb332140680425c7d37d347854160cc997ea8/frontend/src/metabase/admin/settings/slack/components/SlackForm/SlackForm.tsx#L47
		`"bot_token1": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#LL44C27-L44C86
		`"bot_token2": "***REMOVED***"`, // gitleaks:allow
		`"bot_token3": "***REMOVED***"`,   // gitleaks:allow
		`"bot_token4": ` + fmt.Sprintf(`"xoxb-%s-%s-%s"`, secrets.NewSecret(numeric("13")), secrets.NewSecret(numeric("12")), secrets.NewSecret(alphaNumeric("24"))),
	}
	fps := []string{
		"xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx",
		"xoxb-xxx",
		"xoxb-12345-abcd234",
		"xoxb-xoxb-my-bot-token",
	}
	return validate(r, tps, fps)
}

// https://api.slack.com/authentication/token-types#user
func SlackUserToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack User",
		RuleID:      "slack-user-token",
		// The last segment seems to be consistently 32 characters. I've made it 28-34 just in case.
		Regex:    regexp.MustCompile(`(xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34})`),
		Keywords: []string{"xoxp-", "xoxe-"},
	}

	// validate
	tps := []string{
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L25
		`"user_token1": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/praetorian-inc/noseyparker/blob/16e0e5768fd14ea54f6c9a058566184d88343bb4/crates/noseyparker/data/default/rules/slack.yml#L29
		`"user_token2": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/CloudBoost/cloudboost/blob/7ba2ed17099fa85e6fc652302822601283c6fa13/user-service/services/mailService.js#LL248C17-L248C92
		`"user_token3": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/evanyeung/terminal-slack/blob/b068f77808de72424d08b525d6cbf814849acd08/readme.md?plain=1#L66
		`"user_token4": "***REMOVED***"`,    // gitleaks:allow
		`"user_token5": "***REMOVED***"`, // gitleaks:allow
		`"user_token6": ` + fmt.Sprintf(`"xoxp-%s-%s-%s-%s"`, secrets.NewSecret(numeric("12")), secrets.NewSecret(numeric("13")), secrets.NewSecret(numeric("13")), secrets.NewSecret(alphaNumeric("32"))),
		// It's unclear what the `xoxe-` token means in this context, however, the format is similar to a user token.
		`"url_private": "https:\/\/files.slack.com\/files-pri\/T04MCQMEXQ9-F04MAA1PKE3\/image.png?t=xoxe-4726837507825-4848681849303-4856614048758-e0b1f3d4cb371f92260edb0d9444d206"`,
	}
	fps := []string{
		`https://docs.google.com/document/d/1W7KCxOxP-1Fy5EyF2lbJGE2WuKmu5v0suYqoHas1jRM`,
		`"token1": "xoxp-1234567890"`, // gitleaks:allow
		`"token2": "xoxp-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`, // gitleaks:allow
		`"token3": "xoxp-1234-1234-1234-4ddbc191d40ee098cbaae6f3523ada2d"`,                    // gitleaks:allow
		`"token4": "xoxp-572370529330-573807301142-572331691188-####################"`,        // gitleaks:allow
		// This technically matches the pattern but is an obvious false positive.
		// `"token5": "***REMOVED***"`, // gitleaks:allow
	}
	return validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/token-types#app
func SlackAppLevelToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack App-level token",
		RuleID:      "slack-app-token",
		// This regex is based on a limited number of examples and may not be 100% accurate.
		Regex:    regexp.MustCompile(`(?i)(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)`),
		Keywords: []string{"xapp"},
	}

	tps := []string{
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L17
		`"token1": "***REMOVED***"`, // gitleaks:allow
		`"token2": "***REMOVED***"`, // gitleaks:allow
		`"token3": "***REMOVED***"`, // gitleaks:allow
		`"token4": ` + fmt.Sprintf(`"xapp-1-A%s-%s-%s"`, secrets.NewSecret(numeric("10")), secrets.NewSecret(numeric("13")), secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}

// Reference: https://api.slack.com/authentication/config-tokens
func SlackConfigurationToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack Configuration access token",
		RuleID:      "slack-config-access-token",
		Regex:       regexp.MustCompile(`(?i)(xoxe.xox[bp]-\d-[A-Z0-9]{163,166})`),
		Keywords:    []string{"xoxe.xoxb-", "xoxe.xoxp-"},
	}

	tps := []string{
		`"access_token1": "***REMOVED***"`, // gitleaks:allow
		`"access_token2": "***REMOVED***"`, // gitleaks:allow
		`"access_token3": "xoxe.xoxp-1-` + secrets.NewSecret(alphaNumeric("163")) + `"`,
		`"access_token4": "***REMOVED***"`,
		`"access_token5": "xoxe.xoxb-1-` + secrets.NewSecret(alphaNumeric("165")) + `"`,
	}
	fps := []string{
		"***REMOVED***",
		"***REMOVED***",
		"xoxe.xoxp-1-initial",
	}
	return validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/config-tokens
func SlackConfigurationRefreshToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack Configuration refresh token",
		RuleID:      "slack-config-refresh-token",
		Regex:       regexp.MustCompile(`(?i)(xoxe-\d-[A-Z0-9]{146})`),
		Keywords:    []string{"xoxe-"},
	}

	tps := []string{
		`"refresh_token1": "***REMOVED***"`, // gitleaks:allow
		`"refresh_token2": "***REMOVED***"`, // gitleaks:allow
		`"refresh_token3": "xoxe-1-` + secrets.NewSecret(alphaNumeric("146")) + `"`,
	}
	fps := []string{"xoxe-1-xxx", "XOxE-RROAmw, Home and Garden, 5:24, 20120323"}
	return validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/token-types#legacy_bot
func SlackLegacyBotToken() *config.Rule {
	r := config.Rule{
		Description: "Slack Legacy bot token",
		RuleID:      "slack-legacy-bot-token",
		// This rule is based off the limited information I could find and may not be 100% accurate.
		Regex: regexp.MustCompile(
			`(xoxb-[0-9]{8,14}\-[a-zA-Z0-9]{18,26})`),
		Keywords: []string{
			"xoxb",
		},
	}

	tps := []string{
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#LL42C38-L42C80
		`"bot_token1": "***REMOVED***"`, // gitleaks:allow
		// https://heejune.me/2018/08/01/crashdump-analysis-automation-using-slackbot-python-cdb-from-windows/
		`"bot_token2": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/praetorian-inc/noseyparker/blob/16e0e5768fd14ea54f6c9a058566184d88343bb4/crates/noseyparker/data/default/rules/slack.yml#L15
		`"bot_token3": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/pulumi/examples/blob/32d9047c19c2a9380c04e57a764321c25eef45b0/aws-js-sqs-slack/README.md?plain=1#L39
		`"bot_token4": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/ilyasProgrammer/Odoo-eBay-Amazon/blob/a9c4a8a7548b19027bc0fd904f8ae9249248a293/custom_logging/models.py#LL9C24-L9C66
		`"bot_token5": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/jay-johnson/sci-pype/blob/6bff42ea4eb32d35b9f223db312e4cd0d3911100/src/pycore.py#L37
		`"bot_token6": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/logicmoo/logicmoo_workspace/blob/2e1794f596121c9949deb3bfbd30d5b027a51d3d/packs_sys/slack_prolog/prolog/slack_client_old.pl#L28
		`"bot_token7": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/sbarski/serverless-chatbot/blob/7d556897486f3fd53795907b7e33252e5cc6b3a3/Lesson%203/serverless.yml#L38
		`"bot_token8": "***REMOVED***"`,                                                             // gitleaks:allow
		`"bot_token9": "***REMOVED***"`,                                                                     // gitleaks:allow
		`"bot_token10": ` + fmt.Sprintf(`"xoxb-%s-%s`, secrets.NewSecret(numeric("10")), secrets.NewSecret(alphaNumeric("24"))), // gitleaks:allow
		`"bot_token11": ` + fmt.Sprintf(`"xoxb-%s-%s`, secrets.NewSecret(numeric("12")), secrets.NewSecret(alphaNumeric("23"))), // gitleaks:allow
	}
	fps := []string{
		"xoxb-xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx", // gitleaks:allow
		"xoxb-Slack_BOT_TOKEN",
		"xoxb-abcdef-abcdef",
		// "***REMOVED***", // gitleaks:allow
	}
	return validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/token-types#workspace
func SlackLegacyWorkspaceToken() *config.Rule {
	r := config.Rule{
		Description: "Slack Legacy Workspace token",
		RuleID:      "slack-legacy-workspace-token",
		// This is by far the least confident pattern.
		Regex: regexp.MustCompile(
			`(xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48})`),
		Keywords: []string{
			"xoxa",
			"xoxr",
		},
	}

	tps := []string{
		`"access_token": "***REMOVED***"`, // gitleaks:allow
		`"access_token1": ` + fmt.Sprintf(`"xoxa-%s-%s`, secrets.NewSecret(numeric("1")), secrets.NewSecret(alphaNumeric("12"))),
		`"access_token2": ` + fmt.Sprintf(`"xoxa-%s`, secrets.NewSecret(alphaNumeric("12"))),
		`"refresh_token1": ` + fmt.Sprintf(`"xoxr-%s-%s`, secrets.NewSecret(numeric("1")), secrets.NewSecret(alphaNumeric("12"))),
		`"refresh_token2": ` + fmt.Sprintf(`"xoxr-%s`, secrets.NewSecret(alphaNumeric("12"))),
	}
	fps := []string{
		// "xoxa-faketoken",
		// "xoxa-access-token-string",
		// "XOXa-nx991k",
		"https://github.com/xoxa-nyc/xoxa-nyc.github.io/blob/master/README.md",
	}
	return validate(r, tps, fps)
}

// References:
// - https://api.slack.com/authentication/token-types#legacy
// - https://api.slack.com/changelog/2016-05-19-authorship-changing-for-older-tokens
// - https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L29
// - https://gist.github.com/thesubtlety/a1c460d53df0837c5817c478b9f10588#file-local-slack-jack-py-L32
func SlackLegacyToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack Legacy token",
		RuleID:      "slack-legacy-token",
		Regex:       regexp.MustCompile(`(xox[os]-\d+-\d+-\d+-[a-fA-F\d]+)`),
		Keywords:    []string{"xoxo", "xoxs"},
	}

	// validate
	tps := []string{
		// https://github.com/GGStudy-DDUp/https-github.com-aldaor-HackerOneReports/blob/637e9261b63a7292a3a7ddf4bf13729c224d84df/PrivilegeEscalation/47940.txt#L23
		`"access_token1": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L28
		`"access_token2": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/clr2of8/SlackExtract/blob/18d151152ff5a45b293d4b7193aa6d08f9ab1bfd/README.md?plain=1#L32
		`"access_token3": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/zeroc00I/AllVideoPocsFromHackerOne/blob/95ae92f65ccef11c2c6acdaabfb7cc9b2b0eb4c6/jsonReports/61312.json#LL1C17-L1C17
		`"access_token4": "***REMOVED***"`, // gitleaks:allow
		// https://github.com/ericvanderwal/general-playmaker/blob/34bd8e82e2d7b16ca9cc825d0c9d383b8378b550/Logic/setrandomseedtype.cs#LL783C15-L783C69
		`"access_token5": "***REMOVED***"`, // gitleaks:allow
		`"access_token6": "xoxs-` + fmt.Sprintf("%s-%s-%s-%s", secrets.NewSecret(numeric("10")), secrets.NewSecret(numeric("10")), secrets.NewSecret(numeric("10")), secrets.NewSecret(hex("10"))) + `"`,
		`"access_token7": "xoxo-523423-234243-234233-e039d02840a0b9379c"`, // gitleaks:allow
	}
	fps := []string{
		"https://indieweb.org/images/3/35/2018-250-xoxo-indieweb-1.jpg",
		"https://lh3.googleusercontent.com/-tWXjX3LUD6w/Ua4La_N5E2I/AAAAAAAAACg/qcm19xbEYa4/s640/EXO-XOXO-teaser-exo-k-34521098-720-516.jpg",
	}
	return validate(r, tps, fps)
}

func SlackWebHookUrl() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack Webhook",
		RuleID:      "slack-webhook-url",
		// If this generates too many false-positives we should define an allowlist (e.g., "xxxx", "00000").
		Regex: regexp.MustCompile(
			`(https?:\/\/)?hooks.slack.com\/(services|workflows)\/[A-Za-z0-9+\/]{43,46}`),
		Keywords: []string{
			"hooks.slack.com",
		},
	}

	// validate
	tps := []string{
		"hooks.slack.com/services/" + secrets.NewSecret(alphaNumeric("44")),
		"http://hooks.slack.com/services/" + secrets.NewSecret(alphaNumeric("45")),
		"https://hooks.slack.com/services/" + secrets.NewSecret(alphaNumeric("46")),
		"http://hooks.slack.com/services/T024TTTTT/BBB72BBL/AZAAA9u0pA4ad666eMgbi555",   // gitleaks:allow
		"***REMOVED***", // gitleaks:allow
		"hooks.slack.com/workflows/" + secrets.NewSecret(alphaNumeric("44")),
		"http://hooks.slack.com/workflows/" + secrets.NewSecret(alphaNumeric("45")),
		"https://hooks.slack.com/workflows/" + secrets.NewSecret(alphaNumeric("46")),
		"***REMOVED***", // gitleaks:allow
		"http://hooks.slack.com/workflows/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",    // gitleaks:allow
	}
	return validate(r, tps, nil)
}
