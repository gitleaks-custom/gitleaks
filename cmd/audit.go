package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	Lib "github.com/zricethezav/gitleaks/v8/lib"
	"io"
	"net/http"
	"net/url"
)

func init() {
	auditCmd.Flags().String("url", "", "Backend URL")
	rootCmd.AddCommand(auditCmd)
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Send audit data to backend",
	Run:   runAudit,
}

type AuditRequest struct {
	OrganizationName string `json:"organizationName"`
	RepositoryName   string `json:"repositoryName"`
	BranchName       string `json:"branchName"`
	AuthorName       string `json:"authorName"`
	AuthorEmail      string `json:"authorEmail"`
	CommitHash       string `json:"commitHash"`
	CommitTimestamp  string `json:"commitTimestamp"`
}

type AuditResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}

func runAudit(cmd *cobra.Command, args []string) {
	debugging := Lib.GetGitleaksConfigBoolean("debug")
	if debugging {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// 로직상 오류가 발생해도 정상 리턴
	defer func() {
		recover()
		return
	}()

	isEnable := Lib.GetGitleaksConfigBoolean("enable")
	// isDebug := Lib.GetGitleaksConfigBoolean("debug")
	if !isEnable {
		if debugging {
			log.Error().Msg("Gitleaks is not enabled")
		}
		return
	}

	backendUrl, _ := Lib.GetGitleaksConfig("url")

	log.Debug().Str("Url", backendUrl).Msg("Request")

	u, err := url.Parse(backendUrl)
	// net/url Parsing Error
	if err != nil {
		if debugging {
			log.Error().Msg("Error Parsing URL ," + err.Error())
		}
		panic(err)
	}

	// Request Handling
	requestData, _ := json.Marshal(retrieveLocalGitInfo())
	requestUserAgent := `Gitleaks` + "/" + Version

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBuffer(requestData))
	req.Header.Set("User-Agent", requestUserAgent)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	log.Debug().RawJSON("Body", requestData).Msg("Request")

	client := &http.Client{}
	resp, err := client.Do(req)
	// net/http client Error - Request 오류 시 백엔드 통신 X
	if err != nil {
		if debugging {
			log.Error().Msg("Http Request Error, " + err.Error())
		}
		panic(err)
	}
	defer resp.Body.Close()

	// Response Handling
	response, _ := io.ReadAll(resp.Body)

	var responseData AuditResponse
	log.Debug().RawJSON("Body", response).Msg("Response")
	// Error During Json Unmarshaling - 백엔드 Response Type 변경 등
	if err := json.Unmarshal([]byte(response), &responseData); err != nil {
		if debugging {
			log.Error().Msg("Json Unmarshal Error, " + err.Error())
		}
		panic(err)
	}

	responseGitConfig := responseData.Data.(map[string]interface{})["GitConfig"].(map[string]interface{})
	log.Debug().Interface("Body.Data.GitConfig", responseGitConfig).Msg("Response")
	for k, v := range responseGitConfig {
		Lib.SetGitleaksConfig(k, fmt.Sprintf("%v", v))
	}

	responseVersion := responseData.Data.(map[string]interface{})["Version"]
	log.Debug().Interface("Body.Data.Version", responseVersion).Msg("Response")

}

func retrieveLocalGitInfo() AuditRequest {
	OrganizationName, _ := Lib.GetLocalOrganizationName()
	RepositoryName, _ := Lib.GetLocalRepositoryName()
	BranchName, _ := Lib.GetHeadBranchName()
	AuthorName, _ := Lib.GetLocalUserName()
	AuthorEmail, _ := Lib.GetLocalUserEmail()
	CommitHash, _ := Lib.GetHeadCommitHash()
	CommitTimestamp, _ := Lib.GetHeadCommitTimestamp()

	return AuditRequest{
		OrganizationName,
		RepositoryName,
		BranchName,
		AuthorName,
		AuthorEmail,
		CommitHash,
		CommitTimestamp,
	}
}
