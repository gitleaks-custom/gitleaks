package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	GitConfig "github.com/zricethezav/gitleaks/v8/lib"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	// 오류 발생시 Recover.
	defer func() {
		recover()
		return
	}()

	// .git/config 파일 내 Gitleaks.enable = true 가 아닐 경우 리턴을 통해 함수 종료.
	enableValue, _ := GitConfig.GetGitleaksConfig("enable")
	isGitleaksEnable, _ := strconv.ParseBool(enableValue)
	if !isGitleaksEnable {
		fmt.Println("Gitleaks Disabled")
		return
	}

	backendUrl, _ := GitConfig.GetGitleaksConfig("url")

	fmt.Println("Backend URL: ", backendUrl)

	u, err := url.Parse(backendUrl)
	// net/url Parsing Error
	if err != nil {
		fmt.Printf("Error parsing url, %v\n", err)
		panic(err)
	}

	// Request Handling
	requestData, _ := json.Marshal(retrieveLocalGitInfo())

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBuffer(requestData))
	req.Header.Set("User-Agent", `Gitleaks`+"/"+Version)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	// net/http client Error - Request 오류 시 백엔드 통신 X
	if err != nil {
		fmt.Printf("Error http request, %v\n", err)
		panic(err)
	}
	defer resp.Body.Close()

	// Response Handling
	response, _ := io.ReadAll(resp.Body)

	var responseData AuditResponse
	// Error During Json Unmarshaling - 백엔드 Response Type 변경 등
	if err := json.Unmarshal([]byte(response), &responseData); err != nil {
		fmt.Printf("Error Json Unmarshal error: %v", err)
		panic(err)
	}

	responseGitConfig := responseData.Data.(map[string]interface{})["GitConfig"].(map[string]interface{})
	for k, v := range responseGitConfig {
		fmt.Printf("%s: %s\n", k, fmt.Sprintf("%v", v))
		GitConfig.SetGitleaksConfig(k, fmt.Sprintf("%v", v))
	}

	responseVersion := responseData.Data.(map[string]interface{})["Version"]
	fmt.Printf("Response Version : %s\n", responseVersion)
}

func retrieveLocalGitInfo() AuditRequest {
	OrganizationName, _ := GitConfig.GetLocalOrganizationName()
	RepositoryName, _ := GitConfig.GetLocalRepositoryName()
	BranchName, _ := GitConfig.GetHeadBranchName()
	AuthorName, _ := GitConfig.GetLocalUserName()
	AuthorEmail, _ := GitConfig.GetLocalUserEmail()
	CommitHash, _ := GitConfig.GetHeadCommitHash()
	CommitTimestamp, _ := GitConfig.GetHeadCommitTimestamp()

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
