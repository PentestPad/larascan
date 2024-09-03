package vulnerabilities

import (
	"fmt"
	"io/ioutil"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

// SensitiveFilesScan is a struct that contains an HTTP client
type SensitiveFilesScan struct {
	client *httpclient.Client
}

// NewSensitiveFilesScan initializes and returns a new SensitiveFilesScan instance
func NewSensitiveFilesScan() *SensitiveFilesScan {
	return &SensitiveFilesScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks for the presence of sensitive files and directories on the target server
func (sfs *SensitiveFilesScan) Run(target string) []common.ScanResult {
	// List of potentially sensitive files and directories to check
	paths := []string{
		"/.env",
		"/.env.local",
		"/.env.production",
		"/.env.staging",
		"/.env.backup",
		"/.env.old",
		"/.env.bak",
		"/.env.save",
		"/.git/config",
		"/.svn/wc.db",
		"/.DS_Store",
		"/.htaccess",
		"/.bash_history",
		"/.bashrc",
		"/.ssh/id_rsa",
		"/.ssh/known_hosts",
		"/composer.json",
		"/composer.lock",
		"/storage/logs/laravel.log",
		"/vendor/",
		"/node_modules/",
	}

	var exposed []string
	var results []common.ScanResult

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := sfs.client.Get(url, nil)
		if err != nil || resp.StatusCode != 200 {
			continue // Skip if the request fails or the file is not found
		}

		defer resp.Body.Close()

		// Check if the response contains readable content
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err == nil && len(bodyBytes) > 0 {
			exposed = append(exposed, path)
			results = append(results, common.ScanResult{
				ScanName:    sfs.Name(),
				Category:    "Vulnerabilities",
				Description: "Sensitive file or directory exposed",
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("Exposed path: %s", path),
			})
		}
	}

	if len(exposed) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    sfs.Name(),
			Category:    "Vulnerabilities",
			Description: "No sensitive files or directories detected",
			Path:        target,
			StatusCode:  0,
		})
	}

	return results
}

func (pvs *SensitiveFilesScan) Name() string {
	return "Sensitive Files"
}
