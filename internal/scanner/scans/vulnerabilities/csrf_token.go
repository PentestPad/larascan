package vulnerabilities

import (
	"fmt"
	"io/ioutil"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

type CsrfTokenScan struct {
	client *httpclient.Client
}

func NewCsrfTokenScan() *CsrfTokenScan {
	return &CsrfTokenScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

func (c *CsrfTokenScan) Run(target string) []common.ScanResult {
	// List of paths to check for CSRF tokens
	paths := []string{
		"/",
		"/login",
		"/register",
	}

	var results []common.ScanResult

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := c.client.Get(url, nil)
		if err != nil {
			results = append(results, common.ScanResult{
				ScanName:    c.Name(),
				Category:    "Vulnerabilities",
				Description: fmt.Sprintf("Failed to make request to %s", url),
				Path:        path,
				StatusCode:  0,
				Detail:      err.Error(),
			})
			continue // Try the next path if the request fails
		}

		defer resp.Body.Close()
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results = append(results, common.ScanResult{
				ScanName:    c.Name(),
				Category:    "Vulnerabilities",
				Description: fmt.Sprintf("Failed to read response body from %s", url),
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      err.Error(),
			})
			continue
		}
		body := string(bodyBytes)

		// Check if the response body contains a CSRF token
		if strings.Contains(body, "csrf_token") || strings.Contains(body, "_token") {
			results = append(results, common.ScanResult{
				ScanName:    c.Name(),
				Category:    "Vulnerabilities",
				Description: "CSRF token found",
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("CSRF token found on %s", url),
			})
		} else {
			results = append(results, common.ScanResult{
				ScanName:    c.Name(),
				Category:    "Vulnerabilities",
				Description: "CSRF token not found",
				Path:        path,
				StatusCode:  resp.StatusCode,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    c.Name(),
			Category:    "Vulnerabilities",
			Description: "No CSRF tokens found on common paths",
			Path:        target,
			StatusCode:  0,
		})
	}

	return results
}

func (pvs *CsrfTokenScan) Name() string {
	return "CSRF Token"
}
