package vulnerabilities

import (
	"io/ioutil"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"net/http"
	"strings"
	"time"
)

type DebugModeScan struct {
	client *httpclient.Client
}

func NewDebugModeScan() *DebugModeScan {
	return &DebugModeScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks if the Laravel debug mode is enabled by triggering an error page
func (d *DebugModeScan) Run(target string) []common.ScanResult {
	// Intentionally trigger an error to check for debug mode
	errorURL := target + "/nonexistentpage"

	resp, err := d.client.Get(errorURL, nil)
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    d.Name(),
				Category:    "Vulnerabilities",
				Description: "Request to trigger error page failed",
				Path:        errorURL,
				StatusCode:  0,
				Detail:      err.Error(),
			},
		}
	}
	defer resp.Body.Close()

	var results []common.ScanResult

	if resp.StatusCode == http.StatusInternalServerError {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results = append(results, common.ScanResult{
				ScanName:    d.Name(),
				Category:    "Vulnerabilities",
				Description: "Failed to read response body from error page",
				Path:        errorURL,
				StatusCode:  resp.StatusCode,
				Detail:      err.Error(),
			})
			return results
		}
		body := string(bodyBytes)

		if strings.Contains(body, "Whoops, looks like something went wrong.") ||
			strings.Contains(body, "exception") {
			results = append(results, common.ScanResult{
				ScanName:    d.Name(),
				Category:    "Vulnerabilities",
				Description: "Debug mode is enabled!",
				Path:        errorURL,
				StatusCode:  resp.StatusCode,
				Detail:      "The application displayed a detailed error page, indicating that debug mode is active.",
			})
		} else {
			results = append(results, common.ScanResult{
				ScanName:    d.Name(),
				Category:    "Vulnerabilities",
				Description: "Debug mode is disabled.",
				Path:        errorURL,
				StatusCode:  resp.StatusCode,
				Detail:      "The application did not display a detailed error page, indicating that debug mode is likely disabled.",
			})
		}
	} else {
		results = append(results, common.ScanResult{
			ScanName:    d.Name(),
			Category:    "Vulnerabilities",
			Description: "Could not determine debug mode status.",
			Path:        errorURL,
			StatusCode:  resp.StatusCode,
			Detail:      "The server did not return a 500 Internal Server Error as expected, making it difficult to assess debug mode status.",
		})
	}

	return results
}

// Name returns the name of the scan
func (d *DebugModeScan) Name() string {
	return "Debug Mode"
}
