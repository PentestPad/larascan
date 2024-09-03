// internal/scanner/scans/vulnerabilities/tools_detection.go
package vulnerabilities

import (
	"fmt"
	"io"
	"larascan/pkg/httpclient"
	"strings"
	"time"

	"larascan/internal/common"
)

// ToolsDetectionScan is a struct that contains an HTTP client
type ToolsDetectionScan struct {
	client *httpclient.Client
}

// NewToolsDetectionScan initializes and returns a new ToolsDetectionScan instance
func NewToolsDetectionScan() *ToolsDetectionScan {
	return &ToolsDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks for publicly exposed tools and admin interfaces on the target server
func (tds *ToolsDetectionScan) Run(target string) []common.ScanResult {
	// List of common Laravel tools and admin panel paths
	paths := []string{
		"/_debugbar",                  // Laravel Debugbar
		"/telescope",                  // Laravel Telescope
		"/horizon",                    // Laravel Horizon
		"/nova",                       // Laravel Nova
		"/admin",                      // Common admin panel
		"/phpmyadmin",                 // phpMyAdmin, if it happens to be installed
		"/_ignition/execute-solution", // Ignition (Laravel error page handler)
		"/_ignition/health-check",     // Ignition health check
	}

	var exposedTools []string
	var existingTools []string

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := tds.client.Get(url, nil)
		if err != nil {
			continue // Skip if the request fails
		}

		// Read a limited portion of the body to prevent excessive memory usage
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		bodyStr := string(body)

		if resp.StatusCode == 200 {
			// Check if the response indicates the tool is accessible
			if strings.Contains(bodyStr, "Debugbar") ||
				strings.Contains(bodyStr, "Telescope") ||
				strings.Contains(bodyStr, "Horizon") ||
				strings.Contains(bodyStr, "Nova") ||
				strings.Contains(bodyStr, "phpMyAdmin") ||
				strings.Contains(bodyStr, "Ignition") ||
				strings.Contains(bodyStr, "Laravel") ||
				strings.Contains(bodyStr, "Admin") {
				exposedTools = append(exposedTools, path)
			}
		} else if resp.StatusCode == 403 || resp.StatusCode == 401 {
			// Path exists but access is forbidden or unauthorized
			existingTools = append(existingTools, fmt.Sprintf("%s (Status: %d)", path, resp.StatusCode))
		}

		resp.Body.Close()
	}

	var results []common.ScanResult

	if len(exposedTools) > 0 {
		results = append(results, common.ScanResult{
			ScanName:    tds.Name(),
			Category:    "Vulnerabilities",
			Description: "Publicly exposed tools and admin interfaces detected",
			Path:        strings.Join(exposedTools, ", "),
			StatusCode:  200,
		})
	} else {
		results = append(results, common.ScanResult{
			ScanName:    tds.Name(),
			Category:    "Vulnerabilities",
			Description: "No publicly exposed tools or admin interfaces detected",
			Path:        "",
			StatusCode:  0,
		})
	}

	if len(existingTools) > 0 {
		results = append(results, common.ScanResult{
			ScanName:    tds.Name(),
			Category:    "Recon",
			Description: "Tools and admin interfaces exist but are access-restricted",
			Path:        strings.Join(existingTools, ", "),
			StatusCode:  403, // You can adjust this as needed
		})
	}

	return results
}

func (pvs *ToolsDetectionScan) Name() string {
	return "laravel Tools"
}
