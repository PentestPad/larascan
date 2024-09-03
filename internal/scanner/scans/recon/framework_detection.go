package recon

import (
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

// FrameworkDetectionScan is a struct that contains an HTTP client
type FrameworkDetectionScan struct {
	client *httpclient.Client
}

// NewFrameworkDetectionScan initializes and returns a new FrameworkDetectionScan instance
func NewFrameworkDetectionScan() *FrameworkDetectionScan {
	return &FrameworkDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks for signs of the Laravel framework in the response
func (fds *FrameworkDetectionScan) Run(target string) []common.ScanResult {
	headers := map[string]string{
		"User-Agent": "LaravelScanner/1.0",
	}

	resp, err := fds.client.Get(target, headers)
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    fds.Name(),
				Category:    "Recon",
				Description: "Failed to make request",
				Path:        target,
				StatusCode:  0,
				Detail:      err.Error(),
			},
		}
	}
	defer resp.Body.Close()

	var results []common.ScanResult

	// Check for Laravel-specific headers
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" && strings.Contains(poweredBy, "PHP") {
		results = append(results, common.ScanResult{
			ScanName:    fds.Name(),
			Category:    "Recon",
			Description: "Possible Laravel framework detected via X-Powered-By header",
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      poweredBy,
		})
	}

	// Check for Laravel-specific cookies
	for _, cookie := range resp.Cookies() {
		if strings.Contains(cookie.Name, "laravel") {
			results = append(results, common.ScanResult{
				ScanName:    fds.Name(),
				Category:    "Recon",
				Description: "Laravel framework detected via cookie name",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      cookie.Name,
			})
		}
	}

	// If no signs of Laravel are detected, return a corresponding result
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    fds.Name(),
			Category:    "Recon",
			Description: "Laravel framework not detected",
			Path:        target,
			StatusCode:  resp.StatusCode,
		})
	}

	return results
}

func (pvs *FrameworkDetectionScan) Name() string {
	return "Framework Detection"
}
