package recon

import (
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"strings"
	"time"
)

// LivewireScan is a struct that contains an HTTP client
type LivewireScan struct {
	client *httpclient.Client
}

// NewLivewireScan initializes and returns a new LivewireScan instance
func NewLivewireScan() *LivewireScan {
	return &LivewireScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks if Livewire is used on the target site and attempts to determine the version
func (lws *LivewireScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// List of possible Livewire paths
	paths := []string{
		"/vendor/livewire/livewire.js",
		"/vendor/livewire/livewire.min.js",
		"/livewire/livewire.js",
		"/livewire/livewire.min.js",
	}

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := lws.client.Get(url, nil)
		if err != nil || resp.StatusCode != 200 {
			continue // Try the next path if the request fails or the file is not found
		}

		defer resp.Body.Close()
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results = append(results, common.ScanResult{
				ScanName:    lws.Name(),
				Category:    "Recon",
				Description: lws.renderStyled(fmt.Sprintf("Failed to read Livewire file content from %s", url), "error"),
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      err.Error(),
			})
			continue
		}
		body := string(bodyBytes)

		// Determine the version based on the content
		if strings.Contains(body, "window.livewire_token") {
			results = append(results, common.ScanResult{
				ScanName:    lws.Name(),
				Category:    "Recon",
				Description: lws.renderStyled(fmt.Sprintf("Livewire detected: Version 2.x at %s", url), "success"),
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      lws.getVulnerabilitiesForV2(),
			})
		} else if strings.Contains(body, "window.livewireScriptConfig") {
			results = append(results, common.ScanResult{
				ScanName:    lws.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Livewire detected: Version 3.x at %s", url),
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      lws.getVulnerabilitiesForV3(),
			})
		} else {
			results = append(results, common.ScanResult{
				ScanName:    lws.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Livewire detected at %s, but unable to determine version", url),
				Path:        path,
				StatusCode:  resp.StatusCode,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    lws.Name(),
			Category:    "Recon",
			Description: "Livewire not detected",
			Path:        target,
			StatusCode:  0,
		})
	}

	return results
}

// getVulnerabilitiesForV2 returns a formatted list of known CVEs and vulnerabilities for Livewire v2.x
func (lws *LivewireScan) getVulnerabilitiesForV2() string {
	vulnerabilities := []string{
		"Improper Input Validation >=2.2.4, <2.2.6: https://github.com/livewire/livewire/pull/1659",
	}

	result := ""
	for _, vuln := range vulnerabilities {
		result += fmt.Sprintf("  - %s ", vuln)
	}

	return result
}

// getVulnerabilitiesForV3 returns a formatted list of known CVEs and vulnerabilities for Livewire v3.x
func (lws *LivewireScan) getVulnerabilitiesForV3() string {
	vulnerabilities := []string{
		"Cross-site Scripting (XSS) >=3.3.5, <3.4.9: https://www.cve.org/CVERecord?id=CVE-2024-21504",
	}

	result := ""
	for _, vuln := range vulnerabilities {
		result += fmt.Sprintf("  - %s\n", vuln)
	}

	return result
}

func (pvs *LivewireScan) Name() string {
	return "Livewire Scan"
}

// renderStyled applies ANSI styles to the given message based on its type
func (lws *LivewireScan) renderStyled(message, messageType string) string {
	var styledMessage string

	switch messageType {
	case "success":
		styledMessage = color.GreenString(message)
	case "error":
		styledMessage = color.RedString(message)
	case "warning":
		styledMessage = color.YellowString(message)
	default:
		styledMessage = message
	}

	return styledMessage
}
