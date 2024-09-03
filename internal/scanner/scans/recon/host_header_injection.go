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

// HostHeaderInjectionScan is a struct that contains an HTTP client
type HostHeaderInjectionScan struct {
	client *httpclient.Client
}

// NewHostHeaderInjectionScan initializes and returns a new HostHeaderInjectionScan instance
func NewHostHeaderInjectionScan() *HostHeaderInjectionScan {
	return &HostHeaderInjectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run tests for Host Header Injection vulnerabilities and checks for password recovery functionality
func (hhi *HostHeaderInjectionScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Define a malicious host header to test for injection
	injectionHeader := "malicious.com"

	// Send a request with the malicious Host header
	headers := map[string]string{
		"Host": injectionHeader,
	}

	resp, err := hhi.client.Get(target, headers)
	if err != nil {
		results = append(results, common.ScanResult{
			ScanName:    hhi.Name(),
			Category:    "Recon",
			Description: hhi.renderStyled(fmt.Sprintf("[%s]\nDetails: Failed to send request to %s", hhi.Name(), target), "error"),
			Path:        target,
			StatusCode:  0,
			Detail:      err.Error(),
		})
		return results
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		results = append(results, common.ScanResult{
			ScanName:    hhi.Name(),
			Category:    "Recon",
			Description: fmt.Sprintf("Failed to read response body"),
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      err.Error(),
		})
		return results
	}

	body := string(bodyBytes)

	// Check if the injected Host header appears in the response
	if strings.Contains(body, injectionHeader) {
		detail := "The response contains the injected Host header value."
		results = append(results, common.ScanResult{
			ScanName:    hhi.Name(),
			Category:    "Recon",
			Description: fmt.Sprintf("Host Header Injection detected"),
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      detail,
		})

		// Check for password recovery functionality by testing specific URLs
		if hhi.checkPasswordRecoveryURLs(target) {
			detail := "If the application sends password reset links using the injected Host header, it could lead to an account takeover vulnerability."
			results = append(results, common.ScanResult{
				ScanName:    hhi.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Password recovery functionality detected, potential account takeover vulnerability due to Host Header Injection"),
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      detail,
			})
		}

	} else {
		results = append(results, common.ScanResult{
			ScanName:    hhi.Name(),
			Category:    "Recon",
			Description: fmt.Sprintf("No Host Header Injection detected"),
			Path:        target,
			StatusCode:  resp.StatusCode,
		})
	}

	return results
}

// checkPasswordRecoveryURLs checks if the /forgot-password or /auth/forgot-password URLs exist
func (hhi *HostHeaderInjectionScan) checkPasswordRecoveryURLs(target string) bool {
	// List of common password recovery URLs
	passwordRecoveryURLs := []string{
		"/forgot-password",
		"/auth/forgot-password",
	}

	for _, path := range passwordRecoveryURLs {
		url := strings.TrimRight(target, "/") + path
		resp, err := hhi.client.Get(url, nil)
		if err == nil && resp.StatusCode == 200 {
			return true
		}
	}

	return false
}

// Name returns the name of the scan
func (hhi *HostHeaderInjectionScan) Name() string {
	return "Host Header Injection Scan"
}

// renderStyled applies ANSI styles to the given message based on its type
func (hhi *HostHeaderInjectionScan) renderStyled(message, messageType string) string {
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
