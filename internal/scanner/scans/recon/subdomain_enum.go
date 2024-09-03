package recon

import (
	"fmt"
	"net"
	"strings"
	"time"

	"larascan/internal/common"
)

type SubdomainEnumScan struct{}

func NewSubdomainEnumScan() *SubdomainEnumScan {
	return &SubdomainEnumScan{}
}

func (ses *SubdomainEnumScan) Run(target string) []common.ScanResult {
	domain := extractDomain(target)
	subdomains := []string{"www", "api", "admin", "dev", "test"}
	foundSubdomains := []string{}

	for _, sub := range subdomains {
		fullDomain := fmt.Sprintf("%s.%s", sub, domain)
		_, err := net.LookupHost(fullDomain)
		if err == nil {
			foundSubdomains = append(foundSubdomains, fullDomain)
		}
		// Respectful delay between requests
		time.Sleep(500 * time.Millisecond)
	}

	var results []common.ScanResult

	if len(foundSubdomains) > 0 {
		results = append(results, common.ScanResult{
			ScanName:    ses.Name(),
			Category:    "Recon",
			Description: "Found subdomains",
			Path:        target,
			StatusCode:  0, // Subdomain enumeration doesn't involve HTTP status codes
			Detail:      strings.Join(foundSubdomains, ", "),
		})
	} else {
		results = append(results, common.ScanResult{
			ScanName:    ses.Name(),
			Category:    "Recon",
			Description: "No common subdomains found",
			Path:        target,
			StatusCode:  0,
		})
	}

	return results
}

func extractDomain(url string) string {
	// Simple extraction; can be enhanced with proper URL parsing
	parts := strings.Split(url, "//")
	if len(parts) > 1 {
		url = parts[1]
	}
	parts = strings.Split(url, "/")
	return parts[0]
}

func (pvs *SubdomainEnumScan) Name() string {
	return "Subdomain Enumeration"
}
