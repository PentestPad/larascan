package recon

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"larascan/internal/common"
	"larascan/pkg/httpclient"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type LaravelVersionScan struct {
	client *httpclient.Client
}

const (
	reconCategory = "Recon"
	statusOk      = http.StatusOK
)

func NewLaravelVersionScan() *LaravelVersionScan {
	return &LaravelVersionScan{client: httpclient.NewClient(10 * time.Second)}
}

func (lvs *LaravelVersionScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult
	composerFiles := []string{"/composer.json", "/composer.lock"}

	for _, filePath := range composerFiles {
		version := lvs.checkComposerFile(target, filePath)
		if version != "" {
			results = append(results, lvs.addResult(fmt.Sprintf("Laravel version detected from %s: %s", filePath, version), filePath))
		}
	}

	if lvs.checkVendorFolder(target) {
		results = append(results, lvs.addResult("Possible Laravel installation detected via exposed vendor folder", "/vendor/"))
	}

	version := lvs.guessVersionFromPHP(target)
	if version != "" {
		results = append(results, lvs.addResult(fmt.Sprintf("Laravel version range guessed based on PHP version: %s", version), target))
	}

	if len(results) == 0 {
		results = append(results, lvs.addResult("Laravel version could not be detected", target))
	}
	return results
}

func (lvs *LaravelVersionScan) addResult(description, path string) common.ScanResult {
	return common.ScanResult{
		ScanName:    lvs.Name(),
		Category:    reconCategory,
		Description: description,
		Path:        path,
		StatusCode:  statusOk,
	}
}

func (lvs *LaravelVersionScan) checkComposerFile(target, path string) string {
	url := strings.TrimRight(target, "/") + path
	resp, err := lvs.client.Get(url, nil)
	if err != nil || resp.StatusCode != statusOk {
		return ""
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	err = json.Unmarshal(bodyBytes, &data)
	if err != nil {
		return ""
	}
	if path == "/composer.json" {
		if require, ok := data["require"].(map[string]interface{}); ok {
			if version, ok := require["laravel/framework"].(string); ok {
				return version
			}
		}
	}
	if path == "/composer.lock" {
		if packages, ok := data["packages"].([]interface{}); ok {
			for _, pkg := range packages {
				if pkgMap, ok := pkg.(map[string]interface{}); ok {
					if name, ok := pkgMap["name"].(string); ok && name == "laravel/framework" {
						if version, ok := pkgMap["version"].(string); ok {
							return version
						}
					}
				}
			}
		}
	}
	return ""
}

// checkVendorFolder checks if the vendor folder is exposed
func (lvs *LaravelVersionScan) checkVendorFolder(target string) bool {
	url := strings.TrimRight(target, "/") + "/vendor/"
	resp, err := lvs.client.Get(url, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// Simple check to see if "laravel/framework" or "symfony" is listed in the vendor folder
	body := string(bodyBytes)
	return strings.Contains(body, "laravel/framework") || strings.Contains(body, "symfony/")
}

// guessVersionFromPHP guesses the Laravel version range based on the PHP version
func (lvs *LaravelVersionScan) guessVersionFromPHP(target string) string {
	resp, err := lvs.client.Get(target, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	// Check if the X-Powered-By header is present
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy == "" {
		return ""
	}

	// Extract PHP version from X-Powered-By header
	re := regexp.MustCompile(`PHP/([\d\.]+)`)
	matches := re.FindStringSubmatch(xPoweredBy)
	if len(matches) < 2 {
		return ""
	}
	phpVersion := matches[1]

	// Guess Laravel version based on PHP version
	switch {
	case strings.HasPrefix(phpVersion, "7.2"):
		return "Laravel 5.6.x - 6.x"
	case strings.HasPrefix(phpVersion, "7.3"):
		return "Laravel 6.x - 7.x"
	case strings.HasPrefix(phpVersion, "7.4"):
		return "Laravel 7.x - 8.x"
	case strings.HasPrefix(phpVersion, "8.0"):
		return "Laravel 8.x - 9.x"
	case strings.HasPrefix(phpVersion, "8.1"):
		return "Laravel 9.x - 11.x"
	case strings.HasPrefix(phpVersion, "8.2"):
		return "Laravel 10.x - 11.x"
	default:
		return "Unknown Laravel version (based on PHP version " + phpVersion + ")"
	}
}

func (pvs *LaravelVersionScan) Name() string {
	return "Laravel Version Detection"
}
