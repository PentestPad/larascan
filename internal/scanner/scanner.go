package scanner

import (
	"fmt"
	"larascan/internal/common"
	"larascan/internal/scanner/scans/recon"
	"larascan/internal/scanner/scans/vulnerabilities"
	"sync"
)

type Scanner struct {
	scans map[string][]common.Scan
}

func NewScanner() *Scanner {
	return &Scanner{
		scans: map[string][]common.Scan{
			"recon": {
				recon.NewFrameworkDetectionScan(),
				recon.NewLaravelVersionScan(),
				recon.NewLivewireScan(),
				recon.NewPhpVersionScan(),
				recon.NewSubdomainEnumScan(),
				recon.NewHostHeaderInjectionScan(),
			},
			"vulnerabilities": {
				vulnerabilities.NewCsrfTokenScan(),
				vulnerabilities.NewDebugModeScan(),
				vulnerabilities.NewSensitiveFilesScan(),
				vulnerabilities.NewToolsDetectionScan(),
			},
		},
	}
}

// RunScans executes all scans in parallel with a limit on the number of concurrent goroutines
func (s *Scanner) RunScans(target string, threads int) []common.ScanResult {
	var wg sync.WaitGroup
	resultsChan := make(chan common.ScanResult, 100) // Buffered channel for results
	sem := make(chan struct{}, threads)              // Semaphore to limit concurrency

	fmt.Println("Starting scans...")

	for category, scans := range s.scans {
		for _, scan := range scans {
			wg.Add(1)

			// Execute the scan in a goroutine
			go func(scan common.Scan, category string) {
				defer wg.Done()
				sem <- struct{}{}        // Acquire semaphore
				defer func() { <-sem }() // Release semaphore

				results := scan.Run(target)
				for _, result := range results {
					//fmt.Printf("Scan result: %s - %s\n", result.Category, result.Description)
					resultsChan <- result // Send results to channel
				}
			}(scan, category)
		}
	}

	// Close the results channel after all scans are done
	go func() {
		wg.Wait()
		fmt.Println("All scans completed. Closing results channel.")
		close(resultsChan)
	}()

	// Collect all results from the channel
	var allResults []common.ScanResult
	for result := range resultsChan {
		allResults = append(allResults, result)
	}

	fmt.Println("Finished collecting all results.")
	return allResults
}
