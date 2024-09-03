// cmd/larascan/main.go
package main

import (
	"flag"
	"fmt"
	"os"

	"larascan/internal/scanner"
)

func main() {
	url := flag.String("url", "", "Target URL to scan")
	threads := flag.Int("threads", 5, "Number of parallel threads")
	flag.Parse()

	if *url == "" {
		fmt.Println("Please provide a target URL using the --url flag.")
		return
	}

	if *threads <= 0 {
		fmt.Println("Number of threads must be greater than 0.")
		os.Exit(1)
	}

	sc := scanner.NewScanner()

	// Run scans with parallelism
	scanResults := sc.RunScans(*url, *threads)

	// Display results
	for _, result := range scanResults {
		fmt.Printf("[%s] [%s] \nPath:%s \nDetails: %s (Status Code: %d). %s \n\n", result.Category, result.ScanName, result.Path, result.Description, result.StatusCode, result.Detail)
	}
}
