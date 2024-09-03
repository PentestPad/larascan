package common

// ScanResult defines the result of a scan
type ScanResult struct {
	Category    string
	Description string
	Path        string
	StatusCode  int
	Detail      string
	ScanName    string
}

// Scan defines the interface that all scans must implement
type Scan interface {
	Run(target string) []ScanResult
	Name() string
}
