package config

import (
	"encoding/json"
	"os"
	"time"

	"iot-scanner/pkg/models"
)

// Config holds the scanner configuration
type Config struct {
	IPRange             string        // IP range in CIDR notation
	FullScan            bool          // Whether to perform a full scan including vulnerability checks
	OutputFile          string        // File to write results to
	OutputFormat        string        // Format for output files (json, csv, md, html)
	Timeout             time.Duration // Timeout for network operations
	Threads             int           // Number of concurrent scanning threads
	Verbose             bool          // Enable verbose output
	DatabasePath        string        // Path to device and vulnerability database
	ScanPorts           []int         // Ports to scan
	FingerPrintDB       string        // Path to fingerprint database
	EnhancedScan        bool          // Enable enhanced scanning with SNMP and MAC lookup
	TestMode            bool          // Run in test mode with simulated devices
	EnableExport        bool          // Enable export of scan reports
	ExportDirectory     string        // Directory to save exported reports
	ExportFull          bool          // Include full scan data in export
	EnableDashboard     bool          // Enable web dashboard
	DashboardPort       string        // Port for web dashboard
	EnableLiveCVE       bool          // Enable live CVE feed
	CVEInterval         int           // Interval in minutes to check for new CVEs
	EnableExploitNotify bool          // Enable notifications for new exploits
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() Config {
	return Config{
		IPRange:      "192.168.1.1/24",
		FullScan:     false,
		Timeout:      5 * time.Second,
		Threads:      10,
		Verbose:      false,
		DatabasePath: "data/db",
		ScanPorts: []int{
			21,   // FTP
			22,   // SSH
			23,   // Telnet
			25,   // SMTP
			80,   // HTTP
			443,  // HTTPS
			554,  // RTSP
			1883, // MQTT
			5683, // CoAP
			8080, // HTTP Alt
			8443, // HTTPS Alt
			8883, // MQTT TLS
			9000, // UPnP
		},
		FingerPrintDB: "data/fingerprints.json",
	}
}

// LoadConfigFromFile loads configuration from a JSON file
func LoadConfigFromFile(filePath string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return cfg, err
	}

	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// WriteResultsToFile writes scan results to a JSON file
func WriteResultsToFile(devices []models.Device, filePath string) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}
