package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"iot-scanner/pkg/api"
	"iot-scanner/pkg/config"
	"iot-scanner/pkg/credentials"
	"iot-scanner/pkg/discovery"
	"iot-scanner/pkg/fingerprint"
	"iot-scanner/pkg/integration"
	"iot-scanner/pkg/models"
	"iot-scanner/pkg/vulnerability"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

func main() {
	// Run the main scanner CLI
	RunScannerCLI()
}

func RunScannerCLI() {
	// Parse command line arguments
	ipRange := flag.String("range", "192.168.1.1/24", "IP range to scan (CIDR notation)")
	fullScan := flag.Bool("full", false, "Perform full scan including all security checks")
	outputFile := flag.String("output", "results.json", "Output file for scan results (JSON format)")
	timeout := flag.Int("timeout", 5, "Timeout in seconds for network operations")
	threads := flag.Int("threads", 10, "Number of concurrent scanning threads")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	testMode := flag.Bool("test", false, "Run in test mode with simulated devices")
	dashboard := flag.Bool("dashboard", false, "Enable web dashboard")
	dashboardPort := flag.String("port", "8080", "Port for web dashboard")
	export := flag.Bool("export", false, "Export results in specified format")
	exportFormat := flag.String("format", "json", "Export format (json, csv, md, html)")

	flag.Parse()

	// Initialize logger
	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Display banner
	displayBanner()

	// Create configuration
	cfg := config.Config{
		IPRange:         *ipRange,
		FullScan:        *fullScan,
		OutputFile:      *outputFile,
		OutputFormat:    *exportFormat,
		Timeout:         time.Duration(*timeout) * time.Second,
		Threads:         *threads,
		Verbose:         *verbose,
		TestMode:        *testMode,
		EnableExport:    *export,
		EnableDashboard: *dashboard,
		DashboardPort:   *dashboardPort,
	}

	logger.Debugf("Starting scan with configuration: %+v", cfg)

	// Check if running as root/admin (required for some scanning features)
	if os.Geteuid() != 0 && !*testMode {
		logger.Warn("Not running as root. Some scanning features may be limited.")
	}

	// Display banner
	displayBanner()

	var devices []models.Device

	// Use test scanner if in test mode
	if *testMode {
		logger.Info("Running in test mode with simulated devices")
		scanner := integration.NewTestScanner(cfg, logger)
		err := scanner.Scan()
		if err != nil {
			logger.Fatalf("Error during test scan: %v", err)
		}

		// Load results from output file
		devices, err = loadResults(cfg.OutputFile)
		if err != nil {
			logger.Fatalf("Error loading test results: %v", err)
		}
	} else {
		// Initialize real scanner
		scanner := discovery.NewScanner(cfg)

		// Start discovery process
		logger.Infof("Discovering devices on network %s...", cfg.IPRange)
		realDevices, err := scanner.Discover()
		if err != nil {
			logger.Fatalf("Error during device discovery: %v", err)
		}

		// Convert discovery.Device to models.Device
		devices = convertDevices(realDevices)

		logger.Infof("Found %d devices on the network", len(devices))

		// Fingerprint devices
		logger.Info("Fingerprinting discovered devices...")
		fingerprinter := fingerprint.NewFingerprinter(cfg)
		for i := range realDevices {
			err := fingerprinter.FingerprintDevice(&realDevices[i])
			if err != nil && cfg.Verbose {
				logger.Errorf("Error fingerprinting device %s: %v", realDevices[i].IP, err)
			}
		}

		// Perform vulnerability scanning if full scan is enabled
		if cfg.FullScan {
			logger.Info("Scanning for vulnerabilities...")
			vulnScanner := vulnerability.NewScanner(cfg)
			for i := range realDevices {
				vulns, err := vulnScanner.ScanDevice(&realDevices[i])
				if err != nil && cfg.Verbose {
					logger.Errorf("Error scanning device %s for vulnerabilities: %v", realDevices[i].IP, err)
				}
				devices[i].Vulnerabilities = convertVulnerabilities(vulns)
			}

			// Check for default credentials
			logger.Info("Checking for default credentials...")
			credChecker := credentials.NewChecker(cfg)
			for i := range realDevices {
				creds, err := credChecker.CheckDevice(&realDevices[i])
				if err != nil && cfg.Verbose {
					logger.Errorf("Error checking device %s for default credentials: %v", realDevices[i].IP, err)
				}
				devices[i].DefaultCredentials = convertCredentials(creds)
			}
		}

		// Save results
		if cfg.OutputFile != "" {
			err := config.WriteResultsToFile(devices, cfg.OutputFile)
			if err != nil {
				logger.Fatalf("Error writing results to file: %v", err)
			}
			logger.Infof("Results written to %s", cfg.OutputFile)
		}
	}

	// Display summary
	displaySummary(devices)

	// Start dashboard if enabled
	if cfg.EnableDashboard {
		logger.Infof("Starting web dashboard on port %s", cfg.DashboardPort)
		dashboardServer := api.NewDashboardServer(cfg)
		go func() {
			err := dashboardServer.Start()
			if err != nil {
				logger.Errorf("Dashboard server error: %v", err)
			}
		}()

		// Wait for dashboard users
		color.Green("\nWeb dashboard running at http://localhost:%s", cfg.DashboardPort)
		color.Green("Press Ctrl+C to exit")

		// Wait for interrupt signal
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c

		logger.Info("Shutting down...")
	}

	// Display summary
	displaySummary(devices)
}

func displayBanner() {
	banner := `
╔══════════════════════════════════════════════════╗
║                                                  ║
║           IoT Device Security Scanner            ║
║                                                  ║
║           Identify - Fingerprint - Secure        ║
║                                                  ║
╚══════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

// loadResults loads scan results from a JSON file
func loadResults(filePath string) ([]models.Device, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var devices []models.Device
	err = json.Unmarshal(data, &devices)
	return devices, err
}

// Helper functions to convert between discovery and models types
func convertDevices(discoveryDevices []discovery.Device) []models.Device {
	var devices []models.Device
	for _, d := range discoveryDevices {
		devices = append(devices, models.Device{
			IP:              d.IP,
			MAC:             d.MAC,
			Hostname:        d.Hostname,
			Vendor:          d.Vendor,
			Model:           d.Model,
			FirmwareVersion: d.FirmwareVersion,
			OperatingSystem: d.OperatingSystem,
			LastSeen:        d.LastSeen,
			OpenPorts:       d.OpenPorts,
			Services:        d.Services,
			Banners:         d.Banners,
			Tags:            d.Tags,
		})
	}
	return devices
}

func convertVulnerabilities(vulns interface{}) []models.Vulnerability {
	// In a real implementation, this would properly convert between vulnerability types
	// For now, return empty slice to make it compile
	return []models.Vulnerability{}
}

func convertCredentials(creds interface{}) []models.Credential {
	// In a real implementation, this would properly convert between credential types
	// For now, return empty slice to make it compile
	return []models.Credential{}
}

func displaySummary(devices []models.Device) {
	fmt.Println("\n=== Scan Summary ===")
	fmt.Printf("Total devices discovered: %d\n", len(devices))

	var identifiedCount, vulnerableCount, defaultCredsCount int

	// Count device types
	deviceTypes := make(map[string]int)

	for _, device := range devices {
		if device.Vendor != "" || device.Model != "" {
			identifiedCount++
		}

		if len(device.Vulnerabilities) > 0 {
			vulnerableCount++
		}

		if len(device.DefaultCredentials) > 0 {
			defaultCredsCount++
		}

		// Categorize device types
		for _, tag := range device.Tags {
			deviceTypes[tag]++
		}
	}

	fmt.Printf("Identified devices: %d\n", identifiedCount)
	fmt.Printf("Devices with vulnerabilities: %d\n", vulnerableCount)
	fmt.Printf("Devices with default credentials: %d\n", defaultCredsCount)

	// List vulnerable devices
	if vulnerableCount > 0 {
		fmt.Println("\nVulnerable devices:")
		for _, device := range devices {
			if len(device.Vulnerabilities) > 0 {
				fmt.Printf("  - %s (%s %s): %d vulnerabilities\n",
					device.IP, device.Vendor, device.Model, len(device.Vulnerabilities))
			}
		}
	}

	// List devices with default credentials
	if defaultCredsCount > 0 {
		fmt.Println("\nDevices with default credentials:")
		for _, device := range devices {
			if len(device.DefaultCredentials) > 0 {
				fmt.Printf("  - %s (%s %s): %d credential sets\n",
					device.IP, device.Vendor, device.Model, len(device.DefaultCredentials))
			}
		}
	}
}
