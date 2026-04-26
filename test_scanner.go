package main

import (
	"fmt"

	"github.com/fatih/color"
	"iot-scanner
	"iot-scanner/pkg/integration"
	"github.com/sirupsen/logrus"
)

// RunTestScanner executes a test scan using the integration TestScanner
func RunTestScanner() {
	// Print banner
	color.Cyan("\n=== IoT Device Security Scanner (Test Mode) ===\n")

	// Set up simulated network range
	networkRange := "192.168.1.0/24"
	color.Green("Starting scan on network range: %s", networkRange)
	
	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	
	// Create config
	cfg := config.Config{
		IPRange:      networkRange,
		Threads:      10,
		Timeout:      5,
		Verbose:      true,
		FullScan:     true,
		OutputFile:   "results.json",
		EnableExport: true,
		OutputFormat: "json",
	}

	// Create test scanner
	scanner := integration.NewTestScanner(cfg, logger)
	
	// Simulate device discovery and scan
	color.Yellow("Simulating device discovery...")
	logger.Info("Starting test scan...")
	err := scanner.Scan()
	if err != nil {
		logger.Errorf("Error during scan: %v", err)
		return
	}
	
	// Display summary results
	color.Green("\nScan Complete!")
	color.Green("Results have been saved to %s", cfg.OutputFile)
	
	// Display notice about viewing detailed results
	fmt.Println("\nTo view detailed results, open the results file or run the dashboard.")
	fmt.Println("The test scanner has generated simulated devices with the following types:")
	fmt.Println("  - IP Cameras")
	fmt.Println("  - WiFi Routers")
	fmt.Println("  - Smart Speakers")
	fmt.Println("  - Bluetooth Devices")
	fmt.Println("\nSome devices include simulated vulnerabilities and default credentials for testing purposes.")
}
