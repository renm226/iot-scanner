package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/renm226/iot-scanner/pkg/api"
	"github.com/renm226/iot-scanner/pkg/config"
	"github.com/renm226/iot-scanner/pkg/discovery"
	"github.com/sirupsen/logrus"
)

func RunRealScan() {
	// Create a logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Print banner
	color.Cyan("\n=== IoT Device Security Scanner - Live Scanning ===\n")

	// Get network range from arguments or use default
	networkRange := "192.168.1.0/24"
	if len(os.Args) > 1 {
		networkRange = os.Args[1]
	}
	color.Green("Target network: %s", networkRange)
	
	// Create scanner configuration
	scannerConfig := config.Config{
		IPRange:       networkRange,
		Timeout:       5 * time.Second,
		Verbose:       true,
		Threads:       10,
		FullScan:      true,
		FingerPrintDB: "data/fingerprints.json",
		DatabasePath:  "data",
		OutputFile:    "results.json",
	}
	
	// Make sure data directories exist
	os.MkdirAll("data", 0755)
	
	// Configuration for the dashboard
	dashboardConfig := api.DashboardConfig{
		Port:            "8080",
		EnableCORS:      true,
		ResultsHistory:  10,
		EnableRealTime:  true,
		AllowExports:    true,
		EnableRemediate: true,
	}

	// Create dashboard
	color.Green("Initializing web dashboard...")
	dashboard := api.NewDashboard(dashboardConfig, logger)

	// Set up context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Handle Ctrl+C for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		color.Yellow("Shutdown signal received, stopping scanner...")
		cancel()
		time.Sleep(2 * time.Second) // Give some time to clean up
		os.Exit(0)
	}()

	// Start the dashboard in a goroutine
	go func() {
		color.Green("Web dashboard is running at: http://localhost:8080")
		if err := dashboard.Start(); err != nil {
			color.Red("Dashboard error: %v", err)
		}
	}()

	// Start periodic scanning
	scanner := discovery.NewScanner(scannerConfig)
	color.Green("Starting periodic scanning (every 5 minutes)...")
	
	// Run first scan immediately
	runScan(ctx, scanner, dashboard, logger)
	
	// Then schedule periodic scans
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			runScan(ctx, scanner, dashboard, logger)
		case <-ctx.Done():
			return
		}
	}
}

func runScan(_ context.Context, scanner *discovery.Scanner, dashboard *api.Dashboard, logger *logrus.Logger) {
	color.Yellow("\nStarting new network scan at %s", time.Now().Format(time.RFC3339))
	
	// The Discover method doesn't take a context, so we'll use a basic implementation
	// Run the scan
	devices, err := scanner.Discover()
	if err != nil {
		color.Red("Scan error: %v", err)
		return
	}
	
	color.Green("Scan complete! Found %d devices", len(devices))
	
	// Add results to dashboard
	dashboard.AddScanResult(devices)
	
	// Log scan results
	for i, device := range devices {
		logger.Infof("Device %d: %s (%s) - %s %s", 
			i+1, device.IP, device.MAC, device.Vendor, device.Model)
		
		if len(device.Vulnerabilities) > 0 {
			logger.Warnf("  - Found %d vulnerabilities!", len(device.Vulnerabilities))
		}
		
		if len(device.DefaultCredentials) > 0 {
			logger.Warnf("  - Device has default credentials!")
		}
	}
}
