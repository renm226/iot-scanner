package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"iot-scanner
	"iot-scanner/pkg/config"
	"iot-scanner/pkg/discovery"
	"iot-scanner/pkg/integration"
	"github.com/sirupsen/logrus"
	
)

var (
	// Command line flags
	ipRange          = flag.String("range", "192.168.1.0/24", "IP range to scan (CIDR notation)")
	threads          = flag.Int("threads", 10, "Number of scanning threads")
	timeout          = flag.Int("timeout", 5, "Timeout for network operations in seconds")
	verbose          = flag.Bool("verbose", false, "Enable verbose output")
	fullScan         = flag.Bool("full", false, "Perform full scan including all security checks")
	enhancedScan     = flag.Bool("enhanced", false, "Perform enhanced scan with SNMP and MAC lookup")
	testMode         = flag.Bool("test", false, "Run in test mode with simulated devices")
	outputFile       = flag.String("output", "results.json", "Output file for scan results")
	outputFormat     = flag.String("format", "json", "Output format: json, csv, md, html, pdf")
	enableExport     = flag.Bool("export", false, "Enable scan report export")
	exportDir        = flag.String("export-dir", "reports", "Directory to save exported reports")
	exportFull       = flag.Bool("export-full", false, "Include full scan data in export")
	enableDashboard  = flag.Bool("dashboard", false, "Enable web dashboard")
	dashboardPort    = flag.String("port", "8080", "Web dashboard port")
	enableLiveCVE    = flag.Bool("live-cve", false, "Enable live CVE feed")
	cveInterval      = flag.Int("cve-interval", 60, "Interval in minutes to check for new CVEs")
	enableExploitNotify = flag.Bool("exploit-notify", false, "Enable notifications for new exploits")
	list             = flag.Bool("list", false, "List available modules and commands")
	help             = flag.Bool("help", false, "Show help")
)

func printHelp() {
	fmt.Println("IoT Device Security Scanner")
	fmt.Println("==========================")
	fmt.Println("\nUsage:")
	fmt.Println("  iot-scanner [options]")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
}

func printBanner() {
	color.Cyan("\n=== IoT Device Security Scanner ===\n")
	color.Cyan("Scanning devices on network for security vulnerabilities\n")
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Show help if requested
	if *help {
		printHelp()
		return
	}

	// Show available modules and commands if requested
	if *list {
		fmt.Println("Available commands:")
		fmt.Println("  scan      - Perform a network scan")
		fmt.Println("  dashboard - Start the web dashboard")
		fmt.Println("  topology  - Generate network topology")
		fmt.Println("  snmp      - Perform SNMP scanning")
		fmt.Println("  firmware  - Analyze device firmware")
		return
	}

	// Create a logger
	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Create configuration
	cfg := config.Config{
		IPRange:            *ipRange,
		Threads:            *threads,
		Timeout:            time.Duration(*timeout) * time.Second,
		Verbose:            *verbose,
		FullScan:           *fullScan,
		EnhancedScan:       *enhancedScan,
		TestMode:           *testMode,
		OutputFile:         *outputFile,
		OutputFormat:       *outputFormat,
		EnableExport:       *enableExport,
		ExportDirectory:    *exportDir,
		ExportFull:         *exportFull,
		EnableDashboard:    *enableDashboard,
		DashboardPort:      *dashboardPort,
		EnableLiveCVE:      *enableLiveCVE,
		CVEInterval:        *cveInterval,
		EnableExploitNotify: *enableExploitNotify,
		DatabasePath:       "data",
	}

	// Print banner
	printBanner()

	// Prepare export directory if needed
	if cfg.EnableExport {
		os.MkdirAll(cfg.ExportDirectory, 0755)
	}

	// Start dashboard if enabled
	if cfg.EnableDashboard {
		dashboard := api.NewDashboardServer(cfg)
		go dashboard.Start()
		color.Green("Web dashboard started on http://localhost:%s\n", cfg.DashboardPort)
	}

	// Run scan
	var scanner interface {
		Scan() error
	}

	// Choose scanner based on configuration
	if cfg.TestMode {
		scanner = integration.NewTestScanner(cfg, logger)
	} else if cfg.EnhancedScan {
		// Create enhanced scanner config
		enhancedCfg := integration.EnhancedScannerConfig{
			DataDir:       "data",
			Concurrency:   cfg.Threads,
			ScanTimeout:   cfg.Timeout,
			LogLevel:      logger.Level,
			EnableSNMP:    true,
			EnableMacLookup: true,
			EnableTopologyMap: true,
			SNMPRetries:   2,
			SNMPTimeout:   3 * time.Second,
		}
		
		enhancedScanner, err := integration.NewEnhancedScanner(enhancedCfg)
		if err != nil {
			logger.Errorf("Failed to create enhanced scanner: %v", err)
			return
		}
		scanner = enhancedScanner
	} else {
		scanner = discovery.NewScanner(cfg)
	}

	// Perform scan
	color.Green("Starting scan of %s...\n", cfg.IPRange)
	err := scanner.Scan()
	if err != nil {
		logger.Errorf("Scan failed: %v", err)
		return
	}

	color.Green("Scan complete! Results written to %s\n", cfg.OutputFile)
}
