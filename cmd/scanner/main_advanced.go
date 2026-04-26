package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"iot-scanner
	"iot-scanner/pkg/config"
	"iot-scanner/pkg/credentials"
	"iot-scanner/pkg/discovery"
	"iot-scanner/pkg/exploit"
	"iot-scanner/pkg/fingerprint"
	"iot-scanner/pkg/firmware"
	"iot-scanner/pkg/pcap"
	"iot-scanner/pkg/vulnerability"
	"github.com/sirupsen/logrus"
)

var (
	logger *logrus.Logger
	stopCh chan struct{}
)

func RunAdvancedScanner() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:      true,
		DisableTimestamp: false,
		FullTimestamp:    true,
	})

	// Create stop channel for graceful shutdown
	stopCh = make(chan struct{})

	// Parse command line arguments
	ipRange := flag.String("range", "192.168.1.1/24", "IP range to scan (CIDR notation)")
	fullScan := flag.Bool("full", false, "Perform full scan including all security checks")
	outputFile := flag.String("output", "", "Output file for scan results (JSON format)")
	timeout := flag.Int("timeout", 5, "Timeout in seconds for network operations")
	threads := flag.Int("threads", 10, "Number of concurrent scanning threads")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	webUI := flag.Bool("web", false, "Start web UI dashboard")
	webPort := flag.String("port", "8080", "Port for web UI dashboard")
	enablePcap := flag.String("pcap", "", "Enable packet capture on specified interface")
	scanType := flag.String("scan-type", "basic", "Scan type: basic, advanced, full")
	configFile := flag.String("config", "", "Path to configuration file")
	enableExploits := flag.Bool("exploits", false, "Enable exploit testing (use with caution)")
	firmwarePath := flag.String("firmware", "", "Path to firmware file for analysis")

	flag.Parse()

	// Set logging level
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Display banner
	displayBanner()

	// Load configuration
	var cfg config.Config
	if *configFile != "" {
		var err error
		cfg, err = config.LoadConfigFromFile(*configFile)
		if err != nil {
			logger.Warnf("Failed to load config file, using defaults: %v", err)
			cfg = config.DefaultConfig()
		}
	} else {
		cfg = config.DefaultConfig()
	}

	// Override config with command line arguments
	if *ipRange != "192.168.1.1/24" {
		cfg.IPRange = *ipRange
	}
	if *fullScan {
		cfg.FullScan = true
	}
	if *outputFile != "" {
		cfg.OutputFile = *outputFile
	}
	if *timeout != 5 {
		cfg.Timeout = time.Duration(*timeout) * time.Second
	}
	if *threads != 10 {
		cfg.Threads = *threads
	}
	cfg.Verbose = *verbose

	logger.Infof("Starting IoT Device Security Scanner with configuration: %+v", cfg)

	// Check if running as root/admin (required for some scanning features)
	if os.Geteuid() != 0 {
		logger.Warn("Warning: Not running as root. Some scanning features (like packet capture) may be limited.")
	}

	// Setup signal handling for graceful shutdown
	setupSignalHandler()

	// Start web dashboard if enabled
	if *webUI {
		go startWebDashboard(*webPort)
	}

	// Start packet capture if enabled
	var packetAnalyzer *pcap.PacketAnalyzer
	if *enablePcap != "" {
		packetAnalyzer = pcap.NewPacketAnalyzer(*enablePcap, logger)
		err := packetAnalyzer.Start()
		if err != nil {
			logger.Errorf("Failed to start packet capture: %v", err)
		} else {
			logger.Infof("Packet capture started on interface %s", *enablePcap)
			defer packetAnalyzer.Stop()
		}
	}

	// Initialize scanner based on scan type
	var scanner interface {
		Discover() ([]discovery.Device, error)
	}

	if *scanType == "advanced" || *scanType == "full" {
		basicScanner := discovery.NewScanner(cfg)
		scanner = discovery.NewAdvancedScanner(basicScanner, logger)
		logger.Info("Using advanced scanner with enhanced detection capabilities")
	} else {
		scanner = discovery.NewScanner(cfg)
		logger.Info("Using basic scanner")
	}

	// Start discovery process
	logger.Infof("Discovering devices on network %s...", cfg.IPRange)
	startTime := time.Now()
	devices, err := scanner.Discover()
	if err != nil {
		logger.Fatalf("Error during device discovery: %v", err)
	}
	scanDuration := time.Since(startTime)

	logger.Infof("Found %d devices on the network (scan duration: %v)", len(devices), scanDuration)

	// Create a channel to collect results from processing goroutines
	results := make(chan *discovery.Device, len(devices))

	// Process devices using multiple goroutines
	for i := range devices {
		device := &devices[i]
		go processDevice(device, cfg, *enableExploits, results)
	}

	// Collect results
	processedDevices := make([]discovery.Device, 0, len(devices))
	for i := 0; i < len(devices); i++ {
		device := <-results
		processedDevices = append(processedDevices, *device)
	}

	// Perform firmware analysis if specified
	if *firmwarePath != "" {
		logger.Infof("Starting firmware analysis on: %s", *firmwarePath)
		analyzer := firmware.NewFirmwareAnalyzer("./firmware_analysis", logger)
		
		options := firmware.AnalysisOptions{
			ExtractFiles:     true,
			DeepScan:         *scanType == "full",
			ScanHardcodedCreds: true,
			ScanForVulnerableComponents: true,
			MaxExtractSize:   1024 * 1024 * 100, // 100 MB max
		}
		
		findings, err := analyzer.AnalyzeFirmware(*firmwarePath, options)
		if err != nil {
			logger.Errorf("Firmware analysis failed: %v", err)
		} else {
			logger.Infof("Firmware analysis complete: found %d security issues", len(findings))
			
			if len(findings) > 0 {
				logger.Info("Critical firmware security issues:")
				for i, finding := range findings {
					if finding.Severity == "Critical" || finding.Severity == "High" {
						logger.Infof("%d. %s (%s): %s", i+1, finding.SignatureName, finding.Severity, finding.Description)
					}
					
					if i >= 9 { // Show max 10 issues
						logger.Infof("... and %d more issues", len(findings)-10)
						break
					}
				}
			}
		}
	}

	// Output results
	if cfg.OutputFile != "" {
		err := config.WriteResultsToFile(processedDevices, cfg.OutputFile)
		if err != nil {
			logger.Fatalf("Error writing results to file: %v", err)
		}
		logger.Infof("Results written to %s", cfg.OutputFile)
	}

	// Display summary
	displaySummary(processedDevices)

	// Wait for web dashboard if enabled
	if *webUI {
		logger.Info("Web dashboard is running. Press Ctrl+C to exit.")
		<-stopCh
	}
}

// processDevice processes a single device
func processDevice(device *discovery.Device, cfg config.Config, enableExploits bool, results chan<- *discovery.Device) {
	// Fingerprint device
	if cfg.Verbose {
		logger.Infof("Fingerprinting device %s...", device.IP)
	}
	
	fingerprinter := fingerprint.NewFingerprinter(cfg)
	err := fingerprinter.FingerprintDevice(device)
	if err != nil && cfg.Verbose {
		logger.Debugf("Error fingerprinting device %s: %v", device.IP, err)
	}

	// Perform vulnerability scanning if full scan is enabled
	if cfg.FullScan {
		if cfg.Verbose {
			logger.Infof("Scanning device %s for vulnerabilities...", device.IP)
		}
		
		vulnScanner := vulnerability.NewScanner(cfg)
		vulns, err := vulnScanner.ScanDevice(device)
		if err != nil && cfg.Verbose {
			logger.Debugf("Error scanning device %s for vulnerabilities: %v", device.IP, err)
		}
		device.Vulnerabilities = vulns

		// Check for default credentials
		if cfg.Verbose {
			logger.Infof("Checking device %s for default credentials...", device.IP)
		}
		
		credChecker := credentials.NewChecker(cfg)
		creds, err := credChecker.CheckDevice(device)
		if err != nil && cfg.Verbose {
			logger.Debugf("Error checking device %s for default credentials: %v", device.IP, err)
		}
		device.DefaultCredentials = creds

		// Perform exploit testing if enabled
		if enableExploits && (device.Vendor != "" || device.Model != "") {
			if cfg.Verbose {
				logger.Infof("Testing exploits against device %s...", device.IP)
			}
			
			exploitTester := exploit.NewExploitTester(logger)
			exploitResults := exploitTester.RunAllTests(device)
			
			for _, result := range exploitResults {
				if result.Successful {
					vuln := discovery.Vulnerability{
						ID:          result.CVE,
						Name:        fmt.Sprintf("Exploit: %s", result.Type),
						Description: result.Details,
						Severity:    result.Severity,
						References:  []string{},
						Remediation: "Update firmware and apply security patches",
					}
					device.Vulnerabilities = append(device.Vulnerabilities, vuln)
				}
			}
		}
	}

	// Send result
	results <- device
}

// startWebDashboard starts the web UI dashboard
func startWebDashboard(port string) {
	logger.Infof("Starting web dashboard on port %s", port)
	logger.Infof("Access the dashboard at http://localhost:%s", port)

	// Create dashboard configuration
	dashboardConfig := api.DashboardConfig{
		Port:            port,
		EnableCORS:      true,
		ResultsHistory:  10,
		EnableRealTime:  true,
		AllowExports:    true,
		EnableRemediate: true,
	}

	// Create and start dashboard
	dashboard := api.NewDashboard(dashboardConfig, logger)
	err := dashboard.Start()
	if err != nil {
		logger.Errorf("Failed to start web dashboard: %v", err)
	}
}

// setupSignalHandler sets up OS signal handling
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		logger.Info("Received shutdown signal. Shutting down gracefully...")
		close(stopCh)
		
		// Allow some time for cleanup
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

// displayBanner shows the application banner
func displayAdvancedBanner() {
	banner := color.New(color.FgCyan).Add(color.Bold)
	banner.Print(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║            IoT Device Security Scanner (Advanced)            ║
║                                                              ║
║    Identify - Fingerprint - Analyze - Exploit - Secure       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`)
}

// displaySummary shows a summary of scan results
func displayAdvancedSummary(devices []discovery.Device) {
	// Calculate statistics
	var identifiedCount, vulnerableCount, defaultCredsCount int
	var criticalVulns, highVulns, mediumVulns, lowVulns int
	
	for _, device := range devices {
		if device.Vendor != "" || device.Model != "" {
			identifiedCount++
		}
		
		if len(device.Vulnerabilities) > 0 {
			vulnerableCount++
			
			// Count by severity
			for _, vuln := range device.Vulnerabilities {
				switch vuln.Severity {
				case "Critical":
					criticalVulns++
				case "High":
					highVulns++
				case "Medium":
					mediumVulns++
				case "Low":
					lowVulns++
				}
			}
		}
		
		if len(device.DefaultCredentials) > 0 {
			defaultCredsCount++
		}
	}
	
	// Print summary with colors
	fmt.Println("\n=== Scan Summary ===")
	fmt.Printf("Total devices discovered: %d\n", len(devices))
	fmt.Printf("Identified devices: %d\n", identifiedCount)
	
	vulnText := fmt.Sprintf("Devices with vulnerabilities: %d", vulnerableCount)
	if vulnerableCount > 0 {
		color.New(color.FgRed).Add(color.Bold).Println(vulnText)
	} else {
		fmt.Println(vulnText)
	}
	
	credsText := fmt.Sprintf("Devices with default credentials: %d", defaultCredsCount)
	if defaultCredsCount > 0 {
		color.New(color.FgYellow).Add(color.Bold).Println(credsText)
	} else {
		fmt.Println(credsText)
	}
	
	// Print vulnerability summary by severity
	fmt.Println("\nVulnerability breakdown:")
	critText := fmt.Sprintf("  Critical: %d", criticalVulns)
	highText := fmt.Sprintf("  High: %d", highVulns)
	medText := fmt.Sprintf("  Medium: %d", mediumVulns)
	lowText := fmt.Sprintf("  Low: %d", lowVulns)
	
	if criticalVulns > 0 {
		color.New(color.FgRed).Add(color.Bold).Println(critText)
	} else {
		fmt.Println(critText)
	}
	
	if highVulns > 0 {
		color.New(color.FgYellow).Add(color.Bold).Println(highText)
	} else {
		fmt.Println(highText)
	}
	
	if mediumVulns > 0 {
		color.New(color.FgCyan).Println(medText)
	} else {
		fmt.Println(medText)
	}
	
	if lowVulns > 0 {
		color.New(color.FgGreen).Println(lowText)
	} else {
		fmt.Println(lowText)
	}
	
	// List critical and high severity issues
	if criticalVulns > 0 || highVulns > 0 {
		fmt.Println("\nCritical and high severity issues:")
		count := 0
		
		for _, device := range devices {
			for _, vuln := range device.Vulnerabilities {
				if vuln.Severity == "Critical" || vuln.Severity == "High" {
					count++
					sevColor := color.FgRed
					if vuln.Severity == "High" {
						sevColor = color.FgYellow
					}
					
					fmt.Printf("  %d. ", count)
					color.New(sevColor).Printf("[%s] ", vuln.Severity)
					fmt.Printf("%s - %s (%s)\n", device.IP, vuln.Name, deviceInfo(device))
				}
				
				if count >= 10 {
					total := criticalVulns + highVulns
					if total > 10 {
						fmt.Printf("  ... and %d more issues (see output file for details)\n", total-10)
					}
					break
				}
			}
			if count >= 10 {
				break
			}
		}
	}
	
	// List devices with default credentials
	if defaultCredsCount > 0 {
		fmt.Println("\nDevices with default credentials:")
		count := 0
		
		for _, device := range devices {
			if len(device.DefaultCredentials) > 0 {
				count++
				fmt.Printf("  %d. %s - %s (%d credential sets)\n", 
					count, device.IP, deviceInfo(device), len(device.DefaultCredentials))
				
				// Show up to 3 credential sets per device
				for i, cred := range device.DefaultCredentials {
					if i < 3 {
						fmt.Printf("     - %s: %s/%s\n", cred.Service, cred.Username, cred.Password)
					} else {
						fmt.Printf("     - ... and %d more\n", len(device.DefaultCredentials)-3)
						break
					}
				}
				
				if count >= 5 {
					if defaultCredsCount > 5 {
						fmt.Printf("  ... and %d more devices (see output file for details)\n", defaultCredsCount-5)
					}
					break
				}
			}
		}
	}
	
	// Security recommendation
	if vulnerableCount > 0 || defaultCredsCount > 0 {
		fmt.Println("\nSecurity Recommendation:")
		if vulnerableCount > 0 {
			color.New(color.FgRed).Add(color.Bold).Println("  ! Critical security issues found on your network")
			fmt.Println("  - Update firmware on vulnerable devices")
			fmt.Println("  - Consider replacing devices with known security issues")
		}
		if defaultCredsCount > 0 {
			color.New(color.FgYellow).Add(color.Bold).Println("  ! Default credentials found on multiple devices")
			fmt.Println("  - Change default passwords immediately")
			fmt.Println("  - Use strong, unique passwords for each device")
		}
	} else if len(devices) > 0 {
		color.New(color.FgGreen).Add(color.Bold).Println("\nNo major security issues detected!")
		fmt.Println("Continue monitoring your network regularly for new devices and vulnerabilities.")
	}
}

// deviceInfo returns formatted device information
func deviceInfo(device discovery.Device) string {
	if device.Vendor != "" || device.Model != "" {
		return fmt.Sprintf("%s %s", device.Vendor, device.Model)
	}
	return "Unidentified Device"
}
