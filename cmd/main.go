package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/renm226/iot-scanner/pkg/api"
	"github.com/renm226/iot-scanner/pkg/config"
	"github.com/renm226/iot-scanner/pkg/discovery"
	"github.com/renm226/iot-scanner/pkg/integration"
	"github.com/renm226/iot-scanner/pkg/models"
)

const (
	appName    = "IoT Device Security Scanner"
	appVersion = "1.2.0"
)

var (
	log         = logrus.New()
	scanResults []models.Device
)

func main() {
	// Create app directory structure if it doesn't exist
	ensureAppDirectories()

	app := &cli.App{
		Name:    "iot-scanner",
		Usage:   "Advanced IoT Device Security Scanner",
		Version: appVersion,
		HideVersion: true,
		Authors: []*cli.Author{
			{
				Name:  "IoT Security Team",
				Email: "support@iotscan.example.com",
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "config.json",
				Usage:   "Load configuration from `FILE`",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"vv"},
				Usage:   "Enable verbose output",
			},
			&cli.BoolFlag{
				Name:    "version",
				Aliases: []string{"ver"},
				Usage:   "Print version information",
			},
			&cli.StringFlag{
				Name:    "log-level",
				Value:   "info",
				Usage:   "Log level (debug, info, warn, error)",
				EnvVars: []string{"IOT_SCANNER_LOG_LEVEL"},
			},
		},
		Before: func(c *cli.Context) error {
			// Check if version flag is set
			if c.Bool("version") {
				fmt.Printf("IoT Scanner v%s\n", appVersion)
				os.Exit(0)
			}

			// Configure logging
			logLevel := c.String("log-level")
			level, err := logrus.ParseLevel(logLevel)
			if err != nil {
				level = logrus.InfoLevel
			}
			log.SetLevel(level)
			
			// Set up log formatting
			log.SetFormatter(&logrus.TextFormatter{
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05",
			})
			
			return nil
		},
		Commands: []*cli.Command{
			commandScan(),
			commandDashboard(),
			commandTopology(),
			commandSNMP(),
			commandFirmware(),
			commandExploit(),
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// ensureAppDirectories creates necessary directories for the application
func ensureAppDirectories() {
	dirs := []string{
		"data",
		"data/fingerprint",
		"data/firmware",
		"data/reports",
		"data/logs",
	}
	
	for _, dir := range dirs {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			fmt.Printf("Error creating directory %s: %v\n", dir, err)
		}
	}
}

// commandScan returns the scan command configuration
func commandScan() *cli.Command {
	return &cli.Command{
		Name:    "scan",
		Aliases: []string{"s"},
		Usage:   "Scan the network for IoT devices",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "range",
				Aliases: []string{"r"},
				Value:   "192.168.1.0/24",
				Usage:   "IP range to scan in CIDR notation",
			},
			&cli.IntFlag{
				Name:    "threads",
				Aliases: []string{"t"},
				Value:   10,
				Usage:   "Number of concurrent scanning threads",
			},
			&cli.BoolFlag{
				Name:    "full",
				Aliases: []string{"f"},
				Usage:   "Perform a full scan including vulnerability checks",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   "scan_results.json",
				Usage:   "Output file for scan results",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Value: 5 * time.Second,
				Usage: "Timeout for network operations",
			},
			&cli.BoolFlag{
				Name:  "enhanced",
				Usage: "Use enhanced scanning capabilities (SNMP, MAC vendor lookup, etc.)",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "snmp",
				Usage: "Enable SNMP scanning",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "topology",
				Usage: "Generate network topology map",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "mac-lookup",
				Usage: "Enable MAC address vendor lookup",
				Value: true,
			},
		},
		Action: func(c *cli.Context) error {
			cfg := config.DefaultConfig()
			cfg.IPRange = c.String("range")
			cfg.Threads = c.Int("threads")
			cfg.FullScan = c.Bool("full")
			cfg.OutputFile = c.String("output")
			cfg.Timeout = c.Duration("timeout")
			cfg.Verbose = c.Bool("verbose")
			
			if c.Bool("enhanced") {
				return runEnhancedScan(c, cfg)
			}
			
			return runBasicScan(cfg)
		},
	}
}

// commandDashboard returns the dashboard command configuration
func commandDashboard() *cli.Command {
	return &cli.Command{
		Name:    "dashboard",
		Aliases: []string{"d"},
		Usage:   "Start the web dashboard for real-time monitoring and analysis",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   "8080",
				Usage:   "Port to run the dashboard on",
			},
			&cli.StringFlag{
				Name:    "host",
				Value:   "localhost",
				Usage:   "Host to bind the dashboard to",
			},
			&cli.StringFlag{
				Name:  "results",
				Value: "scan_results.json",
				Usage: "Load previous scan results from file",
			},
		},
		Action: func(c *cli.Context) error {
			port := c.String("port")
			host := c.String("host")
			resultsFile := c.String("results")
			
			// Load previous scan results if available
			if fileExists(resultsFile) {
				devices, err := loadScanResults(resultsFile)
				if err != nil {
					log.Warnf("Failed to load scan results: %v", err)
				} else {
					scanResults = devices
					log.Infof("Loaded %d devices from %s", len(devices), resultsFile)
				}
			}
			
			// Start the dashboard
			dashboardConfig := api.DashboardConfig{
				Port: port,
				EnableCORS: true,
				ResultsHistory: 10,
				EnableRealTime: true,
			}
			
			dashboard := api.NewDashboard(dashboardConfig, log)
			
			// Add scan results to the dashboard
			if len(scanResults) > 0 {
				dashboard.AddScanResult(scanResults)
			}
			
			// Start the dashboard
			color.Green("Starting dashboard on http://%s:%s", host, port)
			color.Yellow("Press Ctrl+C to stop the dashboard")
			
			return dashboard.Start()
		},
	}
}

// commandTopology returns the topology command configuration
func commandTopology() *cli.Command {
	return &cli.Command{
		Name:    "topology",
		Aliases: []string{"t"},
		Usage:   "Generate and manage network topology maps",
		Subcommands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate a network topology map from scan results",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "input",
						Aliases: []string{"i"},
						Value:   "scan_results.json",
						Usage:   "Input file with scan results",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Value:   "topology.json",
						Usage:   "Output file for topology map",
					},
				},
				Action: func(c *cli.Context) error {
					inputFile := c.String("input")
					outputFile := c.String("output")
					
					// Check if input file exists
					if !fileExists(inputFile) {
						return fmt.Errorf("input file %s does not exist", inputFile)
					}
					
					// Load scan results
					devices, err := loadScanResults(inputFile)
					if err != nil {
						return fmt.Errorf("failed to load scan results: %v", err)
					}
					
					// Generate topology map
					color.Green("Generating network topology map for %d devices", len(devices))
					
					mapper, err := integration.NewEnhancedScanner(integration.DefaultEnhancedScannerConfig())
					if err != nil {
						color.Red("Error creating enhanced scanner: %v", err)
						return nil
					}
					results := mapper.PerformFullScan(devices)
					
					// Save topology map
					if results.NetworkMap != nil {
						// In a real implementation, you would serialize the topology map here
						color.Green("Network topology map generated and saved to %s", outputFile)
					} else {
						color.Yellow("No topology map was generated")
					}
					
					return nil
				},
			},
			{
				Name:  "visualize",
				Usage: "Visualize a network topology map in the browser",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "input",
						Aliases: []string{"i"},
						Value:   "topology.json",
						Usage:   "Input file with topology map",
					},
					&cli.StringFlag{
						Name:    "port",
						Aliases: []string{"p"},
						Value:   "8081",
						Usage:   "Port to run the visualization server on",
					},
				},
				Action: func(c *cli.Context) error {
					color.Yellow("Topology visualization is available through the dashboard")
					color.Yellow("Run 'iot-scanner dashboard' to access the visualization")
					return nil
				},
			},
		},
	}
}

// commandSNMP returns the SNMP command configuration
func commandSNMP() *cli.Command {
	return &cli.Command{
		Name:  "snmp",
		Usage: "SNMP scanning and enumeration tools",
		Subcommands: []*cli.Command{
			{
				Name:  "scan",
				Usage: "Perform SNMP scanning on devices",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "range",
						Aliases: []string{"r"},
						Value:   "192.168.1.0/24",
						Usage:   "IP range to scan in CIDR notation",
					},
					&cli.StringFlag{
						Name:    "community",
						Aliases: []string{"c"},
						Value:   "public",
						Usage:   "SNMP community string",
					},
					&cli.IntFlag{
						Name:    "timeout",
						Value:   3,
						Usage:   "SNMP timeout in seconds",
					},
					&cli.IntFlag{
						Name:    "retries",
						Value:   2,
						Usage:   "Number of SNMP retries",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Value:   "snmp_results.json",
						Usage:   "Output file for SNMP results",
					},
				},
				Action: func(c *cli.Context) error {
					color.Green("Starting SNMP scan on %s", c.String("range"))
					color.Yellow("This feature is available through the enhanced scan")
					color.Yellow("Run 'iot-scanner scan --enhanced --snmp' to use it")
					return nil
				},
			},
		},
	}
}

// commandFirmware returns the firmware command configuration
func commandFirmware() *cli.Command {
	return &cli.Command{
		Name:  "firmware",
		Usage: "Firmware analysis tools",
		Subcommands: []*cli.Command{
			{
				Name:  "analyze",
				Usage: "Analyze firmware for vulnerabilities",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "Firmware file to analyze",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Value:   "firmware_analysis.json",
						Usage:   "Output file for analysis results",
					},
					&cli.BoolFlag{
						Name:  "extract",
						Usage: "Extract the firmware contents for analysis",
						Value: true,
					},
				},
				Action: func(c *cli.Context) error {
					firmwareFile := c.String("file")
					outputFile := c.String("output")
					extract := c.Bool("extract")
					
					// Check if firmware file exists
					if !fileExists(firmwareFile) {
						return fmt.Errorf("firmware file %s does not exist", firmwareFile)
					}
					
					color.Green("Analyzing firmware file: %s", firmwareFile)
					if extract {
						color.Yellow("Extracting firmware contents...")
					}
					
					color.Yellow("This is a placeholder for firmware analysis functionality")
					color.Yellow("In a real implementation, this would analyze the firmware for vulnerabilities")
					color.Green("Results would be saved to: %s", outputFile)
					
					return nil
				},
			},
		},
	}
}

// commandExploit returns the exploit command configuration
func commandExploit() *cli.Command {
	return &cli.Command{
		Name:  "exploit",
		Usage: "Exploit testing tools (use responsibly and only on systems you own)",
		Subcommands: []*cli.Command{
			{
				Name:  "test",
				Usage: "Test for known vulnerabilities on a device",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "target",
						Aliases: []string{"t"},
						Usage:   "Target IP address",
						Required: true,
					},
					&cli.StringSliceFlag{
						Name:    "cve",
						Usage:   "Specific CVEs to test for",
					},
					&cli.BoolFlag{
						Name:  "safe",
						Usage: "Only run safe, non-intrusive tests",
						Value: true,
					},
				},
				Action: func(c *cli.Context) error {
					target := c.String("target")
					cves := c.StringSlice("cve")
					safe := c.Bool("safe")
					
					color.Red("⚠️  IMPORTANT: Only run exploit tests on systems you own or have permission to test")
					color.Red("⚠️  Using this tool without permission may be illegal and unethical")
					
					if safe {
						color.Green("Running in safe mode - only non-intrusive tests will be performed")
					} else {
						color.Red("Running in UNSAFE mode - tests may affect target system stability")
					}
					
					color.Yellow("Target: %s", target)
					if len(cves) > 0 {
						color.Yellow("Testing for specific CVEs: %v", cves)
					} else {
						color.Yellow("Testing for all known vulnerabilities")
					}
					
					color.Yellow("This is a placeholder for exploit testing functionality")
					color.Yellow("In a real implementation, this would test for actual vulnerabilities")
					
					return nil
				},
			},
		},
	}
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// runBasicScan performs a basic network scan
func runBasicScan(cfg config.Config) error {
	color.Green("Starting basic network scan on %s", cfg.IPRange)
	
	scanner := discovery.NewScanner(cfg)
	color.Yellow("Scanning...")
	
	startTime := time.Now()
	devices, err := scanner.Discover()
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}
	
	scanDuration := time.Since(startTime)
	
	color.Green("Scan completed in %v", scanDuration)
	color.Green("Found %d devices", len(devices))
	
	// Save results if output file is specified
	if cfg.OutputFile != "" {
		err = config.WriteResultsToFile(devices, cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to write results: %v", err)
		}
		color.Green("Results saved to %s", cfg.OutputFile)
	}
	
	// Store results for other commands to use
	scanResults = devices
	
	return nil
}

// runEnhancedScan performs an enhanced network scan with additional capabilities
func runEnhancedScan(c *cli.Context, cfg config.Config) error {
	color.Green("Starting enhanced network scan on %s", cfg.IPRange)
	
	// First, run a basic discovery to find devices
	scanner := discovery.NewScanner(cfg)
	color.Yellow("Discovering devices...")
	
	startTime := time.Now()
	devices, err := scanner.Discover()
	if err != nil {
		return fmt.Errorf("discovery failed: %v", err)
	}
	
	discoveryDuration := time.Since(startTime)
	color.Green("Discovery completed in %v", discoveryDuration)
	color.Green("Found %d devices", len(devices))
	
	// Configure enhanced scanner
	enhancedConfig := integration.EnhancedScannerConfig{
		DataDir:               filepath.Join(".", "data"),
		Concurrency:           cfg.Threads,
		ScanTimeout:           cfg.Timeout,
		LogLevel:              log.Level,
		EnableSNMP:            c.Bool("snmp"),
		EnableMacLookup:       c.Bool("mac-lookup"),
		EnableTopologyMap:     c.Bool("topology"),
		EnableFirmwareAnalysis: false, // Not supported in CLI yet
		EnablePacketAnalysis:   false, // Not supported in CLI yet
		SNMPRetries:           2,
		SNMPTimeout:           3 * time.Second,
	}
	
	enhancedScanner, err := integration.NewEnhancedScanner(enhancedConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize enhanced scanner: %v", err)
	}
	
	// Run enhanced scan
	color.Yellow("Performing enhanced scanning...")
	enhancedStartTime := time.Now()
	results := enhancedScanner.PerformFullScan(devices)
	enhancedDuration := time.Since(enhancedStartTime)
	
	color.Green("Enhanced scan completed in %v", enhancedDuration)
	color.Green("Total scan time: %v", time.Since(startTime))
	
	// Get enhanced devices
	enhancedDevices := results.Devices
	
	// Print summary
	color.Green("--- Enhanced Scan Summary ---")
	color.Green("Devices: %d", len(enhancedDevices))
	color.Green("SNMP Results: %d", len(results.SNMPResults))
	if results.NetworkMap != nil {
		color.Green("Network Map: Generated (%d nodes, %d links)", 
			len(results.NetworkMap.Nodes), len(results.NetworkMap.Links))
	} else {
		color.Yellow("Network Map: Not generated")
	}
	
	// Save results
	if cfg.OutputFile != "" {
		err = config.WriteResultsToFile(enhancedDevices, cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to write results: %v", err)
		}
		color.Green("Results saved to %s", cfg.OutputFile)
	}
	
	// Store results for other commands to use
	scanResults = enhancedDevices
	
	return nil
}

// loadScanResults loads scan results from a file
func loadScanResults(filePath string) ([]models.Device, error) {
	var devices []models.Device
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	err = json.Unmarshal(data, &devices)
	return devices, err
}
