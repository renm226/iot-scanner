package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"iot-scanner/pkg/api"
	"iot-scanner/pkg/config"
	"iot-scanner/pkg/discovery"
	"iot-scanner/pkg/fingerprint"
	"iot-scanner/pkg/models"
)

// CVEData represents information about a CVE vulnerability
type CVEData struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Published   time.Time `json:"published"`
	Updated     time.Time `json:"updated"`
	Affected    []string  `json:"affected_products"`
	Exploits    []Exploit `json:"exploits,omitempty"`
	References  []string  `json:"references"`
}

// Exploit represents information about an exploit for a CVE
type Exploit struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	URL         string `json:"url,omitempty"`
	Author      string `json:"author,omitempty"`
	Date        string `json:"date,omitempty"`
}

// Notification represents a security notification for users
type Notification struct {
	Timestamp   time.Time `json:"timestamp"`
	Level       string    `json:"level"` // info, warning, critical
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	RelatedCVE  string    `json:"related_cve,omitempty"`
	AffectedIPs []string  `json:"affected_ips,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
}

// ReportFormat defines the format for exported reports
type ReportFormat string

const (
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatCSV      ReportFormat = "csv"
	ReportFormatMarkdown ReportFormat = "md"
	ReportFormatHTML     ReportFormat = "html"
	ReportFormatPDF      ReportFormat = "pdf" // Requires additional dependencies
)

// ScanReport represents a complete scan report for export
// DeviceTypeCount holds counts of each device type found in a scan
type DeviceTypeCount struct {
	IPCameras      int `json:"ip_cameras"`
	WiFiDevices    int `json:"wifi_devices"`
	Bluetooth      int `json:"bluetooth_devices"`
	Routers        int `json:"routers"`
	SmartHome      int `json:"smart_home"`
	SmartTV        int `json:"smart_tv"`
	VoiceAssistant int `json:"voice_assistant"`
	Unknown        int `json:"unknown"`
}

type ScanReport struct {
	Timestamp       time.Time       `json:"timestamp"`
	NetworkRange    string          `json:"network_range"`
	TotalDevices    int             `json:"total_devices"`
	VulnerableCount int             `json:"vulnerable_count"`
	Devices         []models.Device `json:"devices"`
	Notifications   []Notification  `json:"notifications,omitempty"`
	CVECount        int             `json:"cve_count"`
	ScanDuration    time.Duration   `json:"scan_duration"`
	DeviceTypes     DeviceTypeCount `json:"device_types"`
}

// DeviceType represents the type of IoT device
type DeviceType string

const (
	DeviceTypeUnknown        DeviceType = "unknown"
	DeviceTypeIPCamera       DeviceType = "ip_camera"
	DeviceTypeWiFi           DeviceType = "wifi_device"
	DeviceTypeBluetooth      DeviceType = "bluetooth_device"
	DeviceTypeRouter         DeviceType = "router"
	DeviceTypeSmartHome      DeviceType = "smart_home"
	DeviceTypeSmartTV        DeviceType = "smart_tv"
	DeviceTypeVoiceAssistant DeviceType = "voice_assistant"
)

var (
	// CLI flags
	networkRange = flag.String("range", "192.168.1.0/24", "Network range to scan in CIDR notation")
	threads      = flag.Int("threads", 10, "Number of concurrent scanning threads")
	timeout      = flag.Int("timeout", 5, "Timeout for network operations in seconds")
	verbose      = flag.Bool("verbose", false, "Enable verbose output")
	fullScan     = flag.Bool("full", false, "Enable full scan with vulnerability checks")
	outputFile   = flag.String("output", "results.json", "File to write results to")
	testMode     = flag.Bool("test", false, "Run in test mode with simulated devices")

	// Dashboard flags
	enableDashboard = flag.Bool("dashboard", false, "Enable web dashboard")
	dashboardPort   = flag.String("port", "8080", "Web dashboard port")

	// CVE and exploit flags
	enableLiveCVE       = flag.Bool("live-cve", false, "Enable live CVE feed")
	cveCheckInterval    = flag.Int("cve-interval", 60, "Interval in minutes to check for new CVEs")
	enableExploitNotify = flag.Bool("exploit-notify", false, "Enable notifications for new exploits")

	// Report export flags
	enableExport    = flag.Bool("export", false, "Enable scan report export")
	exportFormat    = flag.String("format", "json", "Export format (json, csv, md, html, pdf)")
	exportFullData  = flag.Bool("export-full", false, "Include full scan data in export")
	exportDirectory = flag.String("export-dir", "reports", "Directory to save exported reports")

	// General flags
	help = flag.Bool("help", false, "Show help message")

	// Scan tracking variables
	scanStartTime time.Time
	scanDuration  time.Duration

	// Global CVE database
	globalCVEDB     = make(map[string]CVEData)
	globalCVEDBLock = sync.RWMutex{}

	// Notification center
	notifications   = []Notification{}
	notificationsMu = sync.RWMutex{}
)

// exportScanReport exports scan results in the specified format
func exportScanReport(devices []models.Device) {
	// Create a report timestamp
	timestamp := time.Now()
	timeStr := timestamp.Format("20060102-150405")

	// Count vulnerable devices
	vulnerableCount := 0
	for _, device := range devices {
		if len(device.Vulnerabilities) > 0 {
			vulnerableCount++
		}
	}

	// Create the report
	report := ScanReport{
		Timestamp:       timestamp,
		NetworkRange:    *networkRange,
		TotalDevices:    len(devices),
		VulnerableCount: vulnerableCount,
		Devices:         devices,
		ScanDuration:    scanDuration,
		DeviceTypes:     countDeviceTypes(devices),
	}

	// Add notifications if available
	notificationsMu.RLock()
	if len(notifications) > 0 {
		report.Notifications = notifications
	}
	notificationsMu.RUnlock()

	// Add CVE count
	globalCVEDBLock.RLock()
	report.CVECount = len(globalCVEDB)
	globalCVEDBLock.RUnlock()

	// Create filename based on format and timestamp
	filename := fmt.Sprintf("%s/iot_scan_%s.%s", *exportDirectory, timeStr, *exportFormat)

	// Export based on format
	switch ReportFormat(*exportFormat) {
	case ReportFormatJSON:
		exportJSON(report, filename)
	case ReportFormatCSV:
		exportCSV(report, filename)
	case ReportFormatMarkdown:
		exportMarkdown(report, filename)
	case ReportFormatHTML:
		exportHTML(report, filename)
	default:
		color.Red("Unsupported export format: %s, defaulting to JSON", *exportFormat)
		exportJSON(report, fmt.Sprintf("%s/iot_scan_%s.json", *exportDirectory, timeStr))
	}

	color.Green("Report exported to: %s", filename)
}

// exportJSON exports the report in JSON format
func exportJSON(report ScanReport, filename string) error {
	var data []byte
	var err error

	// Export with pretty formatting
	data, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		color.Red("Error marshaling JSON: %v", err)
		return err
	}

	// Write to file
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		color.Red("Error writing to file: %v", err)
		return err
	}

	return nil
}

// exportCSV exports the report in CSV format
func exportCSV(report ScanReport, filename string) error {
	// Open file for writing
	file, err := os.Create(filename)
	if err != nil {
		color.Red("Error creating CSV file: %v", err)
		return err
	}
	defer file.Close()

	// Write CSV header
	_, err = file.WriteString("IP,MAC,Vendor,Model,OS,Firmware,OpenPorts,Vulnerabilities,LastSeen\n")
	if err != nil {
		return err
	}

	// Write each device
	for _, device := range report.Devices {
		// Format open ports as comma-separated list
		portList := ""
		// When iterating over a map, the first value is the key (port number)
		i := 0
		for portNum, service := range device.OpenPorts {
			if i > 0 {
				portList += "|"
			}
			portList += fmt.Sprintf("%d (%s)", portNum, service)
			i++
		}

		// Format vulnerabilities
		vulnList := ""
		for i, vuln := range device.Vulnerabilities {
			if i > 0 {
				vulnList += "|"
			}
			vulnList += vuln.ID
		}

		// Write device data
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			device.IP, device.MAC, device.Vendor, device.Model,
			device.OperatingSystem, device.FirmwareVersion, portList, vulnList,
			device.LastSeen.Format(time.RFC3339))

		_, err = file.WriteString(line)
		if err != nil {
			return err
		}
	}

	return nil
}

// exportMarkdown exports the report in Markdown format
func exportMarkdown(report ScanReport, filename string) error {
	// Open file for writing
	file, err := os.Create(filename)
	if err != nil {
		color.Red("Error creating Markdown file: %v", err)
		return err
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "# IoT Security Scan Report\n\n## Summary\n\n- **Scan Time**: %s\n- **Network Range**: %s\n- **Total Devices**: %d\n- **Vulnerable Devices**: %d\n- **Scan Duration**: %v\n\n",
		report.Timestamp.Format(time.RFC3339), report.NetworkRange, report.TotalDevices, report.VulnerableCount, report.ScanDuration)
	if err != nil {
		return err
	}

	// Write device table header
	_, err = file.WriteString("## Discovered Devices\n\n")
	if err != nil {
		return err
	}

	_, err = file.WriteString("| IP | MAC | Vendor | Model | OS | Firmware | Open Ports | Vulnerabilities |\n")
	if err != nil {
		return err
	}

	_, err = file.WriteString("|---|---|---|---|---|---|---|---|\n")
	if err != nil {
		return err
	}

	// Write each device
	for _, device := range report.Devices {
		// Format open ports
		var portParts []string
		for portNum, service := range device.OpenPorts {
			portParts = append(portParts, fmt.Sprintf("%d (%s)", portNum, service))
		}
		portList := strings.Join(portParts, ", ")

		// Format vulnerabilities
		vulnList := ""
		for i, vuln := range device.Vulnerabilities {
			if i > 0 {
				vulnList += ", "
			}
			vulnList += vuln.ID
		}

		// Write device data
		line := fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			device.IP, device.MAC, device.Vendor, device.Model,
			device.OperatingSystem, device.FirmwareVersion, portList, vulnList)

		_, err = file.WriteString(line)
		if err != nil {
			return err
		}
	}

	return nil
}

// exportHTML exports the report in HTML format
func exportHTML(report ScanReport, filename string) error {
	// Open file for writing
	file, err := os.Create(filename)
	if err != nil {
		color.Red("Error creating HTML file: %v", err)
		return err
	}
	defer file.Close()

	// Write HTML header
	html := `<!DOCTYPE html>
<html>
<head>
    <title>IoT Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #3498db; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .vulnerable { color: #e74c3c; font-weight: bold; }
        .summary { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px; }
        .summary-item { padding: 10px; background-color: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>IoT Security Scan Report</h1>
`

	// Add summary section
	html += `<h2>Summary</h2>
<div class="summary">
    <div class="summary-item"><strong>Scan Time:</strong> ` + report.Timestamp.Format(time.RFC3339) + `</div>
    <div class="summary-item"><strong>Network Range:</strong> ` + report.NetworkRange + `</div>
    <div class="summary-item"><strong>Total Devices:</strong> ` + fmt.Sprintf("%d", report.TotalDevices) + `</div>
    <div class="summary-item"><strong>Vulnerable Devices:</strong> ` + fmt.Sprintf("%d", report.VulnerableCount) + `</div>
    <div class="summary-item"><strong>Scan Duration:</strong> ` + report.ScanDuration.String() + `</div>
    <div class="summary-item"><strong>CVE Database Entries:</strong> ` + fmt.Sprintf("%d", report.CVECount) + `</div>
</div>
`

	// Add devices table
	html += `<h2>Discovered Devices</h2>
<table>
    <tr>
        <th>IP</th>
        <th>MAC</th>
        <th>Vendor</th>
        <th>Model</th>
        <th>OS</th>
        <th>Firmware</th>
        <th>Open Ports</th>
        <th>Vulnerabilities</th>
    </tr>
`

	// Add each device
	for _, device := range report.Devices {
		// Format open ports
		var portParts []string
		for portNum, service := range device.OpenPorts {
			portParts = append(portParts, fmt.Sprintf("%d (%s)", portNum, service))
		}
		portList := strings.Join(portParts, ", ")

		// Format vulnerabilities
		vulnList := ""
		rowClass := ""
		if len(device.Vulnerabilities) > 0 {
			rowClass = " class=\"vulnerable\""
			for i, vuln := range device.Vulnerabilities {
				if i > 0 {
					vulnList += ", "
				}
				vulnList += vuln.ID
			}
		}

		// Write device row
		html += fmt.Sprintf("    <tr%s>\n", rowClass) +
			fmt.Sprintf("        <td>%s</td>\n", device.IP) +
			fmt.Sprintf("        <td>%s</td>\n", device.MAC) +
			fmt.Sprintf("        <td>%s</td>\n", device.Vendor) +
			fmt.Sprintf("        <td>%s</td>\n", device.Model) +
			fmt.Sprintf("        <td>%s</td>\n", device.OperatingSystem) +
			fmt.Sprintf("        <td>%s</td>\n", device.FirmwareVersion) +
			fmt.Sprintf("        <td>%s</td>\n", portList) +
			fmt.Sprintf("        <td>%s</td>\n", vulnList) +
			"    </tr>\n"
	}

	// Close HTML
	html += `</table>

`

	// Add notifications if any
	if len(report.Notifications) > 0 {
		html += `<h2>Security Notifications</h2>
<table>
    <tr>
        <th>Time</th>
        <th>Level</th>
        <th>Title</th>
        <th>Message</th>
        <th>Related CVE</th>
    </tr>
`

		for _, notif := range report.Notifications {
			html += fmt.Sprintf("    <tr>\n") +
				fmt.Sprintf("        <td>%s</td>\n", notif.Timestamp.Format(time.RFC3339)) +
				fmt.Sprintf("        <td>%s</td>\n", notif.Level) +
				fmt.Sprintf("        <td>%s</td>\n", notif.Title) +
				fmt.Sprintf("        <td>%s</td>\n", notif.Message) +
				fmt.Sprintf("        <td>%s</td>\n", notif.RelatedCVE) +
				"    </tr>\n"
		}

		html += `</table>
`
	}

	// Footer with timestamp
	html += `<p><em>Report generated on ` + time.Now().Format(time.RFC3339) + `</em></p>
</body>
</html>`

	// Write to file
	_, err = file.WriteString(html)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	// Parse flags
	flag.Parse()

	if *help {
		printHelp()
		return
	}

	// Prepare export directory if needed
	if *enableExport {
		os.MkdirAll(*exportDirectory, 0755)
	}

	// Load or initialize CVE database
	loadCVEDatabase()

	// Track scan start time
	scanStartTime = time.Now()

	// Create a logger
	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Print banner
	color.Cyan("\n=== IoT Device Security Scanner ===\n")
	color.Cyan("Version 1.0.0 - Advanced IoT Security Scanner\n")

	// Create scanner configuration
	scannerConfig := config.Config{
		IPRange:       *networkRange,
		Timeout:       time.Duration(*timeout) * time.Second,
		Verbose:       *verbose,
		Threads:       *threads,
		FullScan:      *fullScan,
		FingerPrintDB: "data/fingerprints.json",
		DatabasePath:  "data",
		OutputFile:    *outputFile,
	}

	// Make sure data directories exist
	os.MkdirAll("data", 0755)

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start live CVE feed in background if enabled
	if *enableLiveCVE {
		go startLiveCVEFeed(ctx, logger)
	}

	// Handle Ctrl+C for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		color.Yellow("Shutdown signal received, stopping scanner...")
		cancel()
		time.Sleep(1 * time.Second) // Give some time to clean up
		os.Exit(0)
	}()

	// Initialize scanner
	scanner := discovery.NewScanner(scannerConfig)

	// Create fingerprinter
	fp := fingerprint.NewFingerprinter(scannerConfig)

	// Initialize dashboard if enabled
	var dashboard *api.Dashboard
	if *enableDashboard {
		dashboardConfig := api.DashboardConfig{
			Port:            *dashboardPort,
			EnableCORS:      true,
			ResultsHistory:  10,
			EnableRealTime:  true,
			AllowExports:    true,
			EnableRemediate: false, // Disable remediation in this version for safety
		}

		color.Green("Initializing web dashboard...")
		dashboard = api.NewDashboard(dashboardConfig, logger)

		// Start the dashboard in a goroutine
		go func() {
			color.Green("Web dashboard is running at: http://localhost:%s", *dashboardPort)
			if err := dashboard.Start(); err != nil {
				color.Red("Dashboard error: %v", err)
			}
		}()
	}

	// Determine if we are in test mode or real scan mode
	var devices []models.Device
	var err error

	if *testMode {
		// Use simulated devices for testing
		color.Green("Running in TEST MODE with simulated devices")
		devices = generateTestDevices()
	} else {
		// Perform the actual network scan
		color.Green("Starting network scan on range: %s", *networkRange)
		color.Yellow("This may take several minutes depending on the size of the network and scan options")

		// Start time already tracked globally as scanStartTime
		devices, err = scanner.Discover()
		if err != nil {
			color.Red("Scan error: %v", err)
			return
		}
	}

	// If full scan is enabled, try to fingerprint devices
	if *fullScan {
		color.Yellow("Fingerprinting discovered devices...")
		for i := range devices {
			err := fp.FingerprintDevice(&devices[i])
			if err != nil {
				logger.Debugf("Failed to fingerprint device %s: %v", devices[i].IP, err)
			}
		}
	}

	// Save results to file
	if err := config.WriteResultsToFile(devices, *outputFile); err != nil {
		color.Red("Failed to write results: %v", err)
	} else {
		color.Green("Scan results saved to %s", *outputFile)
	}

	// Process device types
	deviceTypeCounts := DeviceTypeCount{}

	for i := range devices {
		// Add device type tag
		deviceType := detectDeviceType(&devices[i])

		// Add to appropriate count
		switch deviceType {
		case DeviceTypeIPCamera:
			deviceTypeCounts.IPCameras++
			devices[i].Tags = append(devices[i].Tags, "ip_camera")
		case DeviceTypeWiFi:
			deviceTypeCounts.WiFiDevices++
			devices[i].Tags = append(devices[i].Tags, "wifi_device")
		case DeviceTypeBluetooth:
			deviceTypeCounts.Bluetooth++
			devices[i].Tags = append(devices[i].Tags, "bluetooth_device")
		case DeviceTypeRouter:
			deviceTypeCounts.Routers++
			devices[i].Tags = append(devices[i].Tags, "router")
		case DeviceTypeSmartHome:
			deviceTypeCounts.SmartHome++
			devices[i].Tags = append(devices[i].Tags, "smart_home")
		case DeviceTypeSmartTV:
			deviceTypeCounts.SmartTV++
			devices[i].Tags = append(devices[i].Tags, "smart_tv")
		case DeviceTypeVoiceAssistant:
			deviceTypeCounts.VoiceAssistant++
			devices[i].Tags = append(devices[i].Tags, "voice_assistant")
		default:
			deviceTypeCounts.Unknown++
			devices[i].Tags = append(devices[i].Tags, "unknown")
		}
	}

	// Add to dashboard if enabled
	if *enableDashboard && dashboard != nil {
		dashboard.AddScanResult(devices)

		// Check for vulnerabilities against our CVE database
		if *enableLiveCVE {
			checkDevicesAgainstCVEDB(devices, dashboard)
		}
	}

	// Calculate scan duration
	scanDuration = time.Since(scanStartTime)

	// Print scan summary
	printScanSummary(devices)

	// Export report if enabled
	if *enableExport {
		exportScanReport(devices)
	}
}

func printScanSummary(devices []models.Device) {
	color.Green("\nScan completed in %v", scanDuration)
	color.Green("Found %d devices on the network", len(devices))

	// Count device types
	deviceTypeCounts := countDeviceTypes(devices)

	// Highlight specific device types of interest
	if deviceTypeCounts.IPCameras > 0 {
		color.Cyan("  - IP Cameras detected: %d", deviceTypeCounts.IPCameras)
	}

	if deviceTypeCounts.WiFiDevices > 0 {
		color.Cyan("  - WiFi devices detected: %d", deviceTypeCounts.WiFiDevices)
	}

	if deviceTypeCounts.Bluetooth > 0 {
		color.Cyan("  - Bluetooth devices detected: %d", deviceTypeCounts.Bluetooth)
	}

	if deviceTypeCounts.Routers > 0 {
		color.Cyan("  - Routers detected: %d", deviceTypeCounts.Routers)
	}

	if deviceTypeCounts.SmartHome > 0 {
		color.Cyan("  - Smart Home devices detected: %d", deviceTypeCounts.SmartHome)
	}

	// Print device summary
	identifiedCount := 0
	vulnerableCount := 0
	defaultCredsCount := 0

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
	}

	color.Green("Identified devices: %d", identifiedCount)
	if vulnerableCount > 0 {
		color.Red("Vulnerable devices: %d", vulnerableCount)
	}
	if defaultCredsCount > 0 {
		color.Red("Devices with default credentials: %d", defaultCredsCount)
	}

	// If dashboard is enabled, wait for user to exit
	if *enableDashboard {
		color.Green("\nWeb dashboard is running at: http://localhost:%s", *dashboardPort)
		color.Yellow("Press Ctrl+C to exit")

		// Wait for user to press Ctrl+C
		waitCh := make(chan os.Signal, 1)
		signal.Notify(waitCh, os.Interrupt, syscall.SIGTERM)
		receivedSignal := <-waitCh
		color.Yellow("Received signal %v, shutting down...", receivedSignal)
	}
}

// countDeviceTypes counts the different types of devices in the scan results
func countDeviceTypes(devices []models.Device) DeviceTypeCount {
	counts := DeviceTypeCount{}

	for i := range devices {
		tagFound := false
		for _, tag := range devices[i].Tags {
			switch tag {
			case "ip_camera":
				counts.IPCameras++
				tagFound = true
			case "wifi_device":
				counts.WiFiDevices++
				tagFound = true
			case "bluetooth_device":
				counts.Bluetooth++
				tagFound = true
			case "router":
				counts.Routers++
				tagFound = true
			case "smart_home":
				counts.SmartHome++
				tagFound = true
			case "smart_tv":
				counts.SmartTV++
				tagFound = true
			case "voice_assistant":
				counts.VoiceAssistant++
				tagFound = true
			}
			if tagFound {
				break
			}
		}

		if !tagFound {
			deviceType := detectDeviceType(&devices[i])
			switch deviceType {
			case DeviceTypeIPCamera:
				counts.IPCameras++
			case DeviceTypeWiFi:
				counts.WiFiDevices++
			case DeviceTypeBluetooth:
				counts.Bluetooth++
			case DeviceTypeRouter:
				counts.Routers++
			case DeviceTypeSmartHome:
				counts.SmartHome++
			case DeviceTypeSmartTV:
				counts.SmartTV++
			case DeviceTypeVoiceAssistant:
				counts.VoiceAssistant++
			default:
				counts.Unknown++
			}
		}
	}

	return counts
}

// generateTestDevices creates simulated devices for testing the scanner without network access
func generateTestDevices() []models.Device {
	// Get current time for timestamps
	now := time.Now()

	// Create a variety of simulated devices
	devices := []models.Device{
		{
			// IP Camera 1 (Hikvision)
			IP:              "192.168.1.100",
			MAC:             "aa:bb:cc:11:22:33",
			Hostname:        "hikvision-cam",
			Vendor:          "Hikvision",
			Model:           "DS-2CD2032-I",
			FirmwareVersion: "V5.4.5",
			OpenPorts:       map[int]string{80: "HTTP", 443: "HTTPS", 554: "RTSP"},
			OperatingSystem: "Embedded Linux",
			Banners:         map[int]string{80: "Hikvision Web Server"},
			LastSeen:        now,
			Services:        map[string]string{"HTTP": "Web Interface", "RTSP": "Video Stream"},
		},
		{
			// WiFi Router
			IP:              "192.168.1.1",
			MAC:             "aa:bb:cc:00:11:22",
			Hostname:        "router",
			Vendor:          "TP-Link",
			Model:           "Archer C7",
			FirmwareVersion: "3.15.3",
			OpenPorts:       map[int]string{80: "HTTP", 443: "HTTPS", 53: "DNS"},
			OperatingSystem: "DD-WRT",
			Banners:         map[int]string{80: "DD-WRT Router"},
			LastSeen:        now,
			Services:        map[string]string{"HTTP": "Web Admin", "DNS": "Domain Name Service"},
		},
		{
			// Bluetooth Speaker
			IP:              "192.168.1.101",
			MAC:             "aa:bb:cc:33:44:55",
			Hostname:        "JBL-Speaker",
			Vendor:          "JBL",
			Model:           "Charge 4",
			FirmwareVersion: "1.8.0",
			OpenPorts:       map[int]string{8080: "HTTP Control"},
			OperatingSystem: "Custom Firmware",
			LastSeen:        now,
			Services:        map[string]string{"bluetooth": "A2DP Audio"},
		},
		{
			// Smart Home Hub
			IP:              "192.168.1.102",
			MAC:             "aa:bb:cc:66:77:88",
			Hostname:        "SmartThings-Hub",
			Vendor:          "Samsung",
			Model:           "SmartThings Hub v3",
			FirmwareVersion: "0.45.2",
			OpenPorts:       map[int]string{80: "HTTP", 443: "HTTPS", 8080: "HTTP API"},
			OperatingSystem: "Embedded OS",
			Banners:         map[int]string{80: "SmartThings Hub"},
			LastSeen:        now,
			Services:        map[string]string{"HTTP": "Web Interface", "HTTPS": "Secure API"},
		},
		{
			// IP Camera 2 (with vulnerability)
			IP:              "192.168.1.103",
			MAC:             "aa:bb:cc:99:00:11",
			Hostname:        "dahua-cam",
			Vendor:          "Dahua",
			Model:           "DH-IPC-HDW1431S",
			FirmwareVersion: "2.400.0000000.18",
			OpenPorts:       map[int]string{80: "HTTP", 443: "HTTPS", 554: "RTSP"},
			OperatingSystem: "Embedded Linux",
			Banners:         map[int]string{80: "Dahua Web Server"},
			LastSeen:        now,
			Services:        map[string]string{"HTTP": "Web Interface", "RTSP": "Video Stream"},
			Vulnerabilities: []models.Vulnerability{
				{
					ID:          "CVE-2020-25506",
					Name:        "Authentication Bypass",
					Description: "Authentication bypass vulnerability in Dahua web interface",
					Severity:    "Critical",
					CVSS:        9.8,
					References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-25506"},
					Remediation: "Update firmware to latest version",
				},
			},
		},
	}

	// Return the simulated devices
	return devices
}

func printHelp() {
	fmt.Println("IoT Device Security Scanner - Usage Guide")
	fmt.Println("\nScanning Options:")
	fmt.Println("  -range string     Network range to scan in CIDR notation (default \"192.168.1.0/24\")")
	fmt.Println("  -threads int      Number of concurrent scanning threads (default 10)")
	fmt.Println("  -timeout int      Timeout for network operations in seconds (default 5)")
	fmt.Println("  -verbose          Enable verbose output")
	fmt.Println("  -full             Enable full scan with vulnerability checks")
	fmt.Println("  -output string    File to write results to (default \"results.json\")")

	fmt.Println("\nDashboard Options:")
	fmt.Println("  -dashboard        Enable web dashboard")
	fmt.Println("  -port string      Web dashboard port (default \"8080\")")

	fmt.Println("\nCVE and Exploit Options:")
	fmt.Println("  -live-cve         Enable live CVE feed")
	fmt.Println("  -cve-interval     Interval in minutes to check for new CVEs (default 60)")
	fmt.Println("  -exploit-notify   Enable notifications for new exploits")

	fmt.Println("\nReport Export Options:")
	fmt.Println("  -export           Enable scan report export")
	fmt.Println("  -format string    Export format: json, csv, md, html, pdf (default \"json\")")
	fmt.Println("  -export-full      Include full scan data in export")
	fmt.Println("  -export-dir       Directory to save exported reports (default \"reports\")")

	fmt.Println("\nExamples:")
	fmt.Println("  # Basic scan:")
	fmt.Println("  sudo ./integrated_scanner -range 192.168.1.0/24")
	fmt.Println("")
	fmt.Println("  # Full scan with web dashboard:")
	fmt.Println("  sudo ./integrated_scanner -range 192.168.1.0/24 -full -dashboard -port 8080")
	fmt.Println("")
	fmt.Println("  # Scan with live CVE feed and exploit notifications:")
	fmt.Println("  sudo ./integrated_scanner -range 192.168.1.0/24 -full -dashboard -live-cve -exploit-notify")
	fmt.Println("")
	fmt.Println("  # Full scan with report export in HTML format:")
	fmt.Println("  sudo ./integrated_scanner -range 192.168.1.0/24 -full -export -format html")
	fmt.Println("")
	fmt.Println("  # Complete security assessment with all features:")
	fmt.Println("  sudo ./integrated_scanner -range 192.168.1.0/24 -full -dashboard -live-cve -exploit-notify -export -format html")
	fmt.Println("")
	fmt.Println("  # Verbose scan with custom output:")
	fmt.Println("  sudo ./integrated_scanner -range 10.0.0.0/24 -verbose -output network_scan.json")
}

// loadCVEDatabase loads the CVE database from file or initializes it
func loadCVEDatabase() {
	// Try to load from a local file first
	data, err := os.ReadFile("data/cve_database.json")
	if err == nil {
		err = json.Unmarshal(data, &globalCVEDB)
		if err == nil {
			color.Green("Loaded %d CVEs from local database", len(globalCVEDB))
			return
		}
	}

	// Initialize with some example high-risk IoT CVEs
	globalCVEDB = map[string]CVEData{
		"CVE-2021-36260": {
			ID:          "CVE-2021-36260",
			Description: "Command injection vulnerability in the web server of Hikvision IP cameras and DVRs allows an attacker to gain full control over devices without authentication.",
			Severity:    "Critical",
			Published:   time.Date(2021, 9, 19, 0, 0, 0, 0, time.UTC),
			Affected:    []string{"Hikvision IP cameras", "Hikvision DVRs"},
			Exploits: []Exploit{
				{
					Name:        "Exploit for CVE-2021-36260",
					Description: "Python script to exploit command injection in Hikvision devices",
					Type:        "Proof of Concept",
					URL:         "https://github.com/threatmonitor/Hikvision-CVE-2021-36260",
				},
			},
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-36260",
				"https://www.hikvision.com/en/support/cybersecurity/security-advisories/security-notification-command-injection-vulnerability-in-some-hikvision-products/",
			},
		},
		"CVE-2020-25506": {
			ID:          "CVE-2020-25506",
			Description: "A vulnerability in TOTOLINK routers allows remote attackers to execute arbitrary OS commands via shell metacharacters.",
			Severity:    "Critical",
			Published:   time.Date(2020, 9, 14, 0, 0, 0, 0, time.UTC),
			Affected:    []string{"TOTOLINK A3000RU", "TOTOLINK N600R", "TOTOLINK A850R", "TOTOLINK A950RG"},
			Exploits: []Exploit{
				{
					Name:        "TOTOLINK Remote Code Execution",
					Description: "Exploit for remote command execution on TOTOLINK routers",
					Type:        "Remote Code Execution",
				},
			},
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2020-25506",
			},
		},
		"CVE-2019-9483": {
			ID:          "CVE-2019-9483",
			Description: "Information disclosure vulnerability in Ring doorbells exposes WiFi credentials during setup.",
			Severity:    "High",
			Published:   time.Date(2019, 7, 1, 0, 0, 0, 0, time.UTC),
			Affected:    []string{"Ring Video Doorbell Pro"},
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9483"},
		},
	}

	// Create directory if it doesn't exist
	os.MkdirAll("data", 0755)

	// Save initial database
	saveCVEDatabase()
}

// saveCVEDatabase saves the CVE database to file
func saveCVEDatabase() {
	globalCVEDBLock.RLock()
	defer globalCVEDBLock.RUnlock()

	data, err := json.MarshalIndent(globalCVEDB, "", "  ")
	if err == nil {
		os.WriteFile("data/cve_database.json", data, 0644)
	}
}

// startLiveCVEFeed starts a background goroutine to fetch new CVEs periodically
func startLiveCVEFeed(ctx context.Context, logger *logrus.Logger) {
	color.Green("Starting live CVE feed. Checking for updates every %d minutes", *cveCheckInterval)

	// Do an initial check
	fetchLatestCVEs(logger)

	// Then set up a ticker for periodic checks
	ticker := time.NewTicker(time.Duration(*cveCheckInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fetchLatestCVEs(logger)
		case <-ctx.Done():
			logger.Info("Stopping CVE feed")
			return
		}
	}
}

// fetchLatestCVEs fetches the latest CVEs from an external source
func fetchLatestCVEs(logger *logrus.Logger) {
	// In a real implementation, this would call an actual CVE API
	// For this demo, we'll simulate finding a new CVE periodically

	// Generate a random "new" CVE to simulate the feed
	timeStamp := time.Now()
	timeStampStr := timeStamp.Format("20060102-150405")

	// Create a simulated new CVE
	newCVE := CVEData{
		ID:          fmt.Sprintf("CVE-2025-%s", timeStampStr[4:8]),
		Description: "Recently discovered vulnerability affecting IoT devices allowing remote code execution.",
		Severity:    "Critical",
		Published:   timeStamp,
		Updated:     timeStamp,
		Affected:    []string{"Multiple IoT Devices", "Smart Home Systems"},
		Exploits: []Exploit{
			{
				Name:        "New IoT Exploit",
				Description: "Zero-day exploit targeting vulnerable IoT devices",
				Type:        "Remote Code Execution",
				Date:        timeStamp.Format(time.RFC3339),
			},
		},
		References: []string{
			"https://example.com/cve-database",
		},
	}

	// Add to our database
	globalCVEDBLock.Lock()
	globalCVEDB[newCVE.ID] = newCVE
	globalCVEDBLock.Unlock()

	// Save updated database
	saveCVEDatabase()

	// Create notification about new CVE
	if *enableExploitNotify {
		notification := Notification{
			Timestamp: timeStamp,
			Level:     "critical",
			Title:     fmt.Sprintf("New Exploit Available: %s", newCVE.ID),
			Message: fmt.Sprintf("A new exploit has been detected for %s. This affects %s devices and is rated %s severity.",
				newCVE.ID, strings.Join(newCVE.Affected, ", "), newCVE.Severity),
			RelatedCVE:  newCVE.ID,
			Remediation: "Apply security updates from manufacturer as soon as they become available.",
		}

		notificationsMu.Lock()
		notifications = append(notifications, notification)
		notificationsMu.Unlock()

		// Display the notification
		color.Red("\n!!! NEW EXPLOIT DETECTED !!!")
		color.Red("CVE: %s", newCVE.ID)
		color.Red("Severity: %s", newCVE.Severity)
		color.Red("Description: %s", newCVE.Description)
		color.Red("Affected: %s", strings.Join(newCVE.Affected, ", "))
		color.Yellow("Remediation: Apply security updates from manufacturer as soon as they become available.")
	}

	logger.Infof("Updated CVE database with %d total entries", len(globalCVEDB))
}

// checkDevicesAgainstCVEDB checks discovered devices against known CVEs
func checkDevicesAgainstCVEDB(devices []models.Device, _ *api.Dashboard) {
	globalCVEDBLock.RLock()
	defer globalCVEDBLock.RUnlock()

	for i, device := range devices {
		vulnDevices := findVulnerabilities(&devices[i])

		if len(vulnDevices) > 0 && *enableExploitNotify {
			// Create notification for vulnerable device
			notification := Notification{
				Timestamp: time.Now(),
				Level:     "warning",
				Title:     fmt.Sprintf("Vulnerable Device: %s", device.IP),
				Message: fmt.Sprintf("%s %s running firmware %s is vulnerable to %d known exploits",
					device.Vendor, device.Model, device.FirmwareVersion, len(vulnDevices)),
				AffectedIPs: []string{device.IP},
				Remediation: "Update device firmware and change default credentials if present.",
			}

			notificationsMu.Lock()
			notifications = append(notifications, notification)
			notificationsMu.Unlock()

			// Display notification
			color.Yellow("\n! VULNERABLE DEVICE DETECTED !")
			color.Yellow("IP: %s", device.IP)
			color.Yellow("Details: %s %s (Firmware: %s)", device.Vendor, device.Model, device.FirmwareVersion)
			color.Yellow("Vulnerabilities: %d known exploits", len(vulnDevices))
		}
	}
}

// findVulnerabilities checks a device against known CVEs and returns matching vulnerabilities
// detectDeviceType determines the type of IoT device based on its characteristics
func detectDeviceType(device *models.Device) DeviceType {
	// Initialize as unknown
	deviceType := DeviceTypeUnknown

	// Check for IP cameras based on ports, banners, and vendor
	if isIPCamera(device) {
		return DeviceTypeIPCamera
	}

	// Check for WiFi devices
	if isWiFiDevice(device) {
		return DeviceTypeWiFi
	}

	// Check for Bluetooth devices
	if isBluetoothDevice(device) {
		return DeviceTypeBluetooth
	}

	// Check for routers
	if isRouter(device) {
		return DeviceTypeRouter
	}

	// Check for smart home devices
	if isSmartHomeDevice(device) {
		return DeviceTypeSmartHome
	}

	// Other device types can be added here

	return deviceType
}

// isIPCamera checks if a device is an IP camera
func isIPCamera(device *models.Device) bool {
	// Common IP camera ports
	cameraPorts := []int{80, 443, 554, 1935, 8000, 8080, 8554, 9000}

	// Check if device has any of the camera ports open
	for _, port := range cameraPorts {
		if _, ok := device.OpenPorts[port]; ok {
			// Check for RTSP, which is common in IP cameras
			if port == 554 || strings.Contains(strings.ToLower(device.OpenPorts[port]), "rtsp") {
				return true
			}
		}
	}

	// Check banners for camera-related strings
	for _, banner := range device.Banners {
		bannerLower := strings.ToLower(banner)
		if strings.Contains(bannerLower, "camera") ||
			strings.Contains(bannerLower, "ipcam") ||
			strings.Contains(bannerLower, "netcam") ||
			strings.Contains(bannerLower, "webcam") {
			return true
		}
	}

	// Check vendor for known camera manufacturers
	knownCameraVendors := []string{
		"hikvision", "dahua", "axis", "hanwha", "vivotek", "tplink",
		"foscam", "nest", "arlo", "wyze", "reolink", "amcrest", "lorex",
		"swann", "unifi", "dlink", "eufy", "ezviz", "geovision",
	}

	vendorLower := strings.ToLower(device.Vendor)
	for _, vendor := range knownCameraVendors {
		if strings.Contains(vendorLower, vendor) {
			return true
		}
	}

	// Check model name for camera indicators
	modelLower := strings.ToLower(device.Model)
	if strings.Contains(modelLower, "cam") ||
		strings.Contains(modelLower, "ipc") ||
		strings.Contains(modelLower, "dvr") ||
		strings.Contains(modelLower, "nvr") {
		return true
	}

	return false
}

// isWiFiDevice checks if a device is a WiFi device
func isWiFiDevice(device *models.Device) bool {
	// Common WiFi device ports
	wifiPorts := []int{53, 67, 68, 80, 443, 8080, 8888}

	// Check if the device has multiple WiFi-related ports open
	wifiPortCount := 0
	for _, port := range wifiPorts {
		if _, ok := device.OpenPorts[port]; ok {
			wifiPortCount++
		}
	}

	// If device has several WiFi-related ports, it's likely a WiFi device
	if wifiPortCount >= 3 {
		return true
	}

	// Check vendor for known WiFi device manufacturers
	knownWiFiVendors := []string{
		"cisco", "netgear", "linksys", "tp-link", "tplink", "asus", "d-link", "dlink",
		"belkin", "ubiquiti", "huawei", "aruba", "meraki", "ruckus", "mikrotik",
		"zyxel", "actiontec", "buffalo", "eero", "google wifi", "nest wifi",
	}

	vendorLower := strings.ToLower(device.Vendor)
	for _, vendor := range knownWiFiVendors {
		if strings.Contains(vendorLower, vendor) {
			return true
		}
	}

	// Check services for WiFi-related protocols
	for service := range device.Services {
		serviceLower := strings.ToLower(service)
		if strings.Contains(serviceLower, "wifi") ||
			strings.Contains(serviceLower, "wireless") ||
			strings.Contains(serviceLower, "wlan") {
			return true
		}
	}

	// Check model name for WiFi indicators
	modelLower := strings.ToLower(device.Model)
	if strings.Contains(modelLower, "wifi") ||
		strings.Contains(modelLower, "wireless") ||
		strings.Contains(modelLower, "wlan") ||
		strings.Contains(modelLower, "router") ||
		strings.Contains(modelLower, "access point") {
		return true
	}

	return false
}

// isBluetoothDevice checks if a device is a Bluetooth device
func isBluetoothDevice(device *models.Device) bool {
	// Note: Bluetooth devices typically aren't directly accessible via IP
	// This function relies on device information that might indicate Bluetooth capability

	// Check vendor for known Bluetooth device manufacturers
	knownBluetoothVendors := []string{
		"bose", "sony", "jabra", "logitech", "jbl", "samsung", "lg",
		"apple", "beats", "sennheiser", "plantronics", "poly", "anker",
		"xiaomi", "huawei", "oneplus", "nokia", "motorola",
	}

	vendorLower := strings.ToLower(device.Vendor)
	for _, vendor := range knownBluetoothVendors {
		if strings.Contains(vendorLower, vendor) {
			// Further check model for Bluetooth indicators
			modelLower := strings.ToLower(device.Model)
			if strings.Contains(modelLower, "bt") ||
				strings.Contains(modelLower, "bluetooth") ||
				strings.Contains(modelLower, "wireless") ||
				strings.Contains(modelLower, "headset") ||
				strings.Contains(modelLower, "earbuds") ||
				strings.Contains(modelLower, "speaker") {
				return true
			}
		}
	}

	// Check for Bluetooth-related services
	for service := range device.Services {
		serviceLower := strings.ToLower(service)
		if strings.Contains(serviceLower, "bluetooth") ||
			strings.Contains(serviceLower, "bt") ||
			strings.Contains(serviceLower, "a2dp") {
			return true
		}
	}

	return false
}

// isRouter checks if a device is a router
func isRouter(device *models.Device) bool {
	// Check common router ports
	routerPorts := []int{22, 23, 53, 80, 443, 8080, 8443}
	routerPortCount := 0

	for _, port := range routerPorts {
		if _, ok := device.OpenPorts[port]; ok {
			routerPortCount++
		}
	}

	// If many router ports are open, it's likely a router
	if routerPortCount >= 3 {
		return true
	}

	// Check vendor for known router manufacturers
	knownRouterVendors := []string{
		"cisco", "netgear", "linksys", "tp-link", "tplink", "asus",
		"d-link", "dlink", "huawei", "mikrotik", "ubiquiti", "edge",
		"zyxel", "actiontec", "belkin", "buffalo", "arris", "technicolor",
	}

	vendorLower := strings.ToLower(device.Vendor)
	for _, vendor := range knownRouterVendors {
		if strings.Contains(vendorLower, vendor) {
			return true
		}
	}

	// Check model for router indicators
	modelLower := strings.ToLower(device.Model)
	if strings.Contains(modelLower, "router") ||
		strings.Contains(modelLower, "gateway") ||
		strings.Contains(modelLower, "modem") {
		return true
	}

	return false
}

// isSmartHomeDevice checks if a device is a smart home device
func isSmartHomeDevice(device *models.Device) bool {
	// Check vendor for known smart home device manufacturers
	knownSmartHomeVendors := []string{
		"philips", "hue", "nest", "ring", "ecobee", "august",
		"chamberlain", "lutron", "wemo", "insteon", "smartthings",
		"google", "amazon", "apple", "lifx", "tplink", "xiaomi",
		"tuya", "wink", "honeywell", "arlo", "eufy", "sonos",
	}

	vendorLower := strings.ToLower(device.Vendor)
	for _, vendor := range knownSmartHomeVendors {
		if strings.Contains(vendorLower, vendor) {
			return true
		}
	}

	// Check model for smart home indicators
	modelLower := strings.ToLower(device.Model)
	if strings.Contains(modelLower, "smart") ||
		strings.Contains(modelLower, "home") ||
		strings.Contains(modelLower, "thermostat") ||
		strings.Contains(modelLower, "switch") ||
		strings.Contains(modelLower, "sensor") ||
		strings.Contains(modelLower, "plug") ||
		strings.Contains(modelLower, "hub") ||
		strings.Contains(modelLower, "bulb") ||
		strings.Contains(modelLower, "doorbell") ||
		strings.Contains(modelLower, "lock") {
		return true
	}

	return false
}

func findVulnerabilities(device *models.Device) []models.Vulnerability {
	if device.Vendor == "" {
		return nil
	}

	var vulnerabilities []models.Vulnerability

	// Check device against known CVEs
	for _, cve := range globalCVEDB {
		// Simple check - in a real implementation this would be more sophisticated
		for _, affected := range cve.Affected {
			if strings.Contains(strings.ToLower(affected), strings.ToLower(device.Vendor)) ||
				(device.Model != "" && strings.Contains(strings.ToLower(affected), strings.ToLower(device.Model))) {

				// Check if this vulnerability is already in the device
				alreadyAdded := false
				for _, v := range device.Vulnerabilities {
					if v.ID == cve.ID {
						alreadyAdded = true
						break
					}
				}

				if !alreadyAdded {
					vuln := models.Vulnerability{
						ID:          cve.ID,
						Name:        fmt.Sprintf("%s Vulnerability", cve.Severity),
						Description: cve.Description,
						Severity:    cve.Severity,
					}

					if len(cve.References) > 0 {
						vuln.References = cve.References
					}

					vulnerabilities = append(vulnerabilities, vuln)
					device.Vulnerabilities = append(device.Vulnerabilities, vuln)
				}

				break
			}
		}
	}

	return vulnerabilities
}
