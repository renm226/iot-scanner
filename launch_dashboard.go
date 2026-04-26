package main

import (
	"github.com/fatih/color"
	"github.com/renm226/iot-scanner/pkg/api"
	"github.com/renm226/iot-scanner/pkg/models"
	"github.com/sirupsen/logrus"
)

func LaunchDashboard() {
	// Create a logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Print banner
	color.Cyan("\n=== IoT Device Security Scanner Dashboard ===\n")

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

	// Add simulated scan results
	color.Yellow("Loading sample device data...")
	devices := getSampleDevices()
	dashboard.AddScanResult(devices)

	// Start the dashboard
	color.Green("Web dashboard is running at: http://localhost:8080")
	color.Green("Press Ctrl+C to stop the server")
	
	// Start the dashboard server
	err := dashboard.Start()
	if err != nil {
		color.Red("Error starting dashboard: %v", err)
	}
}

// Generate sample devices for the dashboard
func getSampleDevices() []models.Device {
	return []models.Device{
		{
			IP:              "192.168.1.10",
			MAC:             "00:1A:2B:3C:4D:5E",
			Hostname:        "camera-livingroom",
			Vendor:          "Hikvision",
			Model:           "DS-2CD2142FWD-I",
			OperatingSystem: "Embedded Linux 4.2",
			FirmwareVersion: "5.6.2",
			OpenPorts: map[int]string{
				80:  "HTTP",
				443: "HTTPS",
				554: "RTSP",
			},
			Services: map[string]string{
				"HTTP":  "Hikvision Web Server",
				"HTTPS": "Hikvision Secure Server",
				"RTSP":  "Camera Stream",
			},
			Vulnerabilities: []models.Vulnerability{
				{
					ID:          "CVE-2021-36260",
					Name:        "Authentication Bypass",
					Description: "Command injection vulnerability in the web server",
					Severity:    "Critical",
					References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-36260"},
				},
			},
			Tags: []string{"camera", "iot", "vulnerable"},
		},
		{
			IP:              "192.168.1.15",
			MAC:             "A1:B2:C3:D4:E5:F6",
			Hostname:        "smart-thermostat",
			Vendor:          "Nest",
			Model:           "Learning Thermostat",
			OperatingSystem: "ThreadOS",
			FirmwareVersion: "7.3.1",
			OpenPorts: map[int]string{
				80:   "HTTP",
				443:  "HTTPS",
				1883: "MQTT",
			},
			Services: map[string]string{
				"HTTP":  "Configuration Interface",
				"HTTPS": "API Endpoint",
				"MQTT":  "Control Protocol",
			},
			Tags: []string{"thermostat", "iot", "secure"},
		},
		{
			IP:              "192.168.1.20",
			MAC:             "5F:4E:3D:2C:1B:0A",
			Hostname:        "smart-doorbell",
			Vendor:          "Ring",
			Model:           "Video Doorbell Pro",
			OperatingSystem: "Embedded Linux",
			FirmwareVersion: "2.3.14",
			OpenPorts: map[int]string{
				80:  "HTTP",
				443: "HTTPS",
				555: "Custom Video",
			},
			Services: map[string]string{
				"HTTP":         "Web Interface",
				"HTTPS":        "Secure API",
				"Custom Video": "Video Stream",
			},
			DefaultCredentials: []models.Credential{
				{
					Username: "admin",
					Password: "admin",
					Service:  "http",
				},
			},
			Vulnerabilities: []models.Vulnerability{
				{
					ID:          "CVE-2019-9483",
					Name:        "Information Disclosure",
					Description: "Device leaks WiFi credentials during setup",
					Severity:    "High",
					References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9483"},
				},
			},
			Tags: []string{"doorbell", "iot", "vulnerable"},
		},
		// Adding a few more devices for a more comprehensive dashboard view
		{
			IP:              "192.168.1.25",
			MAC:             "AA:BB:CC:DD:EE:FF",
			Hostname:        "smart-tv-livingroom",
			Vendor:          "Samsung",
			Model:           "Smart TV UHD",
			OperatingSystem: "Tizen OS 5.0",
			FirmwareVersion: "1.8.2",
			OpenPorts: map[int]string{
				80:  "HTTP",
				443: "HTTPS",
				8080: "HTTP Alternate",
			},
			Services: map[string]string{
				"HTTP":         "Web Interface",
				"HTTPS":        "API",
				"HTTP Alternate": "Media Streaming",
			},
			Tags: []string{"tv", "iot", "media"},
		},
		{
			IP:              "192.168.1.30",
			MAC:             "11:22:33:44:55:66",
			Hostname:        "smart-speaker",
			Vendor:          "Amazon",
			Model:           "Echo Dot",
			OperatingSystem: "FireOS",
			FirmwareVersion: "3.4.6",
			OpenPorts: map[int]string{
				80:   "HTTP",
				443:  "HTTPS",
				8009: "Cast Protocol",
			},
			Services: map[string]string{
				"HTTP":         "Web Interface",
				"HTTPS":        "API",
				"Cast Protocol": "Media Streaming",
			},
			Tags: []string{"speaker", "iot", "audio"},
		},
	}
}
