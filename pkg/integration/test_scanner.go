package integration

import (
	"math/rand"
	"time"

	"github.com/renm226/iot-scanner/pkg/config"
	"github.com/renm226/iot-scanner/pkg/models"
	"github.com/sirupsen/logrus"
)

// TestScanner provides simulated device scanning for testing purposes
type TestScanner struct {
	config  config.Config
	logger  *logrus.Logger
	devices []models.Device
}

// NewTestScanner creates a new test scanner with simulated devices
func NewTestScanner(cfg config.Config, logger *logrus.Logger) *TestScanner {
	return &TestScanner{
		config:  cfg,
		logger:  logger,
		devices: generateTestDevices(),
	}
}

// Scan simulates a network scan and returns a list of devices
func (s *TestScanner) Scan() error {
	// Simulate scan delay based on the number of test devices
	scanDuration := time.Duration(len(s.devices)/5) * time.Second
	if scanDuration < 2*time.Second {
		scanDuration = 2 * time.Second
	}

	s.logger.Infof("Starting test scan with %d simulated devices...", len(s.devices))

	// Simulate scanning delay
	time.Sleep(scanDuration)

	// Apply any filters from config
	var filteredDevices []models.Device
	for _, device := range s.devices {
		// Add any filtering logic based on config here
		filteredDevices = append(filteredDevices, device)
	}

	// Log results
	s.logger.Infof("Test scan completed. Found %d devices.", len(filteredDevices))

	// Save results to file if configured
	if s.config.OutputFile != "" {
		s.logger.Infof("Saving test scan results to %s", s.config.OutputFile)
		err := config.WriteResultsToFile(filteredDevices, s.config.OutputFile)
		if err != nil {
			s.logger.Errorf("Failed to save results: %v", err)
			return err
		}
	}

	// Export results in various formats if enabled
	if s.config.EnableExport {
		err := s.exportResults(filteredDevices)
		if err != nil {
			s.logger.Errorf("Failed to export results: %v", err)
			return err
		}
	}

	return nil
}

// Export results in various formats
func (s *TestScanner) exportResults(_ []models.Device) error {
	// Implementation would export in the format specified by config.OutputFormat
	s.logger.Infof("Exporting test scan results in %s format", s.config.OutputFormat)
	// The actual implementation would be handled by the common export functionality
	return nil
}

// generateTestDevices creates a varied set of simulated devices for testing
func generateTestDevices() []models.Device {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Create a slice of devices
	var devices []models.Device

	// Camera - IP camera
	camera := models.Device{
		IP:               "192.168.1.101",
		MAC:              "A4:B2:C3:D4:E5:F6",
		Hostname:         "HIKVISION-101",
		Vendor:           "Hikvision",
		Model:            "DS-2CD2042WD-I",
		FirmwareVersion:  "V5.4.5 build 170124",
		OpenPorts:        map[int]string{80: "HTTP", 443: "HTTPS", 554: "RTSP", 8000: "SDK"},
		OperatingSystem:  "Embedded Linux 3.10",
		Vulnerabilities:  []models.Vulnerability{
			{
				ID:          "CVE-2017-7921",
				CVE:         "CVE-2017-7921",
				Name:        "Authentication Bypass",
				Title:       "Hikvision IP Camera Authentication Bypass",
				Description: "Certain Hikvision IP cameras allow bypass of authentication via a backdoor, enabling unauthorized access to the device.",
				Severity:    "Critical",
				CVSS:        9.8,
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7921", "https://ipvm.com/reports/hik-exploit"},
				Remediation: "Update firmware to the latest version provided by Hikvision that addresses this vulnerability.",
				Exploitable: true,
			},
			{
				ID:          "CVE-2021-36260",
				CVE:         "CVE-2021-36260",
				Name:        "Command Injection",
				Title:       "Hikvision Command Injection Vulnerability",
				Description: "A command injection vulnerability in the web server of some Hikvision product that allows an attacker to gain unauthorized access.",
				Severity:    "Critical",
				CVSS:        9.8,
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-36260"},
				Remediation: "Update device firmware to the latest version that patches this vulnerability.",
				Exploitable: true,
			},
		},
		DefaultCredentials: []models.Credential{
			{
				Service:  "HTTP",
				Port:     80,
				Username: "admin",
				Password: "12345",
				Valid:    true,
			},
			{
				Service:  "RTSP",
				Port:     554,
				Username: "admin",
				Password: "12345",
				Valid:    true,
			},
		},
		Banners: map[int]string{
			80:  "Hikvision-Webs",
			443: "Hikvision-Webs",
			554: "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision-Webs",
		},
		Services: map[string]string{
			"HTTP": "Web Interface",
			"RTSP": "Video Stream",
			"SDK":  "Hikvision SDK Service",
		},
		Tags:     []string{"camera", "ip-camera", "video-surveillance", "hikvision"},
		LastSeen: time.Now(),
	}
	devices = append(devices, camera)

	// WiFi router device - Mikrotik router with realistic vulnerabilities
	router := models.Device{
		IP:                "192.168.1.1",
		MAC:               "E4:8D:8C:12:34:56",
		Hostname:          "MikroTik",
		Vendor:            "MikroTik",
		Model:             "RouterBOARD hAP ac3",
		FirmwareVersion:   "RouterOS 6.45.9",
		OpenPorts:         map[int]string{21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 8291: "Winbox", 8728: "API", 8729: "API-SSL"},
		OperatingSystem:   "RouterOS",
		Vulnerabilities:   []models.Vulnerability{
			{
				ID:          "CVE-2019-3924",
				CVE:         "CVE-2019-3924",
				Name:        "Directory Traversal",
				Title:       "MikroTik RouterOS Directory Traversal Vulnerability",
				Description: "MikroTik RouterOS suffers from a directory traversal vulnerability that could allow an attacker to access sensitive files.",
				Severity:    "High",
				CVSS:        7.5,
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-3924"},
				Remediation: "Update to RouterOS version 6.46 or later.",
				Exploitable: true,
			},
			{
				ID:          "CVE-2018-14847",
				CVE:         "CVE-2018-14847",
				Name:        "Unauthorized Access",
				Title:       "MikroTik RouterOS Winbox Authentication Bypass",
				Description: "MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files via a directory traversal vulnerability in the WinBox interface.",
				Severity:    "Critical",
				CVSS:        9.1,
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-14847", "https://blog.mikrotik.com/security/winbox-vulnerability.html"},
				Remediation: "Update to RouterOS version 6.43 or later which contains fixes for this vulnerability.",
				Exploitable: true,
			},
		},
		DefaultCredentials: []models.Credential{
			{
				Service:  "Winbox",
				Port:     8291,
				Username: "admin",
				Password: "",
				Valid:    true,
			},
		},
		Banners: map[int]string{
			22:   "SSH-2.0-RouterOS",
			80:   "Router HTTP Server",
			8291: "MikroTik Winbox Service",
		},
		Services: map[string]string{
			"HTTP":   "Web Interface",
			"HTTPS":  "Secure Web Interface",
			"SSH":    "Secure Shell Access",
			"Winbox": "Windows Admin Tool",
			"API":    "RouterOS API",
		},
		Tags:              []string{"router", "gateway", "wifi", "mikrotik", "routeros"},
		LastSeen:          time.Now(),
	}
	devices = append(devices, router)

	// Smart speaker with voice assistant - Amazon Echo with known issues
	speaker := models.Device{
		IP:                "192.168.1.150",
		MAC:               "48:D6:D5:AB:CD:EF",
		Hostname:          "Echo-Dot",
		Vendor:            "Amazon",
		Model:             "Echo Dot 3rd Gen",
		FirmwareVersion:   "v653764720",
		OpenPorts:         map[int]string{80: "HTTP", 443: "HTTPS", 4070: "Local Voice", 8888: "Management"},
		OperatingSystem:   "Fire OS 7.1",
		Vulnerabilities:   []models.Vulnerability{
			{
				ID:          "CVE-2020-24583",
				CVE:         "CVE-2020-24583",
				Name:        "MQTT Transport Information Disclosure",
				Title:       "Amazon Echo Information Disclosure Vulnerability",
				Description: "The MQTT transport in certain Amazon Echo devices may leak sensitive information during the pairing process.",
				Severity:    "Medium",
				CVSS:        5.3,
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-24583"},
				Remediation: "Ensure device is updated to the latest firmware version provided by Amazon.",
				Exploitable: true,
			},
			{
				ID:          "ALHACK-2019-003",
				CVE:         "",
				Name:        "Bluetooth Profile Security",
				Title:       "Amazon Echo Unprotected Bluetooth Interface",
				Description: "The device allows any Bluetooth connection without requiring authentication, allowing nearby attackers to connect and potentially stream audio.",
				Severity:    "Low",
				CVSS:        3.5,
				References:  []string{"https://www.amazon.com/gp/help/customer/display.html?nodeId=GVP69U5USQBPEA5V"},
				Remediation: "Enable voice PIN or disable Bluetooth when not in use.",
				Exploitable: false,
			},
		},
		DefaultCredentials: []models.Credential{},
		Banners: map[int]string{
			80:  "Amazon Echo HTTP Service",
			443: "Amazon Echo HTTPS Service", 
		},
		Services: map[string]string{
			"HTTP":        "Web Interface",
			"HTTPS":       "Secure Web Interface",
			"Local Voice": "Voice Processing Service",
			"Management":  "Device Management",
		},
		Tags:              []string{"voice-assistant", "smart-speaker", "amazon", "alexa", "echo"},
		LastSeen:          time.Now(),
	}
	devices = append(devices, speaker)

	// Smart home hub - Samsung SmartThings with known vulnerabilities
	smartHub := models.Device{
		IP:                "192.168.1.201",
		MAC:               "B0:D5:CC:FC:E7:5A",
		Hostname:          "SmartThings-Hub",
		Vendor:            "Samsung",
		Model:             "SmartThings Hub v3",
		FirmwareVersion:   "000.036.00017",
		OpenPorts:         map[int]string{23: "Telnet", 443: "HTTPS", 8080: "HTTP", 39500: "SSDP", 41230: "ZigBee"},
		OperatingSystem:   "Linux 4.4.62 armv7l",
		Vulnerabilities:   []models.Vulnerability{
			{
				ID:          "CVE-2018-3911",
				CVE:         "CVE-2018-3911",
				Name:        "Authorization Bypass",
				Title:       "SmartThings Hub Authorization Bypass",
				Description: "Samsung SmartThings Hub has an authorization bypass vulnerability that could allow attackers to execute unauthorized MQTT commands.",
				Severity:    "High",
				CVSS:        8.2,
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-3911", "https://www.kb.cert.org/vuls/id/150299"},
				Remediation: "Update to the latest hub firmware via the SmartThings app.",
				Exploitable: true,
			},
			{
				ID:          "CVE-2018-3926",
				CVE:         "CVE-2018-3926",
				Name:        "Command Injection",
				Title:       "SmartThings Hub Command Injection",
				Description: "Samsung SmartThings Hub is vulnerable to a command injection that could allow remote code execution with root privileges.",
				Severity:    "Critical",
				CVSS:        9.8,
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-3926"},
				Remediation: "Immediately update to firmware version 0.0.36.0 or later.",
				Exploitable: true,
			},
		},
		DefaultCredentials: []models.Credential{
			{
				Service:  "Telnet",
				Port:     23,
				Username: "root",
				Password: "sh.fm.root.uidhjdk",
				Valid:    true,
			},
		},
		Banners: map[int]string{
			23:   "\nLogin:",
			8080: "Linux SmartThings Hub",
			443:  "Samsung SmartThings Hub v3",
		},
		Services: map[string]string{
			"HTTP":   "Web Management",
			"HTTPS":  "Secure API",
			"Telnet": "Debug Console",
			"SSDP":   "UPnP Discovery",
			"ZigBee": "ZigBee Coordinator",
		},
		Tags:              []string{"smart-home", "hub", "zigbee", "zwave", "samsung", "smartthings"},
		LastSeen:          time.Now(),
	}
	devices = append(devices, smartHub)

	return devices
}
