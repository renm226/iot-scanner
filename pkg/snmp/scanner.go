package snmp

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"iot-scanner/pkg/models"

	"github.com/sirupsen/logrus"
)

// Common SNMP OIDs
const (
	OIDSysDescr      = "1.3.6.1.2.1.1.1.0"
	OIDSysObjectID   = "1.3.6.1.2.1.1.2.0"
	OIDSysUpTime     = "1.3.6.1.2.1.1.3.0"
	OIDSysContact    = "1.3.6.1.2.1.1.4.0"
	OIDSysName       = "1.3.6.1.2.1.1.5.0"
	OIDSysLocation   = "1.3.6.1.2.1.1.6.0"
	OIDSysServices   = "1.3.6.1.2.1.1.7.0"
	OIDIfNumber      = "1.3.6.1.2.1.2.1.0"
	OIDIfTable       = "1.3.6.1.2.1.2.2.1"
	OIDIfPhysAddress = "1.3.6.1.2.1.2.2.1.6"
)

// SNMPVersion defines the SNMP protocol version
type SNMPVersion int

// SNMP versions
const (
	SNMPv1  SNMPVersion = 0
	SNMPv2c SNMPVersion = 1
	SNMPv3  SNMPVersion = 3
)

// SNMPCredential defines authentication for SNMP
type SNMPCredential struct {
	Version   SNMPVersion
	Community string // For v1/v2c
	Username  string // For v3
	AuthPass  string // For v3
	PrivPass  string // For v3
	AuthProto string // For v3 (MD5, SHA)
	PrivProto string // For v3 (DES, AES)
}

// SNMPResult represents the result of an SNMP scan
type SNMPResult struct {
	IP         string
	Port       int
	Version    SNMPVersion
	SysInfo    map[string]string   // System information
	Interfaces []map[string]string // Network interfaces
	Services   []map[string]string // Running services
	OtherInfo  map[string]string   // Other collected information
}

// SNMPScanner performs SNMP scanning
type SNMPScanner struct {
	timeout     time.Duration
	retries     int
	credentials []SNMPCredential
	logger      *logrus.Logger
}

// NewSNMPScanner creates a new SNMP scanner
func NewSNMPScanner(timeout time.Duration, retries int, logger *logrus.Logger) *SNMPScanner {
	if logger == nil {
		logger = logrus.New()
	}

	// Default credentials (commonly used community strings)
	defaultCreds := []SNMPCredential{
		{Version: SNMPv2c, Community: "public"},
		{Version: SNMPv1, Community: "public"},
		{Version: SNMPv2c, Community: "private"},
		{Version: SNMPv1, Community: "private"},
		{Version: SNMPv2c, Community: "community"},
		{Version: SNMPv2c, Community: "snmp"},
		{Version: SNMPv2c, Community: "cisco"},
		{Version: SNMPv2c, Community: "admin"},
	}

	return &SNMPScanner{
		timeout:     timeout,
		retries:     retries,
		credentials: defaultCreds,
		logger:      logger,
	}
}

// AddCredential adds a new credential to the scanner
func (s *SNMPScanner) AddCredential(cred SNMPCredential) {
	s.credentials = append(s.credentials, cred)
}

// ScanDevice performs an SNMP scan on a device
func (s *SNMPScanner) ScanDevice(device *models.Device) (*SNMPResult, error) {
	// Check if SNMP ports are open
	snmpPort := 0
	for port := range device.OpenPorts {
		if port == 161 || port == 162 {
			snmpPort = port
			break
		}
	}

	if snmpPort == 0 {
		return nil, fmt.Errorf("no SNMP ports (161, 162) open on device %s", device.IP)
	}

	// Try each credential
	for _, cred := range s.credentials {
		result, err := s.trySNMP(device.IP, snmpPort, cred)
		if err == nil {
			s.logger.Infof("SNMP scan successful on %s using %v", device.IP, describeCred(cred))
			return result, nil
		}
	}

	return nil, fmt.Errorf("SNMP scan failed on %s: no valid credentials", device.IP)
}

// ScanNetwork performs SNMP scanning on multiple devices
func (s *SNMPScanner) ScanNetwork(devices []models.Device) map[string]*SNMPResult {
	results := make(map[string]*SNMPResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := range devices {
		wg.Add(1)
		go func(device *models.Device) {
			defer wg.Done()

			result, err := s.ScanDevice(device)
			if err != nil {
				if s.logger.Level >= logrus.DebugLevel {
					s.logger.Debugf("SNMP scan failed for %s: %v", device.IP, err)
				}
				return
			}

			mu.Lock()
			results[device.IP] = result
			mu.Unlock()
		}(&devices[i])
	}

	wg.Wait()
	return results
}

// EnhanceDeviceInfo enhances device information using SNMP data
func (s *SNMPScanner) EnhanceDeviceInfo(device *models.Device, result *SNMPResult) {
	if result == nil {
		return
	}

	// Update device info from SNMP
	if sysName, ok := result.SysInfo["sysName"]; ok && sysName != "" {
		device.Hostname = sysName
	}

	if sysDescr, ok := result.SysInfo["sysDescr"]; ok && sysDescr != "" {
		// Try to extract vendor and model from sysDescr
		extractVendorModel(device, sysDescr)

		// Try to extract firmware version
		extractFirmwareVersion(device, sysDescr)
	}

	// Add SNMP data to device services
	if device.Services == nil {
		device.Services = make(map[string]string)
	}
	device.Services["SNMP"] = fmt.Sprintf("SNMPv%d", result.Version)

	// Store full SNMP result in tags if available
	if device.Tags == nil {
		device.Tags = []string{"snmp-enabled"}
	} else {
		device.Tags = append(device.Tags, "snmp-enabled")
	}
}

// trySNMP attempts to scan a device with given credentials
// Note: In a real implementation, this would use a Go SNMP library
// This is a simplified version that simulates SNMP responses
func (s *SNMPScanner) trySNMP(ip string, port int, cred SNMPCredential) (*SNMPResult, error) {
	// Simulate SNMP communication - in a real implementation, use a proper SNMP library
	// This is just a placeholder to show how the function would work

	// In a real implementation, we would:
	// 1. Create an SNMP client
	// 2. Try to connect with the given credentials
	// 3. If successful, collect system information using GetBulk or Walk operations

	// For the purpose of this example, let's simulate a small percentage of successful connections
	// This is just for demonstration; in a real scanner this would be real SNMP communication
	if ip[len(ip)-1] != '1' && cred.Community == "public" {
		// Simulate a successful connection for some IPs with "public" community
		result := &SNMPResult{
			IP:      ip,
			Port:    port,
			Version: cred.Version,
			SysInfo: map[string]string{
				"sysDescr":    "Generic IoT Device v1.2.3",
				"sysName":     "IOT-" + ip[len(ip)-3:],
				"sysLocation": "Unknown",
				"sysContact":  "admin@example.com",
				"sysUpTime":   "12345678",
			},
			Interfaces: []map[string]string{
				{
					"ifIndex":       "1",
					"ifDescr":       "eth0",
					"ifType":        "ethernet-csmacd(6)",
					"ifPhysAddress": fmt.Sprintf("00:11:22:33:44:%s", ip[len(ip)-2:]),
					"ifSpeed":       "100000000",
				},
			},
			Services: []map[string]string{
				{
					"serviceName":   "HTTP",
					"servicePort":   "80",
					"serviceStatus": "running",
				},
			},
			OtherInfo: map[string]string{
				"deviceType": "IoT Device",
			},
		}

		// Sleep to simulate network latency
		time.Sleep(time.Duration(50+s.retries*20) * time.Millisecond)

		return result, nil
	}

	// Simulate failure for most cases
	time.Sleep(time.Duration(50+s.retries*10) * time.Millisecond)
	return nil, fmt.Errorf("authentication failed or timeout")
}

// Helper functions

// describeCred returns a string description of the credential
func describeCred(cred SNMPCredential) string {
	if cred.Version == SNMPv3 {
		return fmt.Sprintf("SNMPv3 user:%s", cred.Username)
	}
	return fmt.Sprintf("SNMPv%d community:%s", cred.Version+1, cred.Community)
}

// extractVendorModel tries to extract vendor and model from sysDescr
func extractVendorModel(device *models.Device, sysDescr string) {
	// This is a simplified implementation
	// In a real-world application, you would have a more comprehensive database
	// of patterns to match against sysDescr strings

	sysDescr = strings.ToLower(sysDescr)

	// Check for common vendors
	vendors := map[string]string{
		"cisco":     "Cisco",
		"juniper":   "Juniper",
		"huawei":    "Huawei",
		"tp-link":   "TP-Link",
		"d-link":    "D-Link",
		"netgear":   "NETGEAR",
		"hikvision": "Hikvision",
		"dahua":     "Dahua",
		"axis":      "Axis",
		"honeywell": "Honeywell",
		"bosch":     "Bosch",
		"samsung":   "Samsung",
		"sony":      "Sony",
		"panasonic": "Panasonic",
		"ubiquiti":  "Ubiquiti",
		"mikrotik":  "MikroTik",
		"aruba":     "Aruba",
		"fortinet":  "Fortinet",
		"sonicwall": "SonicWall",
		"palo alto": "Palo Alto",
	}

	// Try to identify vendor
	for vendorKey, vendorName := range vendors {
		if strings.Contains(sysDescr, vendorKey) && device.Vendor == "" {
			device.Vendor = vendorName
			break
		}
	}

	// Try to extract model number
	// This is a simplified approach; in reality, you'd need
	// vendor-specific patterns to extract model information
	if device.Model == "" {
		// Look for common model patterns like:
		// Model: XYZ123
		// Type: ABC456
		// Platform: DEF789
		modelPatterns := []string{
			"model",
			"type",
			"platform",
			"series",
		}

		for range modelPatterns {
			// In a real implementation, use regex to extract model information
			// For simplicity, just checking if the pattern prefix exists
			for _, part := range strings.Split(sysDescr, " ") {
				for _, prefix := range []string{"model:", "type:", "platform:", "series:"} {
					if strings.HasPrefix(part, prefix) {
						device.Model = strings.TrimPrefix(part, prefix)
						break
					}
				}
				if device.Model != "" {
					break
				}
			}
			if device.Model != "" {
				break
			}
		}
	}
}

// extractFirmwareVersion tries to extract firmware version from sysDescr
func extractFirmwareVersion(device *models.Device, sysDescr string) {
	if device.FirmwareVersion != "" {
		return
	}

	// In a real implementation, use regex patterns to find version numbers
	// This is a simplified version that just checks common prefixes

	// In a real implementation, use regex to extract version information
	// For simplicity, look for simple patterns
	for _, part := range strings.Split(sysDescr, " ") {
		// Check for version strings
		for _, prefix := range []string{"version:", "firmware:", "sw:", "ver:"} {
			if strings.HasPrefix(part, prefix) {
				ver := strings.TrimPrefix(part, prefix)
				if isVersionFormat(ver) {
					device.FirmwareVersion = ver
					return
				}
			}
		}

		// Check for pattern like v1.2.3
		if len(part) > 1 && part[0] == 'v' && isVersionFormat(part[1:]) {
			device.FirmwareVersion = part[1:]
			return
		}
	}
}

// isVersionFormat returns true if string appears to be a version number
func isVersionFormat(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}

	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}

	return true
}
