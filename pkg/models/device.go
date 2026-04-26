package models

import (
	"time"
)

// Device represents a discovered device on the network
type Device struct {
	IP                 string            // IP address of the device
	MAC                string            // MAC address of the device
	Hostname           string            // Hostname of the device
	Vendor             string            // Vendor/manufacturer of the device
	Model              string            // Model of the device
	FirmwareVersion    string            // Firmware version
	OpenPorts          map[int]string    // Map of open ports to services
	OperatingSystem    string            // Operating system
	Vulnerabilities    []Vulnerability   // List of vulnerabilities
	DefaultCredentials []Credential      // List of default credentials
	Banners            map[int]string    // Service banners by port
	LastSeen           time.Time         // Last time the device was seen
	Services           map[string]string // Running services
	Tags               []string          // Tags for the device
	MACAddress         string            // MAC address in alternate format (for compatibility)
}

// Vulnerability represents a security vulnerability in a device
type Vulnerability struct {
	ID          string   // Vulnerability ID (e.g., CVE)
	CVE         string   // CVE identifier
	Name        string   // Name of the vulnerability
	Title       string   // Title of the vulnerability (display friendly)
	Description string   // Description of the vulnerability
	Severity    string   // Severity level (Low, Medium, High, Critical)
	CVSS        float64  // CVSS score
	References  []string // References to more information
	Remediation string   // Remediation steps
	Exploitable bool     // Whether the vulnerability is exploitable
	ExploitRef  string   // Reference to exploit if available
}

// Credential represents a set of credentials for accessing a device
type Credential struct {
	Service  string // Service (e.g., SSH, Telnet, Web)
	Port     int    // Port number
	Username string // Username
	Password string // Password
	Valid    bool   // Whether the credentials are valid
}
