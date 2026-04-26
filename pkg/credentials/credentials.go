package credentials

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/renm226/iot-scanner/pkg/config"
	"github.com/renm226/iot-scanner/pkg/discovery"
)

// Checker checks for default credentials
type Checker struct {
	config        config.Config
	credentialSets []CredentialSet
}

// CredentialSet represents a set of default credentials for a device
type CredentialSet struct {
	Vendor      string   `json:"vendor"`
	Model       string   `json:"model"`
	Service     string   `json:"service"`
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Usernames   []string `json:"usernames"`
	Passwords   []string `json:"passwords"`
	LoginPath   string   `json:"login_path"`
	PostParams  string   `json:"post_params"`
	SuccessText string   `json:"success_text"`
	FailureText string   `json:"failure_text"`
}

// NewChecker creates a new credentials checker with the given configuration
func NewChecker(cfg config.Config) *Checker {
	checker := &Checker{
		config: cfg,
	}

	// Load credential database
	err := checker.loadCredentials()
	if err != nil && cfg.Verbose {
		fmt.Printf("Warning: Failed to load credentials database: %v\n", err)
	}

	return checker
}

// loadCredentials loads the credentials database from a file
func (c *Checker) loadCredentials() error {
	dbPath := c.config.DatabasePath + "/credentials.json"

	// Check if credentials database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Create default credentials if file doesn't exist
		c.createDefaultCredentials()
		return nil
	}

	// Read credentials database
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return err
	}

	// Parse credentials database
	return json.Unmarshal(data, &c.credentialSets)
}

// createDefaultCredentials creates a default credentials database
func (c *Checker) createDefaultCredentials() {
	c.credentialSets = []CredentialSet{
		{
			Vendor:    "Hikvision",
			Model:     "IP Camera",
			Service:   "Web",
			Port:      80,
			Protocol:  "HTTP",
			Usernames: []string{"admin"},
			Passwords: []string{"12345", "admin", "Admin12345"},
			LoginPath: "/login.asp",
			PostParams: "username={USERNAME}&password={PASSWORD}",
			SuccessText: "Welcome",
			FailureText: "Invalid username or password",
		},
		{
			Vendor:    "Dahua",
			Model:     "IP Camera",
			Service:   "Web",
			Port:      80,
			Protocol:  "HTTP",
			Usernames: []string{"admin"},
			Passwords: []string{"admin", "Admin123", ""},
			LoginPath: "/RPC2_Login",
			PostParams: "method=global.login&params={\"userName\":\"{USERNAME}\",\"password\":\"{PASSWORD}\",\"clientType\":\"Web\"}",
			SuccessText: "\"result\":true",
			FailureText: "\"result\":false",
		},
		{
			Vendor:    "TP-Link",
			Model:     "Router",
			Service:   "Web",
			Port:      80,
			Protocol:  "HTTP",
			Usernames: []string{"admin"},
			Passwords: []string{"admin", "password", "tp-link"},
			LoginPath: "/login.cgi",
			PostParams: "username={USERNAME}&password={PASSWORD}",
			SuccessText: "success",
			FailureText: "error",
		},
		{
			Vendor:    "D-Link",
			Model:     "Router",
			Service:   "Web",
			Port:      80,
			Protocol:  "HTTP",
			Usernames: []string{"admin"},
			Passwords: []string{"admin", "password", ""}, // Added comma here
			LoginPath: "/login.cgi",
			PostParams: "username={USERNAME}&password={PASSWORD}",
			SuccessText: "success",
			FailureText: "error",
		},
		{
			Vendor:    "Netgear",
			Model:     "Router",
			Service:   "Web",
			Port:      80,
			Protocol:  "HTTP",
			Usernames: []string{"admin"},
			Passwords: []string{"password", "admin", "netgear"},
			LoginPath: "/login.cgi",
			PostParams: "username={USERNAME}&password={PASSWORD}",
			SuccessText: "success",
			FailureText: "error",
		},
		{
			Vendor:    "",
			Model:     "",
			Service:   "Telnet",
			Port:      23,
			Protocol:  "Telnet",
			Usernames: []string{"admin", "root", "user"},
			Passwords: []string{"admin", "password", "123456", "root", ""},
		},
		{
			Vendor:    "",
			Model:     "",
			Service:   "SSH",
			Port:      22,
			Protocol:  "SSH",
			Usernames: []string{"admin", "root", "user"},
			Passwords: []string{"admin", "password", "123456", "root", ""},
		},
		{
			Vendor:    "",
			Model:     "",
			Service:   "FTP",
			Port:      21,
			Protocol:  "FTP",
			Usernames: []string{"admin", "root", "user", "anonymous"},
			Passwords: []string{"admin", "password", "123456", "root", ""},
		},
	}

	// Create data directories if they don't exist
	os.MkdirAll(c.config.DatabasePath, 0755)

	// Save default credentials to file
	data, err := json.MarshalIndent(c.credentialSets, "", "  ")
	if err == nil {
		os.WriteFile(c.config.DatabasePath+"/credentials.json", data, 0644)
	}
}

// CheckDevice checks if a device uses default credentials
func (c *Checker) CheckDevice(device *discovery.Device) ([]discovery.Credential, error) {
	var validCredentials []discovery.Credential

	// Get credential sets applicable to this device
	var applicableSets []CredentialSet
	for _, credSet := range c.credentialSets {
		// Check if vendor and model match (if specified in the credential set)
		if credSet.Vendor != "" && credSet.Vendor != device.Vendor {
			continue
		}
		if credSet.Model != "" && credSet.Model != device.Model {
			continue
		}

		// Check if port is open
		if _, ok := device.OpenPorts[credSet.Port]; !ok {
			continue
		}

		applicableSets = append(applicableSets, credSet)
	}

	// Check each applicable credential set
	for _, credSet := range applicableSets {
		switch credSet.Protocol {
		case "HTTP":
			httpCreds := c.checkHTTPCredentials(device, credSet)
			validCredentials = append(validCredentials, httpCreds...)
		case "Telnet":
			telnetCreds := c.checkTelnetCredentials(device, credSet)
			validCredentials = append(validCredentials, telnetCreds...)
		case "SSH":
			// SSH credential checking would require an SSH library
			// For simplicity, we'll skip this in our example
		case "FTP":
			ftpCreds := c.checkFTPCredentials(device, credSet)
			validCredentials = append(validCredentials, ftpCreds...)
		}
	}

	return validCredentials, nil
}

// checkHTTPCredentials checks HTTP/HTTPS credentials
func (c *Checker) checkHTTPCredentials(device *discovery.Device, credSet CredentialSet) []discovery.Credential {
	var validCredentials []discovery.Credential

	// Protocol is determined in tryHTTPCredentials based on port number

	for _, username := range credSet.Usernames {
		for _, password := range credSet.Passwords {
			// Test credentials - use the protocol variable in the description
			if c.tryHTTPCredentials(device.IP, credSet, username, password) {
				cred := discovery.Credential{
					Service:  credSet.Service,
					Port:     credSet.Port,
					Username: username,
					Password: password,
					Valid:    true,
				}
				validCredentials = append(validCredentials, cred)
				
				if c.config.Verbose {
					fmt.Printf("Found valid credentials for %s:%d (%s): %s/%s\n", 
						device.IP, credSet.Port, credSet.Service, username, password)
				}
			}
		}
	}

	return validCredentials
}

// tryHTTPCredentials attempts to authenticate with HTTP credentials
func (c *Checker) tryHTTPCredentials(ip string, credSet CredentialSet, username, password string) bool {
	protocol := "http"
	if credSet.Port == 443 {
		protocol = "https"
	}

	// Create URL
	loginURL := fmt.Sprintf("%s://%s:%d%s", protocol, ip, credSet.Port, credSet.LoginPath)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: c.config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: nil, // In a real implementation, you'd want to handle TLS verification properly
		},
	}

	// Prepare request body
	postParams := strings.ReplaceAll(credSet.PostParams, "{USERNAME}", url.QueryEscape(username))
	postParams = strings.ReplaceAll(postParams, "{PASSWORD}", url.QueryEscape(password))
	body := strings.NewReader(postParams)

	// Create request
	req, err := http.NewRequest("POST", loginURL, body)
	if err != nil {
		return false
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Read response body
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return false
	}
	respBody := string(buf[:n])

	// Check for success
	if credSet.SuccessText != "" && strings.Contains(respBody, credSet.SuccessText) {
		return true
	}

	// Check for failure
	if credSet.FailureText != "" && strings.Contains(respBody, credSet.FailureText) {
		return false
	}

	// If we can't determine success or failure, check HTTP status
	return resp.StatusCode == 200
}

// checkTelnetCredentials checks Telnet credentials
func (c *Checker) checkTelnetCredentials(device *discovery.Device, credSet CredentialSet) []discovery.Credential {
	var validCredentials []discovery.Credential

	for _, username := range credSet.Usernames {
		for _, password := range credSet.Passwords {
			// Try Telnet credentials
			if c.tryTelnetCredentials(device.IP, username, password) {
				cred := discovery.Credential{
					Service:  "Telnet",
					Port:     23,
					Username: username,
					Password: password,
					Valid:    true,
				}
				validCredentials = append(validCredentials, cred)
				
				if c.config.Verbose {
					fmt.Printf("Found valid Telnet credentials for %s: %s/%s\n", 
						device.IP, username, password)
				}
			}
		}
	}

	return validCredentials
}

// tryTelnetCredentials attempts to authenticate with Telnet credentials
func (c *Checker) tryTelnetCredentials(_, _, _ string) bool {
	// This is a simplified implementation. In a real-world scenario,
	// you would implement a proper Telnet client.
	// For now, we'll just return false to avoid false positives.
	return false
}

// checkFTPCredentials checks FTP credentials
func (c *Checker) checkFTPCredentials(device *discovery.Device, credSet CredentialSet) []discovery.Credential {
	var validCredentials []discovery.Credential

	for _, username := range credSet.Usernames {
		for _, password := range credSet.Passwords {
			// Try FTP credentials
			if c.tryFTPCredentials(device.IP, username, password) {
				cred := discovery.Credential{
					Service:  "FTP",
					Port:     21,
					Username: username,
					Password: password,
					Valid:    true,
				}
				validCredentials = append(validCredentials, cred)
				
				if c.config.Verbose {
					fmt.Printf("Found valid FTP credentials for %s: %s/%s\n", 
						device.IP, username, password)
				}
			}
		}
	}

	return validCredentials
}

// tryFTPCredentials attempts to authenticate with FTP credentials
func (c *Checker) tryFTPCredentials(ip, username, password string) bool {
	// Create FTP connection
	conn, err := net.DialTimeout("tcp", ip+":21", c.config.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Read welcome message
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return false
	}

	// Send username
	_, err = conn.Write([]byte("USER " + username + "\r\n"))
	if err != nil {
		return false
	}

	// Read response
	_, err = conn.Read(buf)
	if err != nil {
		return false
	}

	// Send password
	_, err = conn.Write([]byte("PASS " + password + "\r\n"))
	if err != nil {
		return false
	}

	// Read response and check if login was successful
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	response := string(buf[:n])
	return strings.HasPrefix(response, "230 ") // 230 indicates successful login
}

// Duplicate method and all its fragments have been completely removed to fix compilation errors
