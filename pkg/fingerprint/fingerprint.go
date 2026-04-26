package fingerprint

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/ExclusiveAccount/iot-scanner/pkg/config"
	"github.com/ExclusiveAccount/iot-scanner/pkg/models"
)

// Fingerprinter handles device fingerprinting
type Fingerprinter struct {
	config       config.Config
	fingerprints []FingerprintRule
}

// FingerprintRule defines a rule for fingerprinting a device
type FingerprintRule struct {
	Vendor      string            `json:"vendor"`
	Model       string            `json:"model"`
	PortMatches map[int]string    `json:"ports"` // Port -> Regex pattern
	Headers     map[string]string `json:"headers"`
	BannerRegex string            `json:"banner_regex"`
}

// NewFingerprinter creates a new fingerprinter with the given configuration
func NewFingerprinter(cfg config.Config) *Fingerprinter {
	fp := &Fingerprinter{
		config: cfg,
	}

	// Load fingerprint database
	err := fp.loadFingerprints()
	if err != nil && cfg.Verbose {
		fmt.Printf("Warning: Failed to load fingerprint database: %v\n", err)
	}

	return fp
}

// loadFingerprints loads the fingerprint database from a file
func (f *Fingerprinter) loadFingerprints() error {
	// Check if fingerprint database exists
	if _, err := os.Stat(f.config.FingerPrintDB); os.IsNotExist(err) {
		// Create default fingerprints if file doesn't exist
		f.createDefaultFingerprints()
		return nil
	}

	// Read fingerprint database
	data, err := os.ReadFile(f.config.FingerPrintDB)
	if err != nil {
		return err
	}

	// Parse fingerprint database
	return json.Unmarshal(data, &f.fingerprints)
}

// createDefaultFingerprints creates a default fingerprint database
func (f *Fingerprinter) createDefaultFingerprints() {
	f.fingerprints = []FingerprintRule{
		{
			Vendor: "Hikvision",
			Model:  "IP Camera",
			PortMatches: map[int]string{
				80:  "Hikvision",
				554: "RTSP",
			},
			Headers: map[string]string{
				"Server": "Hikvision.*",
			},
		},
		{
			Vendor: "Dahua",
			Model:  "IP Camera",
			PortMatches: map[int]string{
				80:  "Dahua|wificam",
				554: "RTSP",
			},
			Headers: map[string]string{
				"Server": "Dahua.*",
			},
		},
		{
			Vendor:      "TP-Link",
			Model:       "Router",
			BannerRegex: "TP-LINK|tplink",
			Headers: map[string]string{
				"Server": "TP-LINK.*",
			},
		},
		{
			Vendor:      "D-Link",
			Model:       "Router",
			BannerRegex: "D-Link|dlink",
			Headers: map[string]string{
				"Server": "D-Link.*",
			},
		},
		{
			Vendor:      "Netgear",
			Model:       "Router",
			BannerRegex: "NETGEAR|netgear",
			Headers: map[string]string{
				"Server": "NETGEAR.*",
			},
		},
		{
			Vendor:      "Philips Hue",
			Model:       "Bridge",
			BannerRegex: "hue",
			Headers: map[string]string{
				"Server": "Philips hue.*",
			},
		},
		{
			Vendor:      "Nest",
			Model:       "Thermostat",
			BannerRegex: "nest",
		},
		{
			Vendor:      "Amazon",
			Model:       "Echo",
			BannerRegex: "Amazon|Echo|Alexa",
		},
		{
			Vendor:      "Google",
			Model:       "Home",
			BannerRegex: "Google Home|Google Nest",
		},
		{
			Vendor:      "Sonos",
			Model:       "Speaker",
			BannerRegex: "Sonos",
		},
	}

	// Save default fingerprints to file
	data, err := json.MarshalIndent(f.fingerprints, "", "  ")
	if err == nil {
		// Create data directory if it doesn't exist
		os.MkdirAll("data", 0755)
		os.WriteFile(f.config.FingerPrintDB, data, 0644)
	}
}

// FingerprintDevice fingerprints a device based on open ports and banners
func (f *Fingerprinter) FingerprintDevice(device *models.Device) error {
	// First try HTTP fingerprinting if port 80 or 443 is open
	if _, ok := device.OpenPorts[80]; ok {
		err := f.httpFingerprint(device, 80)
		if err == nil && device.Vendor != "" {
			return nil
		}
	}

	if _, ok := device.OpenPorts[443]; ok {
		err := f.httpFingerprint(device, 443)
		if err == nil && device.Vendor != "" {
			return nil
		}
	}

	// Try banner-based fingerprinting
	f.bannerFingerprint(device)

	// Try port-based fingerprinting as a last resort
	if device.Vendor == "" {
		f.portFingerprint(device)
	}

	return nil
}

// httpFingerprint fingerprints a device using HTTP headers
func (f *Fingerprinter) httpFingerprint(device *models.Device, port int) error {
	protocol := "http"
	if port == 443 {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d", protocol, device.IP, port)
	client := &http.Client{
		Timeout: f.config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: nil, // In a real implementation, you'd want to handle TLS verification properly
		},
	}

	// Make HTTP request
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response headers against fingerprint rules
	for _, rule := range f.fingerprints {
		matches := 0
		needed := len(rule.Headers)
		
		if needed == 0 {
			continue
		}

		for headerName, pattern := range rule.Headers {
			headerValue := resp.Header.Get(headerName)
			if headerValue != "" {
				matched, _ := regexp.MatchString(pattern, headerValue)
				if matched {
					matches++
				}
			}
		}

		// If all headers match, we've found a match
		if matches == needed {
			device.Vendor = rule.Vendor
			device.Model = rule.Model
			
			// Try to extract firmware version from headers
			serverHeader := resp.Header.Get("Server")
			if serverHeader != "" {
				versionRegex := regexp.MustCompile(`[vV]?(\d+\.\d+(\.\d+)?)`)
				versionMatches := versionRegex.FindStringSubmatch(serverHeader)
				if len(versionMatches) > 1 {
					device.FirmwareVersion = versionMatches[1]
				}
			}
			
			return nil
		}
	}

	return fmt.Errorf("no fingerprint match found")
}

// bannerFingerprint fingerprints a device using service banners
func (f *Fingerprinter) bannerFingerprint(device *models.Device) {
	for _, rule := range f.fingerprints {
		if rule.BannerRegex == "" {
			continue
		}

		for _, banner := range device.Banners {
			matched, _ := regexp.MatchString(rule.BannerRegex, banner)
			if matched {
				device.Vendor = rule.Vendor
				device.Model = rule.Model

				// Try to extract firmware version from banner
				versionRegex := regexp.MustCompile(`[vV]?(\d+\.\d+(\.\d+)?)`)
				versionMatches := versionRegex.FindStringSubmatch(banner)
				if len(versionMatches) > 1 {
					device.FirmwareVersion = versionMatches[1]
				}

				return
			}
		}
	}
}

// portFingerprint fingerprints a device based on open ports
func (f *Fingerprinter) portFingerprint(device *models.Device) {
	for _, rule := range f.fingerprints {
		matches := 0
		needed := len(rule.PortMatches)
		
		if needed == 0 {
			continue
		}

		for port, pattern := range rule.PortMatches {
			if service, ok := device.OpenPorts[port]; ok {
				matched, _ := regexp.MatchString(pattern, service)
				if matched {
					matches++
				}
			}
		}

		// If all ports match, we've found a match
		if matches == needed {
			device.Vendor = rule.Vendor
			device.Model = rule.Model
			return
		}
	}
}
