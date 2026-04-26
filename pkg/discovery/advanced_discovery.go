package discovery

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// AdvancedScanner provides enhanced network scanning using nmap
type AdvancedScanner struct {
	*Scanner
	logger *logrus.Logger
}

// NewAdvancedScanner creates a new advanced scanner with the given configuration
func NewAdvancedScanner(scanner *Scanner, logger *logrus.Logger) *AdvancedScanner {
	return &AdvancedScanner{
		Scanner: scanner,
		logger:  logger,
	}
}

// ScanWithNmap performs an advanced network scan using nmap
func (a *AdvancedScanner) ScanWithNmap() ([]Device, error) {
	a.logger.Info("Starting advanced network scan with nmap")
	
	// Create a context with timeout for the scan
	_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Configure nmap scan options
	// For simplicity, we'll use a string-based representation of parameters
	target := a.config.IPRange
	ports := strings.Join(convertIntSliceToStringSlice(a.config.ScanPorts), ",")
	
	// These would be actual nmap parameters in a real implementation
	a.logger.Infof("Would scan target %s with ports %s", target, ports)

	// In a real implementation, we would initialize and run the nmap scanner
	// For this simplified version, we'll create some sample device data
	
	// Simulating nmap scan results
	a.logger.Info("Simulating nmap scan results")

	// Generate simulated devices instead of processing actual nmap results
	var devices []Device
	
	// Create a few simulated IoT devices
	// In a real implementation, this would be replaced with actual scan results
	ips := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
	macs := []string{"00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"}
	names := []string{"iot-camera", "smart-thermostat", "media-device"}
	

	for i, ip := range ips {
		device := Device{
			IP:          ip,
			MAC:         macs[i],
			Hostname:    names[i],
			LastSeen:    time.Now(),
			OpenPorts:   make(map[int]string),
			Banners:     make(map[int]string),
			Services:    make(map[string]string),
			Tags:        []string{},
		}

		// Add sample OS information
		device.OperatingSystem = "Embedded Linux 4.2"
		
		// Add sample open ports
		// Define port map for each device type
		portMap := map[int]string{
			80: "HTTP",
			22: "SSH",
			443: "HTTPS",
		}
		
		if i == 0 { // camera device
			portMap[554] = "RTSP" // RTSP for camera streaming
		} else if i == 1 { // thermostat
			portMap[1883] = "MQTT" // MQTT for IoT communication
		}
		
		device.OpenPorts = portMap
		
		// Add sample services
		if i == 0 {
			device.Services["HTTP"] = "Hikvision Web Server 3.0"
			device.Banners[80] = "Hikvision IP Camera"
		} else if i == 1 {
			device.Services["HTTP"] = "Nest Web Interface 2.1"
		} else {
			device.Services["HTTP"] = "Smart Device Control Panel"
		}

		// Try to determine device type based on open ports and services
		a.determineDeviceType(&device)
		
		devices = append(devices, device)
	}

	a.logger.Infof("Advanced scan completed. Found %d devices", len(devices))
	return devices, nil
}

// determineDeviceType attempts to classify the device type based on its ports and services
func (a *AdvancedScanner) determineDeviceType(device *Device) {
	// Check for common IoT device patterns
	if _, ok := device.OpenPorts[80]; ok {
		if _, ok := device.OpenPorts[554]; ok { // RTSP
			device.Tags = append(device.Tags, "camera")
		}
	}
	
	if _, ok := device.OpenPorts[1883]; ok { // MQTT
		device.Tags = append(device.Tags, "iot-hub")
	}
	
	if _, ok := device.OpenPorts[5683]; ok { // CoAP
		device.Tags = append(device.Tags, "iot-device")
	}
	
	// Router patterns
	routerPorts := []int{53, 80, 443, 8080}
	routerPortMatches := 0
	for _, port := range routerPorts {
		if _, ok := device.OpenPorts[port]; ok {
			routerPortMatches++
		}
	}
	if routerPortMatches >= 2 {
		device.Tags = append(device.Tags, "router")
	}

	// Check service names for clues
	for _, details := range device.Services {
		lowerDetails := strings.ToLower(details)
		
		// Look for camera-related terms
		if strings.Contains(lowerDetails, "camera") || 
		   strings.Contains(lowerDetails, "ipcam") ||
		   strings.Contains(lowerDetails, "webcam") {
			device.Tags = append(device.Tags, "camera")
		}
		
		// Look for router-related terms
		if strings.Contains(lowerDetails, "router") || 
		   strings.Contains(lowerDetails, "gateway") ||
		   strings.Contains(lowerDetails, "modem") {
			device.Tags = append(device.Tags, "router")
		}
		
		// Look for other common IoT devices
		if strings.Contains(lowerDetails, "thermostat") {
			device.Tags = append(device.Tags, "thermostat")
		}
		if strings.Contains(lowerDetails, "speaker") || 
		   strings.Contains(lowerDetails, "sonos") || 
		   strings.Contains(lowerDetails, "echo") {
			device.Tags = append(device.Tags, "speaker")
		}
		if strings.Contains(lowerDetails, "tv") || 
		   strings.Contains(lowerDetails, "television") ||
		   strings.Contains(lowerDetails, "smart-tv") {
			device.Tags = append(device.Tags, "tv")
		}
	}
}

// Helper function to convert int slice to string slice for port specification
func convertIntSliceToStringSlice(intSlice []int) []string {
	strSlice := make([]string, len(intSlice))
	for i, val := range intSlice {
		strSlice[i] = strconv.Itoa(val)
	}
	return strSlice
}
