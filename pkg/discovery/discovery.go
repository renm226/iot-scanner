package discovery

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ExclusiveAccount/iot-scanner/pkg/config"
	"github.com/ExclusiveAccount/iot-scanner/pkg/models"
)

// Device is an alias for models.Device
type Device = models.Device

// Vulnerability is an alias for models.Vulnerability
type Vulnerability = models.Vulnerability

// Credential is an alias for models.Credential
type Credential = models.Credential

// Scanner performs network discovery
type Scanner struct {
	config config.Config
}

// NewScanner creates a new scanner with the given configuration
func NewScanner(cfg config.Config) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// Discover performs network discovery and returns a list of devices
func (s *Scanner) Discover() ([]Device, error) {
	// Parse IP range
	ipRange, err := parseIPRange(s.config.IPRange)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range: %v", err)
	}

	// Prepare concurrency control
	var wg sync.WaitGroup
	deviceChan := make(chan Device, len(ipRange))
	semaphore := make(chan struct{}, s.config.Threads)

	// Start a goroutine for each IP address
	for _, ip := range ipRange {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Check if the device is online
			if s.isDeviceOnline(ip) {
				device := Device{
					IP:          ip,
					LastSeen:    time.Now(),
					OpenPorts:   make(map[int]string),
					Banners:     make(map[int]string),
					Services:    make(map[string]string),
				}

				// Try to resolve MAC address
				mac, err := s.getMACAddress(ip)
				if err == nil {
					device.MAC = mac
				}

				// Try to resolve hostname
				hostname, err := net.LookupAddr(ip)
				if err == nil && len(hostname) > 0 {
					device.Hostname = hostname[0]
				}

				// Scan for open ports
				s.scanPorts(&device)

				deviceChan <- device
			}
		}(ip)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(deviceChan)

	// Collect results
	var devices []Device
	for device := range deviceChan {
		devices = append(devices, device)
	}

	return devices, nil
}

// isDeviceOnline checks if a device is online
func (s *Scanner) isDeviceOnline(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}

	// Create ICMP echo request
	conn, err := net.DialTimeout("ip4:icmp", ip, s.config.Timeout)
	if err != nil {
		// If ICMP fails, try TCP port scan as fallback
		for _, port := range []int{80, 443, 22, 23} {
			if s.isPortOpen(ip, port) {
				return true
			}
		}
		return false
	}
	defer conn.Close()

	return true
}

// scanPorts scans for open ports on a device
func (s *Scanner) scanPorts(device *Device) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, port := range s.config.ScanPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			if s.isPortOpen(device.IP, port) {
				service := getServiceName(port)
				banner := s.getBanner(device.IP, port)

				mu.Lock()
				device.OpenPorts[port] = service
				if banner != "" {
					device.Banners[port] = banner
				}
				mu.Unlock()

				if s.config.Verbose {
					log.Printf("Device %s has port %d (%s) open", device.IP, port, service)
				}
			}
		}(port)
	}

	wg.Wait()
}

// isPortOpen checks if a port is open
func (s *Scanner) isPortOpen(ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.config.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// getBanner attempts to get a service banner from an open port
func (s *Scanner) getBanner(ip string, port int) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.config.Timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Try to read banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}

// getMACAddress tries to get the MAC address of a device
func (s *Scanner) getMACAddress(ip string) (string, error) {
	// This is a simplified implementation. In a real-world scenario,
	// you would use ARP to resolve the MAC address.
	// For now, we'll just return an empty string with an error.
	return "", fmt.Errorf("MAC address resolution not implemented")
}

// parseIPRange parses a CIDR notation IP range into a list of IP addresses
func parseIPRange(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getServiceName returns the service name for a port
func getServiceName(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		554:  "RTSP",
		1883: "MQTT",
		5683: "CoAP",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
		8883: "MQTT-TLS",
		9000: "UPnP",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "Unknown"
}
