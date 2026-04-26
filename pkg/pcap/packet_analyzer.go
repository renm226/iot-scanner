package pcap

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

// IoTProtocol represents a detected IoT protocol
type IoTProtocol string

// Known IoT protocols
const (
	ProtocolMQTT    IoTProtocol = "MQTT"
	ProtocolCoAP    IoTProtocol = "CoAP"
	ProtocolAMQP    IoTProtocol = "AMQP"
	ProtocolXMPP    IoTProtocol = "XMPP"
	ProtocolRTSP    IoTProtocol = "RTSP"
	ProtocolSSDPReq IoTProtocol = "SSDP-Request"
	ProtocolSSDPRes IoTProtocol = "SSDP-Response"
	ProtocolmDNS    IoTProtocol = "mDNS"
	ProtocolUnknown IoTProtocol = "Unknown"
)

// DeviceTraffic represents captured traffic data for a device
type DeviceTraffic struct {
	IP                string                   // Device IP address
	MAC               string                   // Device MAC address
	BytesSent         uint64                   // Total bytes sent
	BytesReceived     uint64                   // Total bytes received
	PacketsSent       uint64                   // Total packets sent
	PacketsReceived   uint64                   // Total packets received
	DetectedProtocols map[IoTProtocol]bool     // Detected IoT protocols
	Destinations      map[string]uint64        // Map of destination IPs to packet counts
	FirstSeen         time.Time                // First time the device was seen
	LastSeen          time.Time                // Last time the device was seen
	ServicePorts      map[uint16]uint64        // Map of service ports to packet counts
	PayloadSamples    map[IoTProtocol][]string // Protocol-specific payload samples
	mu                sync.Mutex               // Mutex for concurrent access
}

// PacketAnalyzer captures and analyzes network packets
type PacketAnalyzer struct {
	interfaceName string
	promiscuous   bool
	timeout       time.Duration
	snaplen       int32
	bpfFilter     string
	logger        *logrus.Logger
	handle        *pcap.Handle
	devices       map[string]*DeviceTraffic // Map of IP addresses to device traffic
	localIPs      map[string]bool
	mu            sync.Mutex
	running       bool
	stopChan      chan struct{}
}

// NewPacketAnalyzer creates a new packet analyzer
func NewPacketAnalyzer(interfaceName string, logger *logrus.Logger) *PacketAnalyzer {
	return &PacketAnalyzer{
		interfaceName: interfaceName,
		promiscuous:   true,
		timeout:       pcap.BlockForever,
		snaplen:       1600,
		bpfFilter:     "",
		logger:        logger,
		devices:       make(map[string]*DeviceTraffic),
		localIPs:      make(map[string]bool),
		stopChan:      make(chan struct{}),
	}
}

// Start begins packet capture and analysis
func (p *PacketAnalyzer) Start() error {
	// Detect local IP addresses to filter out local traffic
	p.detectLocalIPs()

	// Open the device for capturing
	handle, err := pcap.OpenLive(p.interfaceName, p.snaplen, p.promiscuous, p.timeout)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", p.interfaceName, err)
	}
	p.handle = handle

	// Set BPF filter if specified
	if p.bpfFilter != "" {
		if err := p.handle.SetBPFFilter(p.bpfFilter); err != nil {
			p.handle.Close()
			return fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	packetSource := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
	p.running = true

	go func() {
		for {
			select {
			case <-p.stopChan:
				return
			case packet := <-packetSource.Packets():
				p.processPacket(packet)
			}
		}
	}()

	p.logger.Info("Packet analyzer started on interface ", p.interfaceName)
	return nil
}

// Stop stops packet capture
func (p *PacketAnalyzer) Stop() {
	if !p.running {
		return
	}

	p.stopChan <- struct{}{}
	p.running = false
	
	if p.handle != nil {
		p.handle.Close()
		p.handle = nil
	}
	
	p.logger.Info("Packet analyzer stopped")
}

// GetDevices returns a copy of the current device traffic data
func (p *PacketAnalyzer) GetDevices() map[string]DeviceTraffic {
	result := make(map[string]DeviceTraffic)
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	for ip, device := range p.devices {
		device.mu.Lock()
		// Create a deep copy
		deviceCopy := DeviceTraffic{
			IP:                device.IP,
			MAC:               device.MAC,
			BytesSent:         device.BytesSent,
			BytesReceived:     device.BytesReceived,
			PacketsSent:       device.PacketsSent,
			PacketsReceived:   device.PacketsReceived,
			DetectedProtocols: make(map[IoTProtocol]bool),
			Destinations:      make(map[string]uint64),
			FirstSeen:         device.FirstSeen,
			LastSeen:          device.LastSeen,
			ServicePorts:      make(map[uint16]uint64),
			PayloadSamples:    make(map[IoTProtocol][]string),
		}
		
		for proto, val := range device.DetectedProtocols {
			deviceCopy.DetectedProtocols[proto] = val
		}
		
		for dst, count := range device.Destinations {
			deviceCopy.Destinations[dst] = count
		}
		
		for port, count := range device.ServicePorts {
			deviceCopy.ServicePorts[port] = count
		}
		
		for proto, samples := range device.PayloadSamples {
			samplesCopy := make([]string, len(samples))
			copy(samplesCopy, samples)
			deviceCopy.PayloadSamples[proto] = samplesCopy
		}
		
		device.mu.Unlock()
		result[ip] = deviceCopy
	}
	
	return result
}

// processPacket analyzes a single packet
func (p *PacketAnalyzer) processPacket(packet gopacket.Packet) {
	// Extract Ethernet layer
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	
	// Extract IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	
	// Extract IP addresses
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return
	}
	
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	
	// Skip packets from/to local IPs if they're not in our target range
	if p.isLocalIP(srcIP) && p.isLocalIP(dstIP) {
		return
	}
	
	// Extract MAC addresses
	ethernet, _ := ethernetLayer.(*layers.Ethernet)
	srcMAC := ethernet.SrcMAC.String()
	
	// Get or create device traffic data
	p.mu.Lock()
	srcDevice, exists := p.devices[srcIP]
	if !exists {
		srcDevice = &DeviceTraffic{
			IP:                srcIP,
			MAC:               srcMAC,
			DetectedProtocols: make(map[IoTProtocol]bool),
			Destinations:      make(map[string]uint64),
			FirstSeen:         time.Now(),
			ServicePorts:      make(map[uint16]uint64),
			PayloadSamples:    make(map[IoTProtocol][]string),
		}
		p.devices[srcIP] = srcDevice
	}
	p.mu.Unlock()
	
	// Update device data
	srcDevice.mu.Lock()
	srcDevice.LastSeen = time.Now()
	srcDevice.BytesSent += uint64(len(packet.Data()))
	srcDevice.PacketsSent++
	srcDevice.Destinations[dstIP]++
	
	// Update destination device if it exists
	p.mu.Lock()
	if dstDevice, exists := p.devices[dstIP]; exists {
		dstDevice.mu.Lock()
		dstDevice.LastSeen = time.Now()
		dstDevice.BytesReceived += uint64(len(packet.Data()))
		dstDevice.PacketsReceived++
		dstDevice.mu.Unlock()
	}
	p.mu.Unlock()
	
	// Extract TCP/UDP layer for port information
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	
	var srcPort, dstPort uint16
	
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		srcDevice.ServicePorts[srcPort]++
		
		// Detect protocols based on common ports
		p.detectProtocolFromPort(srcDevice, dstPort)
		
		// Try to detect protocol from payload
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			payload := applicationLayer.Payload()
			detectedProtocol := p.detectProtocolFromPayload(payload, dstPort)
			if detectedProtocol != ProtocolUnknown {
				srcDevice.DetectedProtocols[detectedProtocol] = true
				
				// Store a payload sample
				if len(payload) > 0 {
					sample := fmt.Sprintf("%x", payload[:min(len(payload), 100)])
					if samples, exists := srcDevice.PayloadSamples[detectedProtocol]; exists && len(samples) < 5 {
						srcDevice.PayloadSamples[detectedProtocol] = append(samples, sample)
					} else if !exists {
						srcDevice.PayloadSamples[detectedProtocol] = []string{sample}
					}
				}
			}
		}
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		srcDevice.ServicePorts[srcPort]++
		
		// Detect protocols based on common ports
		p.detectProtocolFromPort(srcDevice, dstPort)
		
		// Check for mDNS
		if dstPort == 5353 {
			srcDevice.DetectedProtocols[ProtocolmDNS] = true
		}
		
		// Check for SSDP
		if dstPort == 1900 {
			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				payload := string(applicationLayer.Payload())
				if p.isSSDPRequest(payload) {
					srcDevice.DetectedProtocols[ProtocolSSDPReq] = true
				} else if p.isSSDPResponse(payload) {
					srcDevice.DetectedProtocols[ProtocolSSDPRes] = true
				}
			}
		}
		
		// Check for CoAP
		if dstPort == 5683 {
			srcDevice.DetectedProtocols[ProtocolCoAP] = true
		}
	}
	
	srcDevice.mu.Unlock()
}

// detectProtocolFromPort identifies IoT protocols based on destination port
func (p *PacketAnalyzer) detectProtocolFromPort(device *DeviceTraffic, dstPort uint16) {
	switch dstPort {
	case 1883, 8883:
		device.DetectedProtocols[ProtocolMQTT] = true
	case 5683, 5684:
		device.DetectedProtocols[ProtocolCoAP] = true
	case 5672:
		device.DetectedProtocols[ProtocolAMQP] = true
	case 5222, 5223:
		device.DetectedProtocols[ProtocolXMPP] = true
	case 554:
		device.DetectedProtocols[ProtocolRTSP] = true
	}
}

// detectProtocolFromPayload tries to identify protocols from packet payload
func (p *PacketAnalyzer) detectProtocolFromPayload(payload []byte, dstPort uint16) IoTProtocol {
	if len(payload) < 4 {
		return ProtocolUnknown
	}
	
	// Simple pattern matching for common IoT protocols
	// This is a basic implementation - in a real system, you'd implement more robust protocol detection
	
	// MQTT
	if dstPort == 1883 || dstPort == 8883 {
		// Check for MQTT CONNECT packet
		if len(payload) > 0 && payload[0] == 0x10 {
			return ProtocolMQTT
		}
	}
	
	// RTSP
	if dstPort == 554 {
		if len(payload) > 10 {
			header := string(payload[:10])
			if strings.Contains(header, "RTSP/1.0") || 
			   strings.Contains(header, "DESCRIBE") || 
			   strings.Contains(header, "SETUP") ||
			   strings.Contains(header, "PLAY") {
				return ProtocolRTSP
			}
		}
	}
	
	// CoAP - simple check for CoAP version 1
	if dstPort == 5683 || dstPort == 5684 {
		if len(payload) > 0 && (payload[0]>>6) == 1 {
			return ProtocolCoAP
		}
	}
	
	return ProtocolUnknown
}

// isSSDPRequest checks if a payload is an SSDP discovery request
func (p *PacketAnalyzer) isSSDPRequest(payload string) bool {
	return strings.Contains(payload, "M-SEARCH") && strings.Contains(payload, "ssdp:discover")
}

// isSSDPResponse checks if a payload is an SSDP discovery response
func (p *PacketAnalyzer) isSSDPResponse(payload string) bool {
	return strings.Contains(payload, "HTTP/1.1 200 OK") && 
	       (strings.Contains(payload, "ST:") || strings.Contains(payload, "ST: "))
}

// detectLocalIPs finds local IP addresses to filter out local-only traffic
func (p *PacketAnalyzer) detectLocalIPs() {
	interfaces, err := net.Interfaces()
	if err != nil {
		p.logger.Warnf("Failed to get network interfaces: %v", err)
		return
	}
	
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			
			ipv4 := ipNet.IP.To4()
			if ipv4 != nil {
				p.localIPs[ipv4.String()] = true
			}
		}
	}
}

// isLocalIP checks if an IP address is local
func (p *PacketAnalyzer) isLocalIP(ip string) bool {
	return p.localIPs[ip]
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
