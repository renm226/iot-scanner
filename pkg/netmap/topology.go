package netmap

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/renm226/iot-scanner/pkg/models"
	"github.com/sirupsen/logrus"
)

// NodeType represents the type of network node
type NodeType string

const (
	NodeTypeRouter     NodeType = "router"
	NodeTypeSwitch     NodeType = "switch"
	NodeTypeDevice     NodeType = "device"
	NodeTypeCamera     NodeType = "camera"
	NodeTypeGateway    NodeType = "gateway"
	NodeTypePrinter    NodeType = "printer"
	NodeTypeComputer   NodeType = "computer"
	NodeTypeMobileIoT  NodeType = "mobile_iot"
	NodeTypeAccessPoint NodeType = "access_point"
	NodeTypeUnknown    NodeType = "unknown"
)

// Node represents a network device in the topology
type Node struct {
	ID            string            `json:"id"`
	Type          NodeType          `json:"type"`
	IP            string            `json:"ip"`
	MAC           string            `json:"mac"`
	Name          string            `json:"name"`
	Vendor        string            `json:"vendor"`
	Model         string            `json:"model"`
	IsGateway     bool              `json:"is_gateway"`
	OpenPorts     []int             `json:"open_ports,omitempty"`
	Services      []string          `json:"services,omitempty"`
	Vulnerable    bool              `json:"vulnerable"`
	DefaultCreds  bool              `json:"default_creds"`
	LastSeen      time.Time         `json:"last_seen"`
	FirstSeen     time.Time         `json:"first_seen"`
	TrafficStats  map[string]uint64 `json:"traffic_stats,omitempty"`
	X             float64           `json:"x,omitempty"` // For visual layout
	Y             float64           `json:"y,omitempty"` // For visual layout
}

// Link represents a connection between two network nodes
type Link struct {
	Source    string          `json:"source"`
	Target    string          `json:"target"`
	Type      string          `json:"type"`
	LinkData  map[string]any  `json:"link_data,omitempty"`
	Protocols []string        `json:"protocols,omitempty"`
	Latency   int             `json:"latency,omitempty"` // in milliseconds
	Weight    int             `json:"weight,omitempty"`  // for traffic volume
}

// NetworkMap represents the network topology
type NetworkMap struct {
	Nodes    []Node           `json:"nodes"`
	Links    []Link           `json:"links"`
	Metadata map[string]any   `json:"metadata,omitempty"`
}

// TopologyMapper creates network topology maps
type TopologyMapper struct {
	logger          *logrus.Logger
	interfaceName   string
	networkMap      NetworkMap
	gatewayIP       string
	gatewayMAC      string
	localIP         string
	localMAC        string
	networkPrefix   string
	nodes           map[string]*Node // IP to Node map
	mu              sync.RWMutex
}

// NewTopologyMapper creates a new topology mapper
func NewTopologyMapper(interfaceName string, logger *logrus.Logger) *TopologyMapper {
	if logger == nil {
		logger = logrus.New()
	}
	
	return &TopologyMapper{
		logger:        logger,
		interfaceName: interfaceName,
		networkMap: NetworkMap{
			Nodes:    []Node{},
			Links:    []Link{},
			Metadata: map[string]any{},
		},
		nodes: make(map[string]*Node),
	}
}

// Initialize prepares the topology mapper
func (t *TopologyMapper) Initialize() error {
	// Detect local interface info
	iface, err := net.InterfaceByName(t.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", t.interfaceName, err)
	}
	
	t.localMAC = iface.HardwareAddr.String()
	
	// Get local IP
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get interface addresses: %v", err)
	}
	
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}
		
		t.localIP = ipNet.IP.String()
		mask, _ := ipNet.Mask.Size()
		t.networkPrefix = fmt.Sprintf("%s/%d", ipNet.IP.Mask(ipNet.Mask).String(), mask)
		break
	}
	
	if t.localIP == "" {
		return fmt.Errorf("no suitable IPv4 address found on interface %s", t.interfaceName)
	}
	
	// Detect gateway
	if err := t.detectGateway(); err != nil {
		t.logger.Warnf("Failed to detect gateway: %v", err)
	}
	
	t.logger.Infof("Topology mapper initialized: local IP %s, network %s", t.localIP, t.networkPrefix)
	return nil
}

// detectGateway tries to find the default gateway for the network
func (t *TopologyMapper) detectGateway() error {
	// Try to get gateway IP using a basic routing table check
	// This is a simplified implementation; in a real scenario you'd use platform-specific methods
	
	// For now, let's assume the gateway is the first IP in the network
	ip, _, err := net.ParseCIDR(t.networkPrefix)
	if err != nil {
		return err
	}
	
	// Increment to get the first usable IP (often the gateway)
	ip = incrementIP(ip)
	t.gatewayIP = ip.String()
	
	// In a real implementation, we would use ARP to resolve the gateway MAC address
	// For this simplified version, we'll use a placeholder MAC address
	// Simulating a successful ARP resolution
	t.gatewayMAC = "00:11:22:33:44:55" // Placeholder MAC address
	
	t.logger.Infof("Using placeholder gateway: %s (%s)", t.gatewayIP, t.gatewayMAC)
	
	return nil
}

// CreateFromDevices builds a network map from discovered devices
func (t *TopologyMapper) CreateFromDevices(devices []models.Device) *NetworkMap {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	// Reset the network map
	t.networkMap.Nodes = []Node{}
	t.networkMap.Links = []Link{}
	t.nodes = make(map[string]*Node)
	
	// Create current timestamp
	now := time.Now()
	
	// Add gateway node if available
	if t.gatewayIP != "" {
		gatewayNode := Node{
			ID:        t.gatewayIP,
			Type:      NodeTypeGateway,
			IP:        t.gatewayIP,
			MAC:       t.gatewayMAC,
			Name:      "Network Gateway",
			IsGateway: true,
			LastSeen:  now,
			FirstSeen: now,
		}
		t.networkMap.Nodes = append(t.networkMap.Nodes, gatewayNode)
		t.nodes[t.gatewayIP] = &gatewayNode
	}
	
	// Process all devices
	for _, device := range devices {
		// Skip devices without IP
		if device.IP == "" {
			continue
		}
		
		// Determine node type based on device info
		nodeType := determineNodeType(&device)
		
		// Create node
		node := Node{
			ID:          device.IP,
			Type:        nodeType,
			IP:          device.IP,
			MAC:         device.MAC,
			Name:        getDeviceName(&device),
			Vendor:      device.Vendor,
			Model:       device.Model,
			IsGateway:   device.IP == t.gatewayIP,
			LastSeen:    device.LastSeen,
			FirstSeen:   now,
			Vulnerable:  len(device.Vulnerabilities) > 0,
			DefaultCreds: len(device.DefaultCredentials) > 0,
		}
		
		// Add open ports
		for port := range device.OpenPorts {
			node.OpenPorts = append(node.OpenPorts, port)
		}
		
		// Add services
		for service := range device.Services {
			node.Services = append(node.Services, service)
		}
		
		// Add to map
		t.networkMap.Nodes = append(t.networkMap.Nodes, node)
		t.nodes[device.IP] = &node
		
		// Create a link to the gateway if it exists
		if t.gatewayIP != "" && device.IP != t.gatewayIP {
			link := Link{
				Source: t.gatewayIP,
				Target: device.IP,
				Type:   "network",
			}
			t.networkMap.Links = append(t.networkMap.Links, link)
		}
	}
	
	// Add metadata
	t.networkMap.Metadata["created_at"] = now.Format(time.RFC3339)
	t.networkMap.Metadata["network"] = t.networkPrefix
	t.networkMap.Metadata["device_count"] = len(t.networkMap.Nodes)
	
	// Apply layout algorithm for visualization
	t.applyForceDirectedLayout()
	
	return &t.networkMap
}

// UpdateWithTrafficData updates the network map with traffic data
func (t *TopologyMapper) UpdateWithTrafficData(trafficData map[string]map[string]uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	// Update nodes with traffic stats
	for sourceIP, destinations := range trafficData {
		sourceNode, exists := t.nodes[sourceIP]
		if !exists {
			continue
		}
		
		// Update traffic stats for the node
		if sourceNode.TrafficStats == nil {
			sourceNode.TrafficStats = make(map[string]uint64)
		}
		
		var totalTraffic uint64 = 0
		for _, bytes := range destinations {
			totalTraffic += bytes
		}
		sourceNode.TrafficStats["total_bytes"] = totalTraffic
		
		// Create or update links between nodes
		for destIP, bytes := range destinations {
			// Skip if destination is not in our node map
			if _, exists := t.nodes[destIP]; !exists {
				continue
			}
			
			// Look for existing link
			linkFound := false
			for i := range t.networkMap.Links {
				if (t.networkMap.Links[i].Source == sourceIP && t.networkMap.Links[i].Target == destIP) ||
				   (t.networkMap.Links[i].Source == destIP && t.networkMap.Links[i].Target == sourceIP) {
					// Update existing link
					linkFound = true
					t.networkMap.Links[i].Weight = int(bytes / 1024) // Convert bytes to KB for weight
					break
				}
			}
			
			// Create new link if not found
			if !linkFound {
				link := Link{
					Source: sourceIP,
					Target: destIP,
					Type:   "traffic",
					Weight: int(bytes / 1024),
				}
				t.networkMap.Links = append(t.networkMap.Links, link)
			}
		}
	}
}

// ExportJSON exports the network map as JSON
func (t *TopologyMapper) ExportJSON() ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	return json.MarshalIndent(t.networkMap, "", "  ")
}

// applyForceDirectedLayout applies a simple layout algorithm for visualization
func (t *TopologyMapper) applyForceDirectedLayout() {
	// This is a placeholder for a real force-directed layout algorithm
	// In a production system, you would implement a proper algorithm like 
	// Fruchterman-Reingold or D3's force layout
	
	// For now, just place nodes in a circle
	nodeCount := len(t.networkMap.Nodes)
	if nodeCount <= 1 {
		return
	}
	
	// Place gateway in the center if it exists
	radius := 300.0
	centerX := 500.0
	centerY := 500.0
	
	// Place gateway in the center
	if t.gatewayIP != "" {
		for i := range t.networkMap.Nodes {
			if t.networkMap.Nodes[i].IP == t.gatewayIP {
				t.networkMap.Nodes[i].X = centerX
				t.networkMap.Nodes[i].Y = centerY
				break
			}
		}
	}
	
	// Place other nodes in a circle around the center
	angle := 0.0
	angleStep := 2.0 * 3.14159 / float64(nodeCount-1) // Subtract 1 if we have a gateway
	if t.gatewayIP == "" {
		angleStep = 2.0 * 3.14159 / float64(nodeCount)
	}
	
	for i := range t.networkMap.Nodes {
		// Skip gateway
		if t.networkMap.Nodes[i].IP == t.gatewayIP {
			continue
		}
		
		// Calculate position
		t.networkMap.Nodes[i].X = centerX + radius*float64(float64(i)*0.8*angleStep)
		t.networkMap.Nodes[i].Y = centerY + radius*float64(float64(i)*0.8*angleStep)
		angle += angleStep
	}
}

// Helper functions

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) net.IP {
	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)
	for j := len(ipCopy) - 1; j >= 0; j-- {
		ipCopy[j]++
		if ipCopy[j] > 0 {
			break
		}
	}
	return ipCopy
}

// determineNodeType tries to determine the type of node based on device info
func determineNodeType(device *models.Device) NodeType {
	// Check for cameras
	if isCamera(device) {
		return NodeTypeCamera
	}
	
	// Check for routers/gateways
	if isRouterOrGateway(device) {
		return NodeTypeRouter
	}
	
	// Check for printers
	if isPrinter(device) {
		return NodeTypePrinter
	}
	
	// Check for access points
	if isAccessPoint(device) {
		return NodeTypeAccessPoint
	}
	
	// Default to device for IoT devices
	return NodeTypeDevice
}

// getDeviceName generates a user-friendly name for the device
func getDeviceName(device *models.Device) string {
	if device.Vendor != "" && device.Model != "" {
		return fmt.Sprintf("%s %s", device.Vendor, device.Model)
	}
	
	if device.Vendor != "" {
		return fmt.Sprintf("%s Device", device.Vendor)
	}
	
	if device.Hostname != "" {
		return device.Hostname
	}
	
	return fmt.Sprintf("Device (%s)", device.IP)
}

// isCamera checks if the device is likely a camera
func isCamera(device *models.Device) bool {
	// Check based on open ports
	if _, hasRTSP := device.OpenPorts[554]; hasRTSP {
		return true
	}
	
	// Check based on vendor/model
	cameraVendors := []string{"hikvision", "dahua", "axis", "foscam", "reolink", "wyze"}
	deviceVendor := strings.ToLower(device.Vendor)
	
	for _, vendor := range cameraVendors {
		if strings.Contains(deviceVendor, vendor) {
			return true
		}
	}
	
	// Check model name for camera-related terms
	deviceModel := strings.ToLower(device.Model)
	cameraTerms := []string{"camera", "cam", "ipcam", "webcam", "surveillance"}
	
	for _, term := range cameraTerms {
		if strings.Contains(deviceModel, term) {
			return true
		}
	}
	
	return false
}

// isRouterOrGateway checks if the device is likely a router or gateway
func isRouterOrGateway(device *models.Device) bool {
	// Check common router ports
	routerPorts := []int{53, 80, 443, 8080}
	routerPortMatches := 0
	
	for _, port := range routerPorts {
		if _, ok := device.OpenPorts[port]; ok {
			routerPortMatches++
		}
	}
	
	if routerPortMatches >= 3 {
		return true
	}
	
	// Check vendor/model
	routerVendors := []string{"tp-link", "netgear", "asus", "d-link", "linksys", "cisco", "huawei", "mikrotik"}
	deviceVendor := strings.ToLower(device.Vendor)
	
	for _, vendor := range routerVendors {
		if strings.Contains(deviceVendor, vendor) {
			return true
		}
	}
	
	// Check model
	deviceModel := strings.ToLower(device.Model)
	routerTerms := []string{"router", "gateway", "access point", "ap", "modem"}
	
	for _, term := range routerTerms {
		if strings.Contains(deviceModel, term) {
			return true
		}
	}
	
	return false
}

// isPrinter checks if the device is likely a printer
func isPrinter(device *models.Device) bool {
	// Check common printer ports
	printerPorts := []int{9100, 515, 631}
	
	for _, port := range printerPorts {
		if _, ok := device.OpenPorts[port]; ok {
			return true
		}
	}
	
	// Check vendor/model
	printerVendors := []string{"hp", "canon", "epson", "brother", "lexmark", "xerox", "kyocera"}
	deviceVendor := strings.ToLower(device.Vendor)
	
	for _, vendor := range printerVendors {
		if strings.Contains(deviceVendor, vendor) {
			return true
		}
	}
	
	return false
}

// isAccessPoint checks if the device is likely an access point
func isAccessPoint(device *models.Device) bool {
	// Check vendor/model
	apVendors := []string{"ubiquiti", "unifi", "aruba", "meraki", "ruckus", "engenius"}
	deviceVendor := strings.ToLower(device.Vendor)
	
	for _, vendor := range apVendors {
		if strings.Contains(deviceVendor, vendor) {
			return true
		}
	}
	
	// Check model
	deviceModel := strings.ToLower(device.Model)
	apTerms := []string{"access point", "ap", "wifi", "wireless"}
	
	for _, term := range apTerms {
		if strings.Contains(deviceModel, term) {
			return true
		}
	}
	
	return false
}
