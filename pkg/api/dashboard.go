package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/renm226/iot-scanner/pkg/config"
	"github.com/renm226/iot-scanner/pkg/models"
	"github.com/sirupsen/logrus"
)

// DashboardServer represents a web dashboard for displaying scan results
type DashboardServer struct {
	config        config.Config
	router        *gin.Engine
	scanResults   []models.Device
	vulnerabilities map[string]models.Vulnerability
	scanHistory   []DashboardScanResult
	logger        *logrus.Logger
	mutex         sync.RWMutex
	assistant     *Assistant
}

// DashboardScanResult represents the result of a scan for dashboard display
type DashboardScanResult struct {
	Timestamp time.Time
	DeviceCount int
	VulnerabilityCount int
	CredentialCount int
	NetworkRange string
	IPAddresses []string
}

// NewDashboardServer creates a new dashboard server
func NewDashboardServer(cfg config.Config) *DashboardServer {
	// Create router
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Create dashboard server
	server := &DashboardServer{
		config:      cfg,
		router:      router,
		scanResults: []models.Device{},
		vulnerabilities: make(map[string]models.Vulnerability),
		scanHistory: []DashboardScanResult{},
		logger:      logrus.New(),
	}

	// Configure logger
	if cfg.Verbose {
		server.logger.SetLevel(logrus.DebugLevel)
	} else {
		server.logger.SetLevel(logrus.InfoLevel)
	}

	// Create assistant
	server.assistant = NewAssistant(server.logger)

	// Set up routes
	router.LoadHTMLGlob("web/templates/*")
	router.Static("/static", "web/static")

	// Dashboard routes
	router.GET("/", server.handleDashboard)
	router.GET("/devices", server.handleDeviceList)
	router.GET("/devices/:ip", server.handleDeviceDetail)
	router.GET("/vulnerabilities", server.handleVulnerabilities)
	router.GET("/api/scan-results", server.handleGetScanResults)
	router.GET("/api/scan-history", server.handleGetScanHistory)
	router.GET("/api/stats", server.handleGetStats)
	
	// Register assistant routes
	server.assistant.RegisterRoutes(router)

	return server
}

// Start starts the dashboard server
func (s *DashboardServer) Start() error {
	// Start server
	s.logger.Infof("Starting dashboard server on port %s", s.config.DashboardPort)
	return s.router.Run(":" + s.config.DashboardPort)
}

// AddScanResult adds scan results to the dashboard
func (s *DashboardServer) AddScanResult(devices []models.Device) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Update scan results
	s.scanResults = devices

	// Count vulnerabilities and credentials
	vulnCount := 0
	credCount := 0
	ipAddresses := make([]string, 0, len(devices))

	for _, device := range devices {
		vulnCount += len(device.Vulnerabilities)
		credCount += len(device.DefaultCredentials)
		ipAddresses = append(ipAddresses, device.IP)

		// Add vulnerabilities to map for quick lookup
		for _, vuln := range device.Vulnerabilities {
			if vuln.CVE != "" {
				s.vulnerabilities[vuln.CVE] = vuln
			}
		}
	}

	// Current timestamp for the scan
	currentTime := time.Now()
	timeStr := currentTime.Format(time.RFC3339)

	// Add scan history
	s.scanHistory = append(s.scanHistory, DashboardScanResult{
		Timestamp:         currentTime,
		DeviceCount:       len(devices),
		VulnerabilityCount: vulnCount,
		CredentialCount:   credCount,
		NetworkRange:      s.config.IPRange,
		IPAddresses:       ipAddresses,
	})

	// Update assistant with scan stats
	if s.assistant != nil {
		s.assistant.UpdateScanStats(len(devices), vulnCount, s.config.IPRange, timeStr)
	}

	s.logger.Infof("Added scan result with %d devices, %d vulnerabilities, %d credentials", 
		len(devices), vulnCount, credCount)
}

// Route handlers

func (s *DashboardServer) handleDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "IoT Device Security Scanner",
	})
}

func (s *DashboardServer) handleDeviceList(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	c.HTML(http.StatusOK, "devices.html", gin.H{
		"title":   "Devices",
		"devices": s.scanResults,
	})
}

func (s *DashboardServer) handleDeviceDetail(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Get device IP
	ip := c.Param("ip")

	// Find device
	var device models.Device
	found := false
	for _, d := range s.scanResults {
		if d.IP == ip {
			device = d
			found = true
			break
		}
	}

	if !found {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"title":   "Device Not Found",
			"message": fmt.Sprintf("Device with IP %s not found", ip),
		})
		return
	}

	c.HTML(http.StatusOK, "device_detail.html", gin.H{
		"title":  fmt.Sprintf("Device %s", ip),
		"device": device,
	})
}

func (s *DashboardServer) handleVulnerabilities(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	c.HTML(http.StatusOK, "vulnerabilities.html", gin.H{
		"title":          "Vulnerabilities",
		"vulnerabilities": s.vulnerabilities,
	})
}

// API handlers

func (s *DashboardServer) handleGetScanResults(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	c.JSON(http.StatusOK, s.scanResults)
}

func (s *DashboardServer) handleGetScanHistory(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	c.JSON(http.StatusOK, s.scanHistory)
}

func (s *DashboardServer) handleGetStats(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Count device types
	deviceTypes := make(map[string]int)
	for _, device := range s.scanResults {
		deviceType := "unknown"
		for _, tag := range device.Tags {
			if tag == "camera" || tag == "router" || tag == "wifi" || 
			   tag == "bluetooth" || tag == "smart_home" || tag == "voice_assistant" {
				deviceType = tag
				break
			}
		}
		deviceTypes[deviceType]++
	}

	// Count vulnerabilities by severity
	vulnSeverity := make(map[string]int)
	for _, vuln := range s.vulnerabilities {
		vulnSeverity[vuln.Severity]++
	}

	// Prepare statistics
	stats := gin.H{
		"deviceCount":       len(s.scanResults),
		"deviceTypes":       deviceTypes,
		"vulnerabilityCount": len(s.vulnerabilities),
		"vulnerabilitiesBySeverity": vulnSeverity,
	}

	c.JSON(http.StatusOK, stats)
}
