package api

import (
	"github.com/renm226/iot-scanner/pkg/models"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// ScanResult represents the results of a scan
type ScanResult struct {
	Timestamp time.Time           `json:"timestamp"`
	Devices   []models.Device  `json:"devices"`
	Stats     ScanStats           `json:"stats"`
}

// ScanStats contains statistics about a scan
type ScanStats struct {
	TotalDevices         int `json:"total_devices"`
	IdentifiedDevices    int `json:"identified_devices"`
	VulnerableDevices    int `json:"vulnerable_devices"`
	DefaultCredsDevices  int `json:"default_creds_devices"`
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	TotalDefaultCreds    int `json:"total_default_creds"`
}

// Dashboard represents the web dashboard server
type Dashboard struct {
	router       *gin.Engine
	logger       *logrus.Logger
	results      []ScanResult
	config       DashboardConfig
	deviceEvents chan models.Device
	mu           sync.RWMutex
}

// DashboardConfig contains configuration for the dashboard
type DashboardConfig struct {
	Port            string
	EnableCORS      bool
	ResultsHistory  int
	EnableRealTime  bool
	AllowExports    bool
	EnableRemediate bool
}

// NewDashboard creates a new dashboard server
func NewDashboard(config DashboardConfig, logger *logrus.Logger) *Dashboard {
	if logger == nil {
		logger = logrus.New()
	}

	// Set default values if not specified
	if config.Port == "" {
		config.Port = "8080"
	}
	if config.ResultsHistory <= 0 {
		config.ResultsHistory = 10
	}

	router := gin.Default()
	
	// Set release mode in production
	gin.SetMode(gin.ReleaseMode)

	d := &Dashboard{
		router:       router,
		logger:       logger,
		results:      make([]ScanResult, 0, config.ResultsHistory),
		config:       config,
		deviceEvents: make(chan models.Device, 100),
	}

	// Setup routes
	d.setupRoutes()

	return d
}

// setupRoutes configures the API routes
func (d *Dashboard) setupRoutes() {
	// Enable CORS if needed
	if d.config.EnableCORS {
		d.router.Use(func(c *gin.Context) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}

			c.Next()
		})
	}

	// Serve static files for the web UI
	d.router.Static("/static", "./web/static")
	d.router.LoadHTMLGlob("web/templates/*")

	// HTML routes
	d.router.GET("/", d.handleIndex)
	d.router.GET("/dashboard", d.handleDashboard)
	
	// API routes
	api := d.router.Group("/api")
	{
		api.GET("/devices", d.handleGetDevices)
		api.GET("/devices/:ip", d.handleGetDevice)
		api.GET("/vulnerabilities", d.handleGetVulnerabilities)
		api.GET("/stats", d.handleGetStats)
		api.GET("/history", d.handleGetHistory)
		
		// Scan control
		api.POST("/scan/start", d.handleStartScan)
		api.POST("/scan/stop", d.handleStopScan)
		api.GET("/scan/status", d.handleScanStatus)
		
		// Export
		if d.config.AllowExports {
			api.GET("/export/json", d.handleExportJSON)
			api.GET("/export/csv", d.handleExportCSV)
			api.GET("/export/report", d.handleExportReport)
		}
		
		// Remediation
		if d.config.EnableRemediate {
			api.POST("/remediate/:ip", d.handleRemediate)
		}
	}

	// WebSocket for real-time updates
	if d.config.EnableRealTime {
		d.router.GET("/ws", d.handleWebSocket)
	}
}

// Start starts the dashboard server
func (d *Dashboard) Start() error {
	return d.router.Run(":" + d.config.Port)
}

// AddScanResult adds a new scan result to the dashboard
func (d *Dashboard) AddScanResult(devices []models.Device) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Calculate stats
	stats := ScanStats{
		TotalDevices: len(devices),
	}

	for _, device := range devices {
		if device.Vendor != "" || device.Model != "" {
			stats.IdentifiedDevices++
		}
		
		if len(device.Vulnerabilities) > 0 {
			stats.VulnerableDevices++
			stats.TotalVulnerabilities += len(device.Vulnerabilities)
		}
		
		if len(device.DefaultCredentials) > 0 {
			stats.DefaultCredsDevices++
			stats.TotalDefaultCreds += len(device.DefaultCredentials)
		}
	}

	// Create result
	result := ScanResult{
		Timestamp: time.Now(),
		Devices:   devices,
		Stats:     stats,
	}

	// Add to results history
	d.results = append(d.results, result)
	
	// Trim history if needed
	if len(d.results) > d.config.ResultsHistory {
		d.results = d.results[len(d.results)-d.config.ResultsHistory:]
	}

	// Send devices to event channel for real-time updates
	if d.config.EnableRealTime {
		for _, device := range devices {
			select {
			case d.deviceEvents <- device:
				// Device sent to channel
			default:
				// Channel full, skip
			}
		}
	}
}

// HTML handlers

func (d *Dashboard) handleIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "IoT Security Scanner",
	})
}

func (d *Dashboard) handleDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "IoT Security Scanner Dashboard",
	})
}

// API handlers

func (d *Dashboard) handleGetDevices(c *gin.Context) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.results) == 0 {
		c.JSON(http.StatusOK, []models.Device{})
		return
	}

	latest := d.results[len(d.results)-1]
	c.JSON(http.StatusOK, latest.Devices)
}

func (d *Dashboard) handleGetDevice(c *gin.Context) {
	ip := c.Param("ip")
	
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.results) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No scan results available"})
		return
	}

	latest := d.results[len(d.results)-1]
	
	for _, device := range latest.Devices {
		if device.IP == ip {
			c.JSON(http.StatusOK, device)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
}

func (d *Dashboard) handleGetVulnerabilities(c *gin.Context) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.results) == 0 {
		c.JSON(http.StatusOK, []models.Vulnerability{})
		return
	}

	latest := d.results[len(d.results)-1]
	
	var allVulns []struct {
		DeviceIP string `json:"device_ip"`
		DeviceInfo string `json:"device_info"`
		models.Vulnerability
	}

	for _, device := range latest.Devices {
		deviceInfo := device.IP
		if device.Vendor != "" || device.Model != "" {
			deviceInfo = device.Vendor + " " + device.Model + " (" + device.IP + ")"
		}
		
		for _, vuln := range device.Vulnerabilities {
			allVulns = append(allVulns, struct {
				DeviceIP string `json:"device_ip"`
				DeviceInfo string `json:"device_info"`
				models.Vulnerability
			}{
				DeviceIP: device.IP,
				DeviceInfo: deviceInfo,
				Vulnerability: vuln,
			})
		}
	}

	c.JSON(http.StatusOK, allVulns)
}

func (d *Dashboard) handleGetStats(c *gin.Context) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.results) == 0 {
		c.JSON(http.StatusOK, ScanStats{})
		return
	}

	latest := d.results[len(d.results)-1]
	c.JSON(http.StatusOK, latest.Stats)
}

func (d *Dashboard) handleGetHistory(c *gin.Context) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	history := make([]struct {
		Timestamp time.Time `json:"timestamp"`
		Stats     ScanStats `json:"stats"`
	}, len(d.results))

	for i, result := range d.results {
		history[i].Timestamp = result.Timestamp
		history[i].Stats = result.Stats
	}

	c.JSON(http.StatusOK, history)
}

func (d *Dashboard) handleStartScan(c *gin.Context) {
	// This would trigger a new scan
	// Here we'd integrate with the scanner component
	c.JSON(http.StatusOK, gin.H{"status": "scan_started"})
}

func (d *Dashboard) handleStopScan(c *gin.Context) {
	// This would stop an ongoing scan
	c.JSON(http.StatusOK, gin.H{"status": "scan_stopped"})
}

func (d *Dashboard) handleScanStatus(c *gin.Context) {
	// Return current scan status
	c.JSON(http.StatusOK, gin.H{"status": "idle"})
}

func (d *Dashboard) handleExportJSON(c *gin.Context) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.results) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No scan results available"})
		return
	}

	latest := d.results[len(d.results)-1]
	
	// Set headers for file download
	c.Header("Content-Disposition", "attachment; filename=iot_scan_results.json")
	c.JSON(http.StatusOK, latest)
}

func (d *Dashboard) handleExportCSV(c *gin.Context) {
	// Implementation for CSV export would go here
	c.String(http.StatusOK, "CSV export not implemented yet")
}

func (d *Dashboard) handleExportReport(c *gin.Context) {
	// Implementation for PDF/HTML report export would go here
	c.String(http.StatusOK, "Report export not implemented yet")
}

func (d *Dashboard) handleRemediate(c *gin.Context) {
	ip := c.Param("ip")
	
	// Implementation for device remediation would go here
	// This could include changing passwords, applying patches, etc.
	
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"message": "Remediation tasks scheduled for " + ip,
	})
}

func (d *Dashboard) handleWebSocket(c *gin.Context) {
	// Implementation for WebSocket connection would go here
	// This would provide real-time updates to the dashboard
	c.String(http.StatusOK, "WebSocket not implemented yet")
}
