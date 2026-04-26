package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Message represents a chat message between user and assistant
type Message struct {
	ID        string    `json:"id"`
	Content   string    `json:"content"`
	Role      string    `json:"role"` // "user" or "assistant"
	Timestamp time.Time `json:"timestamp"`
}

// ChatRequest represents a request to the chat API
type ChatRequest struct {
	Message string `json:"message" binding:"required"`
}

// Assistant provides AI assistance for the IoT scanner
type Assistant struct {
	logger       *logrus.Logger
	messages     []Message
	scanResults  int
	vulnCount    int
	ipRange      string
	lastScanTime string
}

// NewAssistant creates a new assistant service
func NewAssistant(logger *logrus.Logger) *Assistant {
	if logger == nil {
		logger = logrus.New()
	}
	
	return &Assistant{
		logger:      logger,
		messages:    make([]Message, 0),
		scanResults: 0,
		vulnCount:   0,
	}
}

// RegisterRoutes sets up the assistant API routes
func (a *Assistant) RegisterRoutes(router *gin.Engine) {
	router.GET("/api/assistant/messages", a.getMessagesHandler)
	router.POST("/api/assistant/chat", a.chatHandler)
	router.GET("/assistant", a.assistantUIHandler)
	
	// Serve static assets for the assistant UI
	router.Static("/assistant/static", "./web/static/assistant")
	
	a.logger.Info("Registered assistant routes")
}

// UpdateScanStats updates the assistant with the latest scan statistics
func (a *Assistant) UpdateScanStats(deviceCount, vulnCount int, ipRange, scanTime string) {
	a.scanResults = deviceCount
	a.vulnCount = vulnCount
	a.ipRange = ipRange
	a.lastScanTime = scanTime
	a.logger.Infof("Updated assistant stats: %d devices, %d vulnerabilities", deviceCount, vulnCount)
}

// assistantUIHandler serves the assistant chat UI
func (a *Assistant) assistantUIHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "assistant.html", gin.H{
		"title": "IoT Scanner Assistant",
	})
}

// getMessagesHandler returns the message history
func (a *Assistant) getMessagesHandler(c *gin.Context) {
	c.JSON(http.StatusOK, a.messages)
}

// chatHandler processes a new chat message
func (a *Assistant) chatHandler(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Create user message
	userMsg := Message{
		ID:        time.Now().Format("20060102150405.000") + "-user",
		Content:   req.Message,
		Role:      "user",
		Timestamp: time.Now(),
	}
	
	// Add to message history
	a.messages = append(a.messages, userMsg)
	
	// Generate response
	response := a.generateResponse(req.Message)
	
	// Create assistant message
	assistantMsg := Message{
		ID:        time.Now().Format("20060102150405.000") + "-assistant",
		Content:   response,
		Role:      "assistant",
		Timestamp: time.Now(),
	}
	
	// Add to message history
	a.messages = append(a.messages, assistantMsg)
	
	// Return response
	c.JSON(http.StatusOK, gin.H{
		"assistantMessage": assistantMsg,
	})
}

// generateResponse creates an appropriate response to the user query
func (a *Assistant) generateResponse(query string) string {
	a.logger.WithField("query", query).Info("Processing assistant query")
	q := strings.ToLower(query)
	
	// Help/introduction
	if strings.Contains(q, "help") || strings.Contains(q, "hi") || strings.Contains(q, "hello") || 
	   strings.Contains(q, "what can you do") {
		return "Hello! I'm your IoT Scanner Assistant. I can help you understand your scan results, " +
			"explain vulnerabilities, and provide security recommendations. What would you like to know about your network?"
	}
	
	// Scan results
	if strings.Contains(q, "result") || strings.Contains(q, "scan") || strings.Contains(q, "found") {
		return a.getScanResultsResponse()
	}
	
	// Vulnerabilities
	if strings.Contains(q, "vulnerab") || strings.Contains(q, "risk") || strings.Contains(q, "issue") {
		return a.getVulnerabilityResponse()
	}
	
	// Security recommendations
	if strings.Contains(q, "recommend") || strings.Contains(q, "secure") || strings.Contains(q, "protect") {
		return a.getSecurityRecommendations()
	}
	
	// Cameras
	if strings.Contains(q, "camera") || strings.Contains(q, "hikvision") {
		return a.getCameraSecurityInfo()
	}
	
	// Routers
	if strings.Contains(q, "router") || strings.Contains(q, "mikrotik") || strings.Contains(q, "gateway") {
		return a.getRouterSecurityInfo()
	}
	
	// Smart speakers
	if strings.Contains(q, "speaker") || strings.Contains(q, "alexa") || strings.Contains(q, "echo") || 
	   strings.Contains(q, "google home") {
		return a.getSmartSpeakerInfo()
	}
	
	// Smart hubs
	if strings.Contains(q, "hub") || strings.Contains(q, "smartthings") || strings.Contains(q, "samsung") {
		return a.getSmartHubInfo()
	}
	
	// Catch-all response
	return "I'm here to help with IoT security. You can ask me about scan results, vulnerabilities found, " +
		   "specific device recommendations, or general security best practices. What would you like to know?"
}

// getScanResultsResponse provides information about the most recent scan
func (a *Assistant) getScanResultsResponse() string {
	if a.scanResults > 0 {
		return "In the most recent scan of " + a.ipRange + ", I found " + 
			   strconv.Itoa(a.scanResults) + " devices on your network. " +
			   "Of these, " + strconv.Itoa(a.vulnCount) + " have potential vulnerabilities. " +
			   "The scan was completed at " + a.lastScanTime + "."
	} else {
		return "No scan results are available yet. Would you like to start a network scan?"
	}
}

// getVulnerabilityResponse provides information about vulnerabilities found
func (a *Assistant) getVulnerabilityResponse() string {
	if a.vulnCount > 0 {
		return "I detected " + strconv.Itoa(a.vulnCount) + " potential vulnerabilities in your network. " +
			   "These include default credentials, outdated firmware, and insecure configurations. " +
			   "The most critical issues include:\n" +
			   "1. Hikvision camera with authentication bypass (CVE-2017-7921)\n" +
			   "2. MikroTik router directory traversal vulnerability (CVE-2019-3924)\n" +
			   "3. SmartThings Hub with multiple command injection vulnerabilities\n" +
			   "Would you like specific information about a particular vulnerability?"
	} else if a.scanResults > 0 {
		return "Good news! No vulnerabilities were detected in the last scan. " +
			   "However, it's always good practice to regularly update firmware and change default passwords."
	} else {
		return "No vulnerability data is available yet. Would you like to start a network scan?"
	}
}

// getSecurityRecommendations provides general IoT security recommendations
func (a *Assistant) getSecurityRecommendations() string {
	return "Here are my key recommendations for IoT security:\n" +
		   "1. Change default passwords on all devices\n" +
		   "2. Keep firmware updated regularly\n" +
		   "3. Segment IoT devices onto a separate network\n" +
		   "4. Disable unnecessary services and features\n" +
		   "5. Use strong encryption where available\n" +
		   "6. Monitor device behavior for anomalies\n" +
		   "7. Consider using a dedicated IoT security gateway\n\n" +
		   "Would you like specific recommendations for a particular device type?"
}

// getCameraSecurityInfo provides security information about cameras
func (a *Assistant) getCameraSecurityInfo() string {
	return "IP cameras are often vulnerable to security issues. In your network, I found Hikvision cameras with these issues:\n\n" +
		   "Critical Vulnerabilities:\n" +
		   "- Authentication Bypass (CVE-2017-7921): Allows attackers to access the camera without credentials\n" +
		   "- Command Injection (CVE-2021-36260): Allows remote code execution\n\n" +
		   "Other Issues:\n" +
		   "- Default credentials (admin/12345) are in use\n" +
		   "- Firmware version (V5.4.5) is outdated\n" +
		   "- Exposed RTSP stream on port 554\n\n" +
		   "Recommendations:\n" +
		   "1. Update firmware immediately from the manufacturer website\n" +
		   "2. Change default passwords to strong alternatives\n" +
		   "3. Restrict access to camera interfaces using firewall rules\n" +
		   "4. Consider placing cameras on an isolated network segment"
}

// getRouterSecurityInfo provides security information about routers
func (a *Assistant) getRouterSecurityInfo() string {
	return "Routers are critical security devices in your network. I found a MikroTik router with these issues:\n\n" +
		   "Vulnerabilities:\n" +
		   "- Directory Traversal (CVE-2019-3924): Allows attackers to access sensitive files\n" +
		   "- WinBox Authentication Bypass (CVE-2018-14847): Allows attackers to gain unauthorized access\n\n" +
		   "Other Issues:\n" +
		   "- Running outdated RouterOS version 6.45.9\n" +
		   "- Admin account has no password set\n" +
		   "- Unnecessary services (FTP, Telnet) are enabled\n\n" +
		   "Recommendations:\n" +
		   "1. Update to RouterOS version 6.46 or later immediately\n" +
		   "2. Set a strong password for the admin account\n" +
		   "3. Disable unused services (FTP, Telnet)\n" +
		   "4. Configure proper firewall rules\n" +
		   "5. Enable logging for security monitoring"
}

// getSmartSpeakerInfo provides security information about smart speakers
func (a *Assistant) getSmartSpeakerInfo() string {
	return "Smart speakers can introduce privacy and security concerns. I found an Amazon Echo device with these issues:\n\n" +
		   "Issues Detected:\n" +
		   "- Information disclosure vulnerability in MQTT transport\n" +
		   "- Unprotected Bluetooth interface allowing anyone to connect\n\n" +
		   "Recommendations:\n" +
		   "1. Keep firmware updated through the companion app\n" +
		   "2. Configure a voice PIN for sensitive actions like purchases\n" +
		   "3. Disable the microphone when not in use\n" +
		   "4. Review and delete voice recordings regularly\n" +
		   "5. Disable Bluetooth when not needed or use a PIN for pairing\n\n" +
		   "Privacy Considerations:\n" +
		   "- Be aware that voice data is processed in the cloud\n" +
		   "- Consider the location of your smart speaker (avoid sensitive areas)"
}

// getSmartHubInfo provides security information about smart home hubs
func (a *Assistant) getSmartHubInfo() string {
	return "Smart home hubs can be a central point of vulnerability. I found a Samsung SmartThings hub with these issues:\n\n" +
		   "Critical Vulnerabilities:\n" +
		   "- Authorization Bypass (CVE-2018-3911): Allows unauthorized MQTT commands\n" +
		   "- Command Injection (CVE-2018-3926): Allows remote code execution with root privileges\n\n" +
		   "Other Issues:\n" +
		   "- Telnet service enabled with default credentials\n" +
		   "- Running outdated firmware version\n\n" +
		   "Recommendations:\n" +
		   "1. Update firmware immediately to version 0.0.36.0 or later\n" +
		   "2. Disable Telnet service if not needed\n" +
		   "3. Create a separate network for your smart home devices\n" +
		   "4. Monitor for unusual activity or unauthorized device connections\n" +
		   "5. Regularly review and remove unused device authorizations"
}
