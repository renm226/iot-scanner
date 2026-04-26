package integration

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/renm226/iot-scanner/pkg/fingerprint"
	"github.com/renm226/iot-scanner/pkg/firmware"
	"github.com/renm226/iot-scanner/pkg/models"
	"github.com/renm226/iot-scanner/pkg/netmap"
	"github.com/renm226/iot-scanner/pkg/snmp"
	"github.com/sirupsen/logrus"
)

// EnhancedScannerConfig holds configuration for the enhanced scanner
type EnhancedScannerConfig struct {
	// General settings
	DataDir       string
	Concurrency   int
	ScanTimeout   time.Duration
	LogLevel      logrus.Level
	
	// Feature toggles
	EnableSNMP          bool
	EnableMacLookup     bool
	EnableTopologyMap   bool
	EnableFirmwareAnalysis bool
	EnablePacketAnalysis   bool
	
	// Scanner-specific settings
	SNMPRetries int
	SNMPTimeout time.Duration
}

// DefaultEnhancedScannerConfig returns default configuration
func DefaultEnhancedScannerConfig() EnhancedScannerConfig {
	return EnhancedScannerConfig{
		DataDir:             "./data",
		Concurrency:         10,
		ScanTimeout:         5 * time.Second,
		LogLevel:            logrus.InfoLevel,
		EnableSNMP:          true,
		EnableMacLookup:     true,
		EnableTopologyMap:   true,
		EnableFirmwareAnalysis: false, // Requires firmware files
		EnablePacketAnalysis:   false, // Requires packet capture privileges
		SNMPRetries:         2,
		SNMPTimeout:         3 * time.Second,
	}
}

// EnhancedScanner integrates multiple scanning and analysis modules
type EnhancedScanner struct {
	config         EnhancedScannerConfig
	logger         *logrus.Logger
	macVendorDB    *fingerprint.MacVendorDB
	snmpScanner    *snmp.SNMPScanner
	topologyMapper *netmap.TopologyMapper
	firmwareAnalyzer *firmware.FirmwareAnalyzer
	devices        []models.Device
	scanResults    *ScanResults
	mutex          sync.RWMutex
}

// ScanResults stores the integrated results from various scanners
type ScanResults struct {
	Devices       []models.Device
	SNMPResults   map[string]*snmp.SNMPResult
	NetworkMap    *netmap.NetworkMap
	FirmwareAnalysis map[string][]firmware.FindingResult
	LastScanTime  time.Time
}

// NewEnhancedScanner creates a new integrated scanner
func NewEnhancedScanner(config EnhancedScannerConfig) (*EnhancedScanner, error) {
	logger := logrus.New()
	logger.SetLevel(config.LogLevel)
	
	scanner := &EnhancedScanner{
		config:      config,
		logger:      logger,
		scanResults: &ScanResults{
			SNMPResults:      make(map[string]*snmp.SNMPResult),
			FirmwareAnalysis: make(map[string][]firmware.FindingResult),
		},
		mutex:       sync.RWMutex{},
	}
	
	// Initialize components based on configuration
	if config.EnableMacLookup {
		macDB, err := fingerprint.NewMacVendorDB(
			filepath.Join(config.DataDir, "fingerprint/data"),
			logger,
		)
		if err != nil {
			logger.Warnf("MAC vendor database initialization failed: %v", err)
			// Continue without MAC lookup if it fails
		} else {
			scanner.macVendorDB = macDB
		}
	}
	
	if config.EnableSNMP {
		scanner.snmpScanner = snmp.NewSNMPScanner(
			config.SNMPTimeout,
			config.SNMPRetries,
			logger,
		)
	}
	
	if config.EnableTopologyMap {
		scanner.topologyMapper = netmap.NewTopologyMapper("eth0", logger)
	}
	
	if config.EnableFirmwareAnalysis {
		scanner.firmwareAnalyzer = firmware.NewFirmwareAnalyzer(
			filepath.Join(config.DataDir, "firmware"),
			logger,
		)
	}
	
	return scanner, nil
}

// EnhanceDeviceInformation improves device details using all available modules
func (s *EnhancedScanner) EnhanceDeviceInformation(devices []models.Device) []models.Device {
	enhancedDevices := make([]models.Device, len(devices))
	copy(enhancedDevices, devices)
	
	// Use a WaitGroup to coordinate concurrent enhancements
	var wg sync.WaitGroup
	var deviceMutex sync.Mutex
	
	// Create a worker pool for concurrent processing
	semaphore := make(chan struct{}, s.config.Concurrency)
	
	for i := range enhancedDevices {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			// Acquire semaphore slot
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			device := &enhancedDevices[index]
			
			// 1. Enhance with MAC vendor lookup if possible
			if s.macVendorDB != nil && device.MACAddress != "" && device.Vendor == "" {
				vendor := s.macVendorDB.LookupVendor(device.MACAddress)
				if vendor != "" {
					deviceMutex.Lock()
					device.Vendor = vendor
					if device.Tags == nil {
						device.Tags = []string{"vendor-identified"}
					} else {
						device.Tags = append(device.Tags, "vendor-identified")
					}
					deviceMutex.Unlock()
				}
			}
			
			// 2. Perform SNMP scanning if enabled
			if s.snmpScanner != nil {
				result, err := s.snmpScanner.ScanDevice(device)
				if err == nil && result != nil {
					// Store result for later use
					deviceMutex.Lock()
					s.scanResults.SNMPResults[device.IP] = result
					s.snmpScanner.EnhanceDeviceInfo(device, result)
					deviceMutex.Unlock()
				}
			}
			
			// 3. Add any other enhancement steps here
			// ...
			
		}(i)
	}
	
	// Wait for all enhancements to complete
	wg.Wait()
	
	// Update the stored device list
	s.mutex.Lock()
	s.devices = enhancedDevices
	s.mutex.Unlock()
	
	return enhancedDevices
}

// PerformFullScan conducts a full scan with all enabled components
func (s *EnhancedScanner) PerformFullScan(devices []models.Device) *ScanResults {
	startTime := time.Now()
	s.logger.Info("Starting enhanced scan on", len(devices), "devices")
	
	// Clear previous results
	s.mutex.Lock()
	s.scanResults = &ScanResults{
		Devices:         make([]models.Device, 0),
		SNMPResults:     make(map[string]*snmp.SNMPResult),
		FirmwareAnalysis: make(map[string][]firmware.FindingResult),
		LastScanTime:    startTime,
	}
	s.mutex.Unlock()
	
	// 1. Enhance device information
	enhancedDevices := s.EnhanceDeviceInformation(devices)
	
	// 2. Create network topology if enabled
	if s.topologyMapper != nil {
		s.logger.Info("Generating network topology map")
		networkMap := s.topologyMapper.CreateFromDevices(enhancedDevices)
		
		s.mutex.Lock()
		s.scanResults.NetworkMap = networkMap
		s.mutex.Unlock()
	}
	
	// 3. Store the final results
	s.mutex.Lock()
	s.scanResults.Devices = enhancedDevices
	s.scanResults.LastScanTime = time.Now()
	result := s.scanResults // Create a copy to return
	s.mutex.Unlock()
	
	s.logger.Infof("Enhanced scan completed in %v", time.Since(startTime))
	return result
}

// GetLastScanResults returns the most recent scan results
func (s *EnhancedScanner) GetLastScanResults() *ScanResults {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	// Create a deep copy to avoid race conditions
	return &ScanResults{
		Devices:         s.scanResults.Devices,
		SNMPResults:     s.scanResults.SNMPResults,
		NetworkMap:      s.scanResults.NetworkMap,
		FirmwareAnalysis: s.scanResults.FirmwareAnalysis,
		LastScanTime:    s.scanResults.LastScanTime,
	}
}

// UpdateScannerConfig updates the scanner configuration
func (s *EnhancedScanner) UpdateScannerConfig(config EnhancedScannerConfig) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Update configuration
	s.config = config
	
	// Update logger level
	s.logger.SetLevel(config.LogLevel)
}

// GetScannerStatus returns current scanner status information
func (s *EnhancedScanner) GetScannerStatus() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	status := map[string]interface{}{
		"scannerVersion":       "1.2.0",
		"enabledModules":       []string{},
		"deviceCount":          len(s.devices),
		"lastScanTime":         s.scanResults.LastScanTime,
		"macVendorDbEntries":   0,
		"macVendorDbUpdated":   time.Time{},
		"snmpResultCount":      len(s.scanResults.SNMPResults),
		"firmwareAnalysisCount": len(s.scanResults.FirmwareAnalysis),
	}
	
	// Build list of enabled modules
	enabledModules := []string{"base"}
	if s.config.EnableMacLookup {
		enabledModules = append(enabledModules, "mac_lookup")
	}
	if s.config.EnableSNMP {
		enabledModules = append(enabledModules, "snmp")
	}
	if s.config.EnableTopologyMap {
		enabledModules = append(enabledModules, "topology")
	}
	if s.config.EnableFirmwareAnalysis {
		enabledModules = append(enabledModules, "firmware")
	}
	if s.config.EnablePacketAnalysis {
		enabledModules = append(enabledModules, "packet_analysis")
	}
	status["enabledModules"] = enabledModules
	
	// Add MAC vendor DB stats if available
	if s.macVendorDB != nil {
		status["macVendorDbEntries"] = s.macVendorDB.Count()
		status["macVendorDbUpdated"] = s.macVendorDB.GetLastUpdated()
	}
	
	return status
}

// Scan performs a complete scan process and is the main entrypoint for scanning
func (s *EnhancedScanner) Scan() error {
	s.logger.Info("Starting enhanced scan process")
	
	// This would normally use a real discovery module to find devices
	// For simplicity in our example, we'll create some test devices
	testDevices := generateTestDevices()
	
	// Enhance the discovered devices with additional information
	enhancedDevices := s.EnhanceDeviceInformation(testDevices)
	
	// Perform the full scan with all enabled modules
	s.PerformFullScan(enhancedDevices)
	
	s.logger.Info("Enhanced scan completed successfully")
	return nil
}
