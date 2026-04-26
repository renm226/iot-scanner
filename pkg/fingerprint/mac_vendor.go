package fingerprint

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// MacVendorDBURL is the URL to download the latest MAC vendor database
	MacVendorDBURL = "https://standards-oui.ieee.org/oui/oui.csv"
	
	// LocalDBPath is the path to store the MAC vendor database locally
	localDBFileName = "mac_vendors.csv"
)

// MacVendorDB represents a database of MAC address prefixes mapped to vendors
type MacVendorDB struct {
	vendors     map[string]string // MAC prefix -> vendor name
	lastUpdated time.Time
	mutex       sync.RWMutex
	dbPath      string
	logger      *logrus.Logger
}

// NewMacVendorDB creates a new MAC vendor database
func NewMacVendorDB(dataDir string, logger *logrus.Logger) (*MacVendorDB, error) {
	if logger == nil {
		logger = logrus.New()
	}
	
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}
	
	dbPath := filepath.Join(dataDir, localDBFileName)
	
	db := &MacVendorDB{
		vendors: make(map[string]string),
		dbPath:  dbPath,
		logger:  logger,
	}
	
	// Try to load existing database
	err := db.loadDatabase()
	if err != nil {
		logger.Warnf("Couldn't load MAC vendor database: %v. Will try to download it.", err)
		
		// If loading fails, try to download and build the database
		if err := db.updateDatabase(); err != nil {
			logger.Warnf("Failed to download MAC vendor database: %v", err)
			// Continue with an empty database rather than failing completely
		}
	}
	
	// Check if the database is older than 30 days
	if time.Since(db.lastUpdated) > 30*24*time.Hour {
		logger.Info("MAC vendor database is older than 30 days. Attempting to update...")
		
		// Update in background to avoid blocking startup
		go func() {
			if err := db.updateDatabase(); err != nil {
				logger.Warnf("Failed to update MAC vendor database: %v", err)
			} else {
				logger.Info("MAC vendor database updated successfully")
			}
		}()
	}
	
	return db, nil
}

// loadDatabase loads the MAC vendor database from disk
func (db *MacVendorDB) loadDatabase() error {
	file, err := os.Open(db.dbPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	db.lastUpdated = fileInfo.ModTime()
	db.vendors = make(map[string]string)
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		
		// Normalize MAC prefix
		prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
		vendor := strings.TrimSpace(parts[1])
		
		if prefix != "" && vendor != "" {
			db.vendors[prefix] = vendor
		}
	}
	
	db.logger.Infof("Loaded %d MAC vendor entries", len(db.vendors))
	return scanner.Err()
}

// updateDatabase downloads and updates the MAC vendor database
func (db *MacVendorDB) updateDatabase() error {
	db.logger.Info("Downloading MAC vendor database...")
	
	// Create temporary file
	tempFile, err := os.CreateTemp("", "mac_vendors_*.csv")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tempFilePath := tempFile.Name()
	defer os.Remove(tempFilePath)
	defer tempFile.Close()
	
	// Download database
	resp, err := http.Get(MacVendorDBURL)
	if err != nil {
		return fmt.Errorf("failed to download MAC vendor database: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download MAC vendor database: HTTP %d", resp.StatusCode)
	}
	
	// Process the CSV file
	reader := csv.NewReader(resp.Body)
	vendors := make(map[string]string)
	
	// Skip header row
	if _, err := reader.Read(); err != nil {
		return fmt.Errorf("failed to read CSV header: %v", err)
	}
	
	// Process rows
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			db.logger.Warnf("Error reading CSV line: %v", err)
			continue
		}
		
		// IEEE OUI.csv format: 
		// MA-L,Assignment,Organization Name,Organization Address
		if len(record) < 3 {
			continue
		}
		
		// Extract the MAC prefix and vendor name
		// Format is usually like "EC-F4-51" or "94-E2-FD"
		prefix := strings.ReplaceAll(record[0], "-", "")
		prefix = strings.TrimSpace(prefix)
		vendorName := strings.TrimSpace(record[2])
		
		if prefix != "" && vendorName != "" {
			vendors[prefix] = vendorName
			
			// Write processed record to temp file
			fmt.Fprintf(tempFile, "%s,%s\n", prefix, vendorName)
		}
	}
	
	// Close temp file before moving it
	tempFile.Close()
	
	// Replace the old database with the new one
	if err := os.Rename(tempFilePath, db.dbPath); err != nil {
		return fmt.Errorf("failed to replace database file: %v", err)
	}
	
	// Update in-memory database
	db.mutex.Lock()
	db.vendors = vendors
	db.lastUpdated = time.Now()
	count := len(vendors)
	db.mutex.Unlock()
	
	db.logger.Infof("Updated MAC vendor database with %d entries", count)
	return nil
}

// LookupVendor looks up a vendor by MAC address
func (db *MacVendorDB) LookupVendor(macAddress string) string {
	// Normalize MAC address: remove separators and convert to uppercase
	macAddress = strings.ReplaceAll(macAddress, ":", "")
	macAddress = strings.ReplaceAll(macAddress, "-", "")
	macAddress = strings.ReplaceAll(macAddress, ".", "")
	macAddress = strings.ToUpper(macAddress)
	
	if len(macAddress) < 6 {
		return ""
	}
	
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	// Try different prefix lengths, from most specific to least
	for i := len(macAddress); i >= 6; i -= 2 {
		prefix := macAddress[:i]
		if vendor, exists := db.vendors[prefix]; exists {
			return vendor
		}
	}
	
	return ""
}

// UpdateIfNeeded checks if the database needs updating and updates it if necessary
func (db *MacVendorDB) UpdateIfNeeded(force bool) error {
	db.mutex.RLock()
	needsUpdate := force || time.Since(db.lastUpdated) > 30*24*time.Hour
	db.mutex.RUnlock()
	
	if needsUpdate {
		return db.updateDatabase()
	}
	
	return nil
}

// GetLastUpdated returns the time the database was last updated
func (db *MacVendorDB) GetLastUpdated() time.Time {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return db.lastUpdated
}

// Count returns the number of entries in the MAC vendor database
func (db *MacVendorDB) Count() int {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return len(db.vendors)
}
