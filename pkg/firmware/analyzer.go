package firmware

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// FirmwareAnalyzer handles firmware extraction and analysis
type FirmwareAnalyzer struct {
	logger      *logrus.Logger
	workDir     string
	signatures  []FirmwareSignature
	findings    []FindingResult
	mu          sync.Mutex
}

// FirmwareSignature represents a pattern to search for in firmware
type FirmwareSignature struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Category    string
	Pattern     *regexp.Regexp
	FileTypes   []string
}

// FindingResult represents a security issue found in firmware
type FindingResult struct {
	SignatureID   string
	SignatureName string
	Description   string
	Severity      string
	Category      string
	FilePath      string
	LineNumber    int
	Context       string
	Hash          string
}

// AnalysisOptions contains options for firmware analysis
type AnalysisOptions struct {
	ExtractFiles     bool
	DeepScan         bool
	ScanHardcodedCreds bool
	ScanForVulnerableComponents bool
	MaxExtractSize   int64
}

// NewFirmwareAnalyzer creates a new firmware analyzer
func NewFirmwareAnalyzer(workDir string, logger *logrus.Logger) *FirmwareAnalyzer {
	if logger == nil {
		logger = logrus.New()
	}
	
	analyzer := &FirmwareAnalyzer{
		workDir:    workDir,
		logger:     logger,
		signatures: loadDefaultSignatures(),
	}
	
	// Create work directory if it doesn't exist
	os.MkdirAll(workDir, 0755)
	
	return analyzer
}

// AnalyzeFirmware analyzes a firmware file
func (a *FirmwareAnalyzer) AnalyzeFirmware(firmwarePath string, options AnalysisOptions) ([]FindingResult, error) {
	a.mu.Lock()
	a.findings = []FindingResult{}
	a.mu.Unlock()
	
	a.logger.Infof("Analyzing firmware: %s", firmwarePath)
	
	// Get firmware file info
	fi, err := os.Stat(firmwarePath)
	if err != nil {
		return nil, fmt.Errorf("failed to access firmware file: %v", err)
	}
	
	// Check file size
	if options.MaxExtractSize > 0 && fi.Size() > options.MaxExtractSize {
		return nil, fmt.Errorf("firmware file too large (max size: %d bytes)", options.MaxExtractSize)
	}
	
	// Calculate firmware hash
	hash, err := a.calculateFileHash(firmwarePath)
	if err != nil {
		a.logger.Warnf("Failed to calculate firmware hash: %v", err)
	} else {
		a.logger.Infof("Firmware MD5: %s", hash)
	}
	
	// Create extraction directory
	extractDir := filepath.Join(a.workDir, hash)
	os.MkdirAll(extractDir, 0755)
	
	// Extract firmware
	if options.ExtractFiles {
		err = a.extractFirmware(firmwarePath, extractDir)
		if err != nil {
			a.logger.Warnf("Firmware extraction failed: %v", err)
		}
	}
	
	// Analyze embedded files
	err = a.analyzeDirectory(extractDir, options)
	if err != nil {
		a.logger.Warnf("Firmware analysis error: %v", err)
	}
	
	// Return findings
	a.mu.Lock()
	findings := make([]FindingResult, len(a.findings))
	copy(findings, a.findings)
	a.mu.Unlock()
	
	return findings, nil
}

// extractFirmware attempts to extract firmware contents
func (a *FirmwareAnalyzer) extractFirmware(firmwarePath, extractDir string) error {
	// First try to extract as a ZIP file
	err := a.extractZIP(firmwarePath, extractDir)
	if err == nil {
		a.logger.Info("Firmware extracted as ZIP")
		return nil
	}
	
	// Try other extraction methods
	// In a real implementation, you would try various methods:
	// - TAR/GZIP extraction
	// - Binwalk for firmware headers
	// - Specialized IoT firmware unpacking tools
	
	a.logger.Warn("Could not extract firmware with available methods")
	return fmt.Errorf("could not extract firmware")
}

// extractZIP extracts a ZIP file
func (a *FirmwareAnalyzer) extractZIP(zipPath, extractDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	
	for _, file := range reader.File {
		filePath := filepath.Join(extractDir, file.Name)
		
		// Ensure file path is within extract dir (prevent zip slip vulnerability)
		if !strings.HasPrefix(filePath, extractDir) {
			continue
		}
		
		// Create directory tree if needed
		if file.FileInfo().IsDir() {
			os.MkdirAll(filePath, 0755)
			continue
		}
		
		// Create parent directory if needed
		os.MkdirAll(filepath.Dir(filePath), 0755)
		
		// Extract file
		fileReader, err := file.Open()
		if err != nil {
			continue
		}
		
		targetFile, err := os.Create(filePath)
		if err != nil {
			fileReader.Close()
			continue
		}
		
		_, err = io.Copy(targetFile, fileReader)
		
		targetFile.Close()
		fileReader.Close()
	}
	
	return nil
}

// analyzeDirectory scans a directory for security issues
func (a *FirmwareAnalyzer) analyzeDirectory(dir string, options AnalysisOptions) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}
		
		if info.IsDir() {
			return nil // Skip directories
		}
		
		// Check if file extension is interesting
		ext := strings.ToLower(filepath.Ext(path))
		if isInterestingFile(path, ext) {
			err := a.analyzeFile(path, options)
			if err != nil {
				a.logger.Debugf("Error analyzing file %s: %v", path, err)
			}
		}
		
		return nil
	})
}

// analyzeFile scans a single file for security issues
func (a *FirmwareAnalyzer) analyzeFile(filePath string, options AnalysisOptions) error {
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	// Skip large binary files
	if len(content) > 5*1024*1024 && isBinaryFile(content) {
		return nil
	}
	
	// Calculate file hash
	hash := md5.Sum(content)
	fileHash := hex.EncodeToString(hash[:])
	
	// Look for patterns
	for _, sig := range a.signatures {
		// Skip if signature doesn't apply to this file type
		if !signatureAppliesToFile(sig, filePath) {
			continue
		}
		
		// Search for matches
		matches := sig.Pattern.FindAllIndex(content, -1)
		if len(matches) > 0 {
			// Get line numbers and context for matches
			lines := bytes.Split(content, []byte("\n"))
			
			for _, match := range matches {
				lineNum, context := findLineAndContext(lines, match[0])
				
				finding := FindingResult{
					SignatureID:   sig.ID,
					SignatureName: sig.Name,
					Description:   sig.Description,
					Severity:      sig.Severity,
					Category:      sig.Category,
					FilePath:      filePath,
					LineNumber:    lineNum,
					Context:       context,
					Hash:          fileHash,
				}
				
				a.mu.Lock()
				a.findings = append(a.findings, finding)
				a.mu.Unlock()
				
				a.logger.Infof("Found issue: %s in %s (line %d)", sig.Name, filePath, lineNum)
			}
		}
	}
	
	// If deep scan is enabled, perform additional checks
	if options.DeepScan {
		// Additional deep scan checks would go here
	}
	
	// If credential scanning is enabled, look for hardcoded credentials
	if options.ScanHardcodedCreds {
		// Credential scanning would go here
	}
	
	return nil
}

// calculateFileHash calculates MD5 hash of a file
func (a *FirmwareAnalyzer) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Helper functions
func isInterestingFile(path string, ext string) bool {
	// Check extension
	interestingExts := map[string]bool{
		".c":    true,
		".cpp":  true,
		".h":    true,
		".js":   true,
		".php":  true,
		".py":   true,
		".sh":   true,
		".xml":  true,
		".json": true,
		".conf": true,
		".ini":  true,
		".sql":  true,
		".html": true,
		".txt":  true,
	}
	
	if interestingExts[ext] {
		return true
	}
	
	// Check filename
	interestingNames := []string{
		"passwd", "shadow", "htpasswd", "config", "settings",
		"key", "cert", "crt", "pem", "env", "credentials",
	}
	
	baseName := strings.ToLower(filepath.Base(path))
	for _, name := range interestingNames {
		if strings.Contains(baseName, name) {
			return true
		}
	}
	
	return false
}

func isBinaryFile(content []byte) bool {
	// Simple check: if file contains NULL bytes, it's likely binary
	return bytes.Contains(content, []byte{0})
}

func findLineAndContext(lines [][]byte, offset int) (int, string) {
	// Find line number for byte offset
	lineNum := 1
	currentOffset := 0
	
	for i, line := range lines {
		lineLength := len(line) + 1 // +1 for newline
		if currentOffset+lineLength > offset {
			lineNum = i + 1
			break
		}
		currentOffset += lineLength
	}
	
	// Extract context (the line containing the match)
	if lineNum <= len(lines) {
		return lineNum, string(lines[lineNum-1])
	}
	
	return lineNum, ""
}

func signatureAppliesToFile(sig FirmwareSignature, filePath string) bool {
	// If no file types specified, apply to all files
	if len(sig.FileTypes) == 0 {
		return true
	}
	
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, fileType := range sig.FileTypes {
		if ext == fileType || fileType == "*" {
			return true
		}
	}
	
	return false
}

// loadDefaultSignatures loads the default set of security signatures
func loadDefaultSignatures() []FirmwareSignature {
	signatures := []FirmwareSignature{
		{
			ID:          "FW-CRED-001",
			Name:        "Hardcoded Password",
			Description: "Hardcoded password found in firmware",
			Severity:    "High",
			Category:    "Credentials",
			Pattern:     regexp.MustCompile(`(?i)(?:password|passwd)[\s]*=[\s]*['"]([^'"]{4,})['"]`),
			FileTypes:   []string{".c", ".cpp", ".h", ".js", ".php", ".py", ".sh", ".conf", ".ini"},
		},
		{
			ID:          "FW-CRED-002",
			Name:        "API Key",
			Description: "Possible API key found in firmware",
			Severity:    "Medium",
			Category:    "Credentials",
			Pattern:     regexp.MustCompile(`(?i)(?:api_key|apikey|api token)[\s]*=[\s]*['"]([a-zA-Z0-9_\-]{16,})['"]`),
			FileTypes:   []string{".c", ".cpp", ".h", ".js", ".php", ".py", ".sh", ".conf", ".ini"},
		},
		{
			ID:          "FW-VULN-001",
			Name:        "Command Injection",
			Description: "Potential command injection vulnerability",
			Severity:    "Critical",
			Category:    "Injection",
			Pattern:     regexp.MustCompile(`(?:system|exec|popen|spawn)\s*\(\s*\$?(?:(?:REQUEST)|(?:GET)|(?:POST)|(?:_GET)|(?:_POST))`),
			FileTypes:   []string{".c", ".cpp", ".h", ".php", ".py", ".js"},
		},
		{
			ID:          "FW-VULN-002",
			Name:        "Insecure File Operations",
			Description: "Insecure file operations that could lead to path traversal",
			Severity:    "High",
			Category:    "FileAccess",
			Pattern:     regexp.MustCompile(`(?:fopen|open|file_get_contents)\s*\(\s*\$?(?:(?:REQUEST)|(?:GET)|(?:POST)|(?:_GET)|(?:_POST))`),
			FileTypes:   []string{".c", ".cpp", ".h", ".php", ".py"},
		},
		{
			ID:          "FW-VULN-003",
			Name:        "Use of Weak Crypto",
			Description: "Use of weak or outdated cryptographic functions",
			Severity:    "Medium",
			Category:    "Crypto",
			Pattern:     regexp.MustCompile(`(?:MD5|md5|DES|des|RC4|rc4|SHA1|sha1)\(`),
			FileTypes:   []string{".c", ".cpp", ".h", ".php", ".py", ".js"},
		},
		{
			ID:          "FW-CONFIG-001",
			Name:        "Debug Mode Enabled",
			Description: "Debug mode or verbose logging enabled in production",
			Severity:    "Low",
			Category:    "Configuration",
			Pattern:     regexp.MustCompile(`(?i)(?:debug|verbose)[\s]*=[\s]*(?:true|1|yes|on)`),
			FileTypes:   []string{".conf", ".ini", ".json", ".xml", ".php", ".py", ".js"},
		},
		{
			ID:          "FW-NET-001",
			Name:        "Insecure Network Configuration",
			Description: "Insecure network configuration settings",
			Severity:    "Medium",
			Category:    "Network",
			Pattern:     regexp.MustCompile(`(?i)(?:ssl|tls)[\s]*=[\s]*(?:false|0|no|off)`),
			FileTypes:   []string{".conf", ".ini", ".json", ".xml"},
		},
		{
			ID:          "FW-AUTH-001",
			Name:        "Weak Authentication",
			Description: "Weak or missing authentication settings",
			Severity:    "High",
			Category:    "Authentication",
			Pattern:     regexp.MustCompile(`(?i)(?:auth|authentication|login)[\s]*=[\s]*(?:false|0|no|off|none)`),
			FileTypes:   []string{".conf", ".ini", ".json", ".xml"},
		},
	}
	
	return signatures
}
