package discovery

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ScannerInterface defines the interface for all scanner implementations
type ScannerInterface interface {
	Scan() error
}

// Scan implements the ScannerInterface
func (s *Scanner) Scan() error {
	// Use the existing Discover method
	devices, err := s.Discover()
	if err != nil {
		return err
	}
	
	// Process and output the results
	if s.config.Verbose {
		for _, device := range devices {
			printDeviceInfo(device, s.config.Verbose)
		}
	}
	
	// Save results to the output file if needed
	if s.config.OutputFile != "" {
		err = saveResults(devices, s.config.OutputFile, s.config.OutputFormat)
		if err != nil {
			return err
		}
	}
	
	return nil
}

// Helper function to print device information
func printDeviceInfo(device Device, verbose bool) {
	fmt.Printf("Device: %s\n", device.IP)
	if device.Hostname != "" {
		fmt.Printf("  Hostname: %s\n", device.Hostname)
	}
	if device.MAC != "" {
		fmt.Printf("  MAC: %s\n", device.MAC)
	}
	if device.Vendor != "" {
		fmt.Printf("  Vendor: %s\n", device.Vendor)
	}
	
	// Print open ports
	if len(device.OpenPorts) > 0 {
		fmt.Println("  Open Ports:")
		for port, service := range device.OpenPorts {
			fmt.Printf("    %d: %s\n", port, service)
			
			// Print banner if available and verbose mode is enabled
			if verbose {
				if banner, ok := device.Banners[port]; ok && banner != "" {
					fmt.Printf("      Banner: %s\n", banner)
				}
			}
		}
	}
	
	// Print vulnerabilities if any and verbose mode is enabled
	if verbose && len(device.Vulnerabilities) > 0 {
		fmt.Println("  Vulnerabilities:")
		for _, vuln := range device.Vulnerabilities {
			fmt.Printf("    - %s (CVE: %s, Severity: %s)\n", 
				vuln.Title, vuln.CVE, vuln.Severity)
		}
	}
	
	// Print default credentials if any and verbose mode is enabled
	if verbose && len(device.DefaultCredentials) > 0 {
		fmt.Println("  Default Credentials:")
		for _, cred := range device.DefaultCredentials {
			fmt.Printf("    - %s on %s:%d (User: %s, Pass: %s)\n", 
				cred.Service, device.IP, cred.Port, cred.Username, cred.Password)
		}
	}
	
	fmt.Println()
}

// Helper function to save scan results
func saveResults(devices []Device, outputFile string, outputFormat string) error {
	// Create output file
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()
	
	// Save results based on format
	switch strings.ToLower(outputFormat) {
	case "json":
		return saveAsJSON(devices, file)
	case "csv":
		return saveAsCSV(devices, file)
	case "md", "markdown":
		return saveAsMarkdown(devices, file)
	case "html":
		return saveAsHTML(devices, file)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}

// Save results as JSON
func saveAsJSON(devices []Device, writer io.Writer) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal devices to JSON: %v", err)
	}
	
	_, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write JSON data: %v", err)
	}
	
	return nil
}

// Save results as CSV
func saveAsCSV(devices []Device, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()
	
	// Write header
	header := []string{"IP", "Hostname", "MAC", "Vendor", "Model", "Open Ports", "Vulnerabilities"}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}
	
	// Write device data
	for _, device := range devices {
		// Format open ports
		portList := ""
		i := 0
		for port, service := range device.OpenPorts {
			if i > 0 {
				portList += ", "
			}
			portList += fmt.Sprintf("%d (%s)", port, service)
			i++
		}
		
		// Format vulnerabilities
		vulnList := ""
		for i, vuln := range device.Vulnerabilities {
			if i > 0 {
				vulnList += ", "
			}
			vulnList += fmt.Sprintf("%s (%s)", vuln.Title, vuln.CVE)
		}
		
		// Write row
		row := []string{
			device.IP,
			device.Hostname,
			device.MAC,
			device.Vendor,
			device.Model,
			portList,
			vulnList,
		}
		
		if err := csvWriter.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %v", err)
		}
	}
	
	return nil
}

// Save results as Markdown
func saveAsMarkdown(devices []Device, writer io.Writer) error {
	// Write header
	_, err := fmt.Fprintln(writer, "# IoT Device Security Scan Results")
	if err != nil {
		return err
	}
	
	_, err = fmt.Fprintf(writer, "\nScan performed on %s\n\n", time.Now().Format(time.RFC1123))
	if err != nil {
		return err
	}
	
	// Write device data
	for _, device := range devices {
		_, err = fmt.Fprintf(writer, "## Device: %s\n\n", device.IP)
		if err != nil {
			return err
		}
		
		// Basic info
		_, err = fmt.Fprintln(writer, "### Basic Information")
		if err != nil {
			return err
		}
		
		_, err = fmt.Fprintf(writer, "- **IP Address**: %s\n", device.IP)
		if err != nil {
			return err
		}
		
		if device.Hostname != "" {
			_, err = fmt.Fprintf(writer, "- **Hostname**: %s\n", device.Hostname)
			if err != nil {
				return err
			}
		}
		
		if device.MAC != "" {
			_, err = fmt.Fprintf(writer, "- **MAC Address**: %s\n", device.MAC)
			if err != nil {
				return err
			}
		}
		
		if device.Vendor != "" {
			_, err = fmt.Fprintf(writer, "- **Vendor**: %s\n", device.Vendor)
			if err != nil {
				return err
			}
		}
		
		if device.Model != "" {
			_, err = fmt.Fprintf(writer, "- **Model**: %s\n", device.Model)
			if err != nil {
				return err
			}
		}
		
		// Open ports
		if len(device.OpenPorts) > 0 {
			_, err = fmt.Fprintln(writer, "\n### Open Ports")
			if err != nil {
				return err
			}
			
			for port, service := range device.OpenPorts {
				_, err = fmt.Fprintf(writer, "- **%d**: %s\n", port, service)
				if err != nil {
					return err
				}
			}
		}
		
		// Vulnerabilities
		if len(device.Vulnerabilities) > 0 {
			_, err = fmt.Fprintln(writer, "\n### Vulnerabilities")
			if err != nil {
				return err
			}
			
			for _, vuln := range device.Vulnerabilities {
				_, err = fmt.Fprintf(writer, "- **%s** (%s)\n", vuln.Title, vuln.CVE)
				if err != nil {
					return err
				}
				
				_, err = fmt.Fprintf(writer, "  - Severity: %s\n", vuln.Severity)
				if err != nil {
					return err
				}
				
				if vuln.Description != "" {
					_, err = fmt.Fprintf(writer, "  - Description: %s\n", vuln.Description)
					if err != nil {
						return err
					}
				}
			}
		}
		
		// Default Credentials
		if len(device.DefaultCredentials) > 0 {
			_, err = fmt.Fprintln(writer, "\n### Default Credentials")
			if err != nil {
				return err
			}
			
			for _, cred := range device.DefaultCredentials {
				_, err = fmt.Fprintf(writer, "- **%s** (Port %d)\n", cred.Service, cred.Port)
				if err != nil {
					return err
				}
				
				_, err = fmt.Fprintf(writer, "  - Username: %s\n", cred.Username)
				if err != nil {
					return err
				}
				
				_, err = fmt.Fprintf(writer, "  - Password: %s\n", cred.Password)
				if err != nil {
					return err
				}
			}
		}
		
		// Add separator between devices
		_, err = fmt.Fprintln(writer, "\n---\n")
		if err != nil {
			return err
		}
	}
	
	return nil
}

// Save results as HTML
func saveAsHTML(devices []Device, writer io.Writer) error {
	// Write HTML header
	_, err := fmt.Fprint(writer, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Device Security Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #333; }
        .device { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .vuln-high { color: #d9534f; }
        .vuln-medium { color: #f0ad4e; }
        .vuln-low { color: #5bc0de; }
        table { border-collapse: collapse; width: 100%; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>IoT Device Security Scan Results</h1>
    <p>Scan performed on `)
	if err != nil {
		return err
	}
	
	_, err = fmt.Fprint(writer, time.Now().Format(time.RFC1123))
	if err != nil {
		return err
	}
	
	_, err = fmt.Fprint(writer, `</p>
`)
	if err != nil {
		return err
	}
	
	// Write device data
	for _, device := range devices {
		_, err = fmt.Fprintf(writer, `    <div class="device">
        <h2>Device: %s</h2>
`, device.IP)
		if err != nil {
			return err
		}
		
		// Basic info
		_, err = fmt.Fprint(writer, `        <h3>Basic Information</h3>
        <table>
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
`)
		if err != nil {
			return err
		}
		
		_, err = fmt.Fprintf(writer, `            <tr>
                <td>IP Address</td>
                <td>%s</td>
            </tr>
`, device.IP)
		if err != nil {
			return err
		}
		
		if device.Hostname != "" {
			_, err = fmt.Fprintf(writer, `            <tr>
                <td>Hostname</td>
                <td>%s</td>
            </tr>
`, device.Hostname)
			if err != nil {
				return err
			}
		}
		
		if device.MAC != "" {
			_, err = fmt.Fprintf(writer, `            <tr>
                <td>MAC Address</td>
                <td>%s</td>
            </tr>
`, device.MAC)
			if err != nil {
				return err
			}
		}
		
		if device.Vendor != "" {
			_, err = fmt.Fprintf(writer, `            <tr>
                <td>Vendor</td>
                <td>%s</td>
            </tr>
`, device.Vendor)
			if err != nil {
				return err
			}
		}
		
		if device.Model != "" {
			_, err = fmt.Fprintf(writer, `            <tr>
                <td>Model</td>
                <td>%s</td>
            </tr>
`, device.Model)
			if err != nil {
				return err
			}
		}
		
		_, err = fmt.Fprint(writer, `        </table>
`)
		if err != nil {
			return err
		}
		
		// Open ports
		if len(device.OpenPorts) > 0 {
			_, err = fmt.Fprint(writer, `        <h3>Open Ports</h3>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
            </tr>
`)
			if err != nil {
				return err
			}
			
			for port, service := range device.OpenPorts {
				_, err = fmt.Fprintf(writer, `            <tr>
                <td>%d</td>
                <td>%s</td>
            </tr>
`, port, service)
				if err != nil {
					return err
				}
			}
			
			_, err = fmt.Fprint(writer, `        </table>
`)
			if err != nil {
				return err
			}
		}
		
		// Vulnerabilities
		if len(device.Vulnerabilities) > 0 {
			_, err = fmt.Fprint(writer, `        <h3>Vulnerabilities</h3>
        <table>
            <tr>
                <th>Title</th>
                <th>CVE</th>
                <th>Severity</th>
                <th>Description</th>
            </tr>
`)
			if err != nil {
				return err
			}
			
			for _, vuln := range device.Vulnerabilities {
				severityClass := "vuln-low"
				if strings.Contains(strings.ToLower(vuln.Severity), "high") {
					severityClass = "vuln-high"
				} else if strings.Contains(strings.ToLower(vuln.Severity), "medium") {
					severityClass = "vuln-medium"
				}
				
				_, err = fmt.Fprintf(writer, `            <tr>
                <td>%s</td>
                <td>%s</td>
                <td class="%s">%s</td>
                <td>%s</td>
            </tr>
`, vuln.Title, vuln.CVE, severityClass, vuln.Severity, vuln.Description)
				if err != nil {
					return err
				}
			}
			
			_, err = fmt.Fprint(writer, `        </table>
`)
			if err != nil {
				return err
			}
		}
		
		// Default Credentials
		if len(device.DefaultCredentials) > 0 {
			_, err = fmt.Fprint(writer, `        <h3>Default Credentials</h3>
        <table>
            <tr>
                <th>Service</th>
                <th>Port</th>
                <th>Username</th>
                <th>Password</th>
            </tr>
`)
			if err != nil {
				return err
			}
			
			for _, cred := range device.DefaultCredentials {
				_, err = fmt.Fprintf(writer, `            <tr>
                <td>%s</td>
                <td>%d</td>
                <td>%s</td>
                <td>%s</td>
            </tr>
`, cred.Service, cred.Port, cred.Username, cred.Password)
				if err != nil {
					return err
				}
			}
			
			_, err = fmt.Fprint(writer, `        </table>
`)
			if err != nil {
				return err
			}
		}
		
		_, err = fmt.Fprint(writer, `    </div>
`)
		if err != nil {
			return err
		}
	}
	
	// Write HTML footer
	_, err = fmt.Fprint(writer, `</body>
</html>
`)
	if err != nil {
		return err
	}
	
	return nil
}
