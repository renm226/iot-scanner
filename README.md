# IoT Device Security Scanner

An advanced network security scanner written in Go that identifies IoT devices on a network, fingerprints them, and performs comprehensive security assessments including vulnerability scanning, credential testing, and firmware analysis. The scanner includes an AI-powered assistant to help interpret scan results and provide security recommendations.

## Features

### Core Features
- Network discovery of IoT devices (basic and advanced modes)
- Device fingerprinting (vendor, model, firmware version)
- Vulnerability scanning based on device profiles
- Default credential checking for common IoT devices
- Insecure configuration detection
- Detailed reporting with severity levels

### Advanced Features
- Web-based dashboard for real-time monitoring and analysis
- AI Assistant for interactive security guidance and recommendations
- SNMP scanning and enumeration
- MAC address vendor identification
- Network topology mapping and visualization
- Packet capture and analysis for IoT protocol detection
- Firmware extraction and vulnerability analysis
- Exploit testing (for authorized security assessments only)
- Integration with CVE databases for real-time vulnerability detection

### Next Future Features
- **Interactive Device Analysis**: Click on any device in the dashboard to open a detailed popup with comprehensive security analysis
- **Firmware Vulnerability Explorer**: Interactive popup interface for exploring detected firmware vulnerabilities with remediation guidance
- **Real-time Attack Surface Visualization**: Click-to-expand popup showing potential attack vectors for each device
- **Compliance Report Generator**: One-click popup to generate compliance reports against various IoT security standards
- **Threat Intelligence Integration**: Popup alerts when devices match known threat indicators
- **Remote Remediation Interface**: Interactive popup console for authorized device remediation actions
- **Custom Rule Builder**: Drag-and-drop popup interface for creating custom scanning rules

## Requirements

### System Requirements
- Go 1.21 or later
- Root/Administrator privileges (for raw socket operations and port scanning)
- libpcap development libraries (for packet capture features)

### Dependencies for Real Device Scanning

#### Required Packages
- **libpcap**: Essential for packet capture and network traffic analysis
  - Ubuntu/Debian: `sudo apt install libpcap-dev`
  - CentOS/RHEL: `sudo yum install libpcap-devel`
  - macOS: `brew install libpcap`

#### Network Permissions
- **CAP_NET_RAW capability**: Required for raw socket operations
  - `sudo setcap cap_net_raw+ep /path/to/iot-scanner`
- **CAP_NET_ADMIN capability**: Required for network interface operations
  - `sudo setcap cap_net_admin+ep /path/to/iot-scanner`
- **Root or sudo access**: Alternatively, running the entire application with elevated privileges
  - `sudo ./iot-scanner scan`

#### Firewall Configuration
- Allow outgoing TCP SYN packets for port scanning
- Allow ICMP echo request/reply for device discovery
- If using SNMP scanning, allow UDP 161 traffic

#### Hardware Requirements
- Network interface that supports promiscuous mode (for passive scanning)
- Wireless adapter that supports monitor mode (for wireless IoT device scanning)

### Optional Dependencies
- MongoDB (for persistent scan results storage)
- Python 3.8+ with scikit-learn (for enhanced device classification)
- Nmap 7.0+ (for advanced port scanning capabilities)
- WireShark/TShark (for detailed protocol analysis)

## Installation

### Installing Dependencies

```bash
# Install required system packages (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential libpcap-dev golang-go

```

### Installation Steps

```bash

# Install Go dependencies
go mod download
go mod tidy

# Build the application
go build -o iot-scanner ./cmd/main.go

# Verify installation
./iot-scanner --version
```

## Usage

### Basic Commands

```bash
# Show help and available commands
./iot-scanner --help

# Basic scan of local network
./iot-scanner scan

# Scan specific IP range
./iot-scanner scan --range 192.168.1.0/24 --threads 20

# Full scan with all security checks
./iot-scanner scan --range 192.168.1.0/24 --full

# Output results to JSON file
./iot-scanner scan --range 192.168.1.0/24 --output results.json
```

### Dashboard & AI Assistant

```bash
# Start the web dashboard on default port (8080)
./iot-scanner dashboard

# Start dashboard on specific port
./iot-scanner dashboard --port 9090

# Start dashboard with persistent storage
./iot-scanner dashboard --db-path ./data/scanner.db
```

Once the dashboard is running, access it at http://localhost:8080

The AI Assistant is available at http://localhost:8080/assistant

### Advanced Features

```bash
# Generate network topology
./iot-scanner topology generate --input scan_results.json

# Perform SNMP scanning
./iot-scanner snmp scan --range 192.168.1.0/24 --community public

# Test mode (simulated devices, no actual network scanning)
./iot-scanner scan --simulation

# Analyze firmware (if available)
./iot-scanner firmware analyze --file firmware.bin

# Run exploit tests (use responsibly)
./iot-scanner exploit test --target 192.168.1.100 --port 23
```

## Running in Test Mode

The scanner includes a test mode to simulate network scanning and device discovery without requiring actual network access or privileges. This is useful for testing and development purposes.

```bash
# Run scanner in test mode with simulated devices
./iot-scanner scan --simulation

# Run dashboard with simulated data
./iot-scanner dashboard --simulation
```

## Scanning Real Devices

To scan actual IoT devices on your network, the scanner must be run with appropriate permissions. Here are the detailed commands for real-world scanning:

### Basic Network Scan

```bash
# Basic scan (requires root privileges)
sudo ./iot-scanner scan --range 192.168.1.0/24

# Specify scan threads for faster performance
sudo ./iot-scanner scan --range 192.168.1.0/24 --threads 20

# Scan specific IP address
sudo ./iot-scanner scan --range 192.168.1.100/32
```

### Advanced Scanning

```bash
# Full scan with vulnerability checks (takes longer)
sudo ./iot-scanner scan --range 192.168.1.0/24 --full

# Enhanced scan with SNMP, device fingerprinting
sudo ./iot-scanner scan --range 192.168.1.0/24 --enhanced --snmp

# Specifying additional scan options
sudo ./iot-scanner scan --range 192.168.1.0/24 --timeout 10s --output scan_results.json
```

### Using Without Root (with capabilities)

If you prefer not to run the entire application as root, you can use Linux capabilities:

```bash
# Set required capabilities
sudo setcap cap_net_raw,cap_net_admin+ep ./iot-scanner

# Now you can run without sudo
./iot-scanner scan --range 192.168.1.0/24
```

### Scanning from the Web Dashboard

1. Start the dashboard: `./iot-scanner dashboard`
2. Access in browser: http://localhost:8080
3. Click the "Start Scan" button in the top right
4. Enter the IP range and options in the modal dialog
5. Click "Start Scan" to begin the network scan

> **Note:** If running the dashboard without root privileges, you may need to provide the password when prompted, or configure sudo to allow the scan command without a password.

## Troubleshooting Scan Issues

### Common Problems

1. **Permission Denied Errors**
   - Solution: Run with sudo or set correct capabilities
   - Command: `sudo setcap cap_net_raw,cap_net_admin+ep ./iot-scanner`

2. **No Devices Found**
   - Check if you're on the same network as your IoT devices
   - Try a smaller IP range or specific IP addresses
   - Verify devices are powered on and connected

3. **Scan Button Not Working**
   - Ensure you have the latest version of the application
   - Check browser console for JavaScript errors
   - Make sure the backend API server is running

4. **Slow Scanning**
   - Increase thread count: `--threads 30`
   - Reduce timeout: `--timeout 3s`
   - Limit scan to smaller IP ranges



## Disclaimer

This tool is designed for security professionals and researchers to audit their own networks. Always obtain proper authorization before scanning any network. The authors are not responsible for any misuse or damage caused by this program.

