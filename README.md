# IoT Device Security Scanner

A real-time, agent-free network security tool written in Go that discovers, fingerprints, and assesses the security posture of IoT devices on a local network — all from a single scanning host, with no agents required on target devices.

## Features

- **Active discovery** — ARP sweep, ICMP echo, TCP SYN scanning
- **Passive monitoring** — libpcap-based packet capture (ARP, DHCP, DNS)
- **Device fingerprinting** — MAC OUI resolution, banner grabbing, SNMP enumeration, DHCP/DNS passive analysis
- **Vulnerability assessment** — default credential testing (2,847 known pairs), SNMP misconfiguration detection, CVE matching via the NIST NVD API
- **AI assistant** — Claude API integration that converts scan findings into plain-language remediation advice
- **Web dashboard** — real-time device map, vulnerability alerts, network topology graph, and interactive AI assistant

---

## Prerequisites

### Required

- **Go 1.21 or later** — https://go.dev/dl
- **Git**

### Required for real network scanning

| Platform | Requirement |
|---|---|
| Linux / macOS | Run as `root` (`sudo`) — needed for ARP sweep and packet capture |
| Windows | Run terminal as **Administrator** + install **[Npcap](https://npcap.com/)** (enable WinPcap compatibility mode during install) |

### Optional

- **Npcap / libpcap** — required only for passive packet capture (`--pcap` flag)

> Simulation mode (`-test`) requires no root access, no network, and no Npcap.

---

## Installation

```bash
git clone <repository-url>
cd IoT-device-Scanner

go mod download
go build ./...
go vet ./...
```

Data directories are created automatically on first run. To create them manually:

```bash
mkdir -p data data/fingerprint data/firmware data/reports data/logs reports
```

---

## Quick Start

The fastest way to explore all features is simulation mode, which generates synthetic IoT devices with realistic vulnerabilities, open ports, and fingerprints — no network or root access needed.

```bash
go run ./cmd/scanner/ -test -dashboard -port 8080
```

Open **http://localhost:8080** to access the dashboard.

---

## Usage

The project exposes three CLI entry points. Use whichever matches your workflow.

---

### CLI A — Subcommand style (`./cmd/`)

The primary entry point with a structured subcommand interface.

```bash
# Basic device discovery
go run ./cmd/ scan --range 192.168.1.0/24

# Full scan: fingerprinting + vulnerability checks + credential testing
go run ./cmd/ scan --range 192.168.1.0/24 --full --output scan_results.json

# Enhanced scan: adds SNMP enumeration, MAC OUI lookup, topology map
sudo go run ./cmd/ scan --range 192.168.1.0/24 --full --enhanced --output scan_results.json

# Launch dashboard from saved results
go run ./cmd/ dashboard --port 8080 --results scan_results.json
```

#### Subcommands

| Command | Description |
|---|---|
| `scan --range <CIDR>` | Target network (default: `192.168.1.0/24`) |
| `scan --full` | Enable vulnerability and credential scanning |
| `scan --enhanced` | Add SNMP enumeration, MAC OUI lookup, topology |
| `scan --threads <n>` | Concurrent threads (default: `10`) |
| `scan --timeout <duration>` | Network timeout (default: `5s`) |
| `scan --output <file>` | Save results to JSON |
| `dashboard --port <port>` | Dashboard port (default: `8080`) |
| `dashboard --results <file>` | Pre-load scan results into dashboard |
| `topology generate --input <file>` | Generate topology map from scan results |
| `snmp scan --range <CIDR>` | Dedicated SNMP scan |
| `firmware analyze --file <path>` | Analyze a firmware binary |
| `exploit test --target <IP>` | Test known exploits against a target device |

#### Global flags

| Flag | Description |
|---|---|
| `--verbose` | Enable debug-level logging |
| `--log-level debug\|info\|warn\|error` | Set log verbosity |
| `--config <file>` | Load all settings from a JSON config file |

---

### CLI B — Flag style (`./cmd/scanner/`)

Includes test/simulation mode.

```bash
# Simulation — no root, no network, full dashboard
go run ./cmd/scanner/ -test -dashboard -port 8080

# Real scan with dashboard
sudo go run ./cmd/scanner/ -range 192.168.1.0/24 -full -dashboard -port 8080

# Full scan with live CVE feed, exploit alerts, and HTML report export
sudo go run ./cmd/scanner/ \
  -range 192.168.1.0/24 \
  -full \
  -dashboard -port 8080 \
  -live-cve -cve-interval 30 \
  -exploit-notify \
  -export -format html -export-dir reports
```

| Flag | Default | Description |
|---|---|---|
| `-range` | `192.168.1.0/24` | CIDR network to scan |
| `-threads` | `10` | Concurrent scanning threads |
| `-timeout` | `5` | Network timeout in seconds |
| `-full` | `false` | Full scan: vulnerability checks + credential testing |
| `-test` | `false` | Simulation mode — no network or root required |
| `-dashboard` | `false` | Launch web dashboard |
| `-port` | `8080` | Dashboard port |
| `-output` | `results.json` | JSON output file |
| `-verbose` | `false` | Debug logging |
| `-live-cve` | `false` | Poll NIST NVD API for new CVEs |
| `-cve-interval` | `60` | CVE poll interval in minutes |
| `-exploit-notify` | `false` | Alert on newly discovered exploits |
| `-export` | `false` | Export a report file |
| `-format` | `json` | Export format: `json`, `csv`, `md`, `html` |
| `-export-dir` | `reports` | Directory for exported reports |

---

### CLI C — Root-level all-in-one (`./`)

```bash
# Simulation with dashboard
go run . -test -dashboard

# Full scan with all features enabled
sudo go run . \
  -range 192.168.1.0/24 \
  -full \
  -dashboard -port 8080 \
  -live-cve -exploit-notify \
  -export -format html
```

---

## Passive Packet Capture

Enables continuous background monitoring without active probing after the initial sweep. Linux and macOS only.

```bash
# Find your interface
ip link show        # Linux
ifconfig            # macOS

# Launch with passive capture
sudo go run ./cmd/scanner/ \
  -range 192.168.1.0/24 \
  -full -dashboard \
  -pcap eth0
```

---

## Scanning Modes

| Mode | Command | Root Required | Network Required | Description |
|---|---|---|---|---|
| Simulation | `-test -dashboard` | No | No | Full dashboard with synthetic devices |
| Basic | `scan --range ...` | Yes | Yes | ARP discovery + port scan |
| Full | `scan --range ... --full` | Yes | Yes | + Credential testing + CVE matching |
| Enhanced | `scan --range ... --full --enhanced` | Yes | Yes | + SNMP enumeration + MAC OUI + topology |
| Passive | `-pcap <interface>` | Yes | Yes | Continuous background ARP monitoring |

---

## Configuration File

All settings can be loaded from a JSON config file using `--config config.json`:

```json
{
  "IPRange":         "192.168.1.0/24",
  "FullScan":        true,
  "EnhancedScan":    true,
  "Threads":         10,
  "Timeout":         "5s",
  "OutputFile":      "scan_results.json",
  "OutputFormat":    "json",
  "EnableDashboard": true,
  "DashboardPort":   "8080",
  "EnableExport":    true,
  "ExportDirectory": "reports",
  "DatabasePath":    "data",
  "FingerPrintDB":   "data/fingerprints.json"
}
```

---

## Report Export

| Format | Flag value | Contents |
|---|---|---|
| JSON | `json` | Full machine-readable device and vulnerability data |
| CSV | `csv` | Spreadsheet-compatible device listing |
| Markdown | `md` | Documentation-ready tables |
| HTML | `html` | Self-contained browser report with styled tables |

Reports are saved to `reports/iot_scan_<YYYYMMDD-HHMMSS>.<ext>`.

---

## Web Dashboard

Accessible at **http://localhost:8080** when `-dashboard` or `--dashboard` is set.

- **Device table** — IP, MAC, vendor, model, OS, firmware version, open ports, CVEs
- **Real-time alerts** — WebSocket-streamed notifications for newly detected devices and HIGH/CRITICAL findings
- **Network topology** — D3.js interactive graph of device relationships
- **Vulnerability summary** — CVE list with CVSS scores and NIST NVD links
- **AI Security Assistant** — Chat interface at `/assistant`; generates prioritized remediation checklists from scan findings, aligned with NIST SP 800-213 and the OWASP IoT Top 10
- **Export** — Download results as JSON or HTML directly from the browser

---

## Project Structure

```
IoT-device-Scanner/
├── cmd/
│   ├── main.go                  # Primary CLI (subcommand-based)
│   ├── main/main.go             # Alternate CLI (flag-based)
│   └── scanner/
│       ├── main.go              # Scanner CLI with simulation mode
│       └── main_advanced.go     # Advanced scanner helpers
├── integrated_scanner.go        # Root-level scanner with CVE feed and export
├── pkg/
│   ├── api/
│   │   ├── assistant.go         # AI assistant chat endpoint
│   │   ├── dashboard.go         # Web dashboard and WebSocket server
│   │   └── server.go            # HTTP server setup
│   ├── config/config.go         # Config struct and defaults
│   ├── credentials/             # Default credential database and tester
│   ├── discovery/
│   │   ├── discovery.go         # ARP sweep, ICMP, TCP SYN scanner
│   │   ├── advanced_discovery.go
│   │   └── scanner_interface.go
│   ├── exploit/exploit.go       # CVE exploit testing
│   ├── fingerprint/
│   │   ├── fingerprint.go       # Banner grabbing, SNMP, DHCP fingerprinting
│   │   └── mac_vendor.go        # OUI-to-manufacturer database
│   ├── firmware/analyzer.go     # Firmware binary analysis
│   ├── integration/
│   │   ├── enhanced_scanner.go  # SNMP, MAC, and topology orchestration
│   │   └── test_scanner.go      # Simulation scanner
│   ├── models/
│   │   ├── device.go            # Device, Vulnerability, Credential types
│   │   └── device_methods.go
│   ├── netmap/topology.go       # Network topology graph
│   ├── pcap/packet_analyzer.go  # libpcap passive packet capture
│   ├── snmp/scanner.go          # SNMP community string testing and OID walk
│   └── vulnerability/           # NIST NVD CVE lookup and CVSS scoring
├── data/                        # Runtime data (OUI DB, fingerprints, CVE cache)
├── reports/                     # Exported scan reports
├── go.mod
└── go.sum
```

---

## Default Scanned Ports

| Port | Protocol / Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 80 | HTTP |
| 443 | HTTPS |
| 554 | RTSP |
| 1883 | MQTT |
| 5683 | CoAP |
| 8080 | HTTP (alternate) |
| 8443 | HTTPS (alternate) |
| 8883 | MQTT over TLS |
| 9000 | UPnP |

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/google/gopacket` | Packet capture via libpcap |
| `github.com/gin-gonic/gin` | Web dashboard HTTP server |
| `github.com/urfave/cli/v2` | Subcommand CLI framework |
| `github.com/sirupsen/logrus` | Structured logging |
| `github.com/fatih/color` | Terminal color output |

See `go.mod` for the full dependency list.

---

## Limitations

- **MAC address randomization** — iOS 14+, Android 10+, and Windows 10 v1903+ use per-network randomized MACs. Reconnecting devices appear as new unknowns. Mitigation requires multi-dimensional identification (DHCP fingerprinting, TLS JA3, behavioral profiling).
- **Encrypted traffic** — Passive fingerprinting is limited to unencrypted protocols. Increasing TLS adoption by IoT vendors reduces traffic-analysis utility.
- **Single subnet scope** — ARP-based discovery is bounded by a single Layer-2 broadcast domain. Multi-VLAN environments require one scanner instance per segment.
- **Windows constraints** — Full ARP sweep and packet capture on Windows require Npcap and an Administrator terminal. Features degrade gracefully without it.
- **Legal notice** — Active scanning and credential testing are only lawful on networks for which you hold explicit authorization. Unauthorized use may violate applicable computer fraud legislation.

---

## License

See `LICENSE` for terms.