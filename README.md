# IoT Device Security Scanner

> **College of Engineering — Department of Computer Science and Engineering**
> **CMPS 485: Computer Security | Spring 2026**
>
> | | |
> |---|---|
> | **Submission Date** | May 7, 2026 |
> | **Course Instructor** | Dr. Ahmed Badawy |
> | **Teaching Assistant** | Engr. Naveed Nawaz |
> | **Team Members** | Hissa Al-Qahtani (201904081) · Noora Al-Naimi (201106147) · Noora Al-Yafei (202103324) |

---

## Overview

The IoT Security Scanner is a real-time, agent-free network security tool written in Go that discovers, fingerprints, and assesses the security posture of IoT devices on a local network — all from a single scanning host without installing agents on target devices.

The scanner combines:

- **Active discovery** — ARP sweep, ICMP echo, TCP SYN scanning
- **Passive monitoring** — libpcap-based packet capture (ARP, DHCP, DNS)
- **Device fingerprinting** — MAC OUI resolution, banner grabbing, SNMP enumeration, DHCP/DNS passive analysis
- **Vulnerability assessment** — default credential testing (2,847 known pairs), SNMP misconfiguration detection, CVE matching via the NIST NVD API
- **AI-powered assistant** — Claude API integration that converts raw scan findings into plain-language remediation advice
- **Web dashboard** — real-time device map, vulnerability alerts, and interactive AI assistant

---

## Key Results (Evaluated on 14-Device Physical Testbed)

| Metric | Result |
|---|---|
| Unauthorized device detection rate | **90%** within 30 seconds |
| Mean detection latency | **3.2 seconds** |
| Default credential detection accuracy | **88.9%** |
| SNMP enumeration coverage | **100%** |
| False positive rate | **0%** |
| Full scan duration (17 devices) | **47.3 seconds** |

---

## System Architecture

```
cmd/
├── main.go              ← Primary CLI entry point (urfave/cli, subcommands)
├── main/main.go         ← Alternate CLI (flag-based)
└── scanner/
    ├── main.go          ← Scanner CLI (flag-based, includes test mode)
    └── main_advanced.go ← Advanced scanner helpers

pkg/
├── discovery/           ← ARP sweep, ICMP, TCP SYN, passive ARP listener
├── fingerprint/         ← MAC OUI, banner grabbing, SNMP, DHCP/DNS
├── credentials/         ← Default credential testing (SSH, Telnet, HTTP)
├── vulnerability/       ← CVE matching via NIST NVD API
├── snmp/                ← SNMP community string enumeration and OID walks
├── pcap/                ← libpcap packet capture and traffic analysis
├── firmware/            ← Firmware binary analysis
├── exploit/             ← Exploit testing module
├── netmap/              ← Network topology graph generation
├── api/                 ← Web dashboard, WebSocket streaming, AI assistant
├── integration/         ← Enhanced scanner orchestration, simulation scanner
├── models/              ← Shared data structures (Device, Vulnerability, etc.)
└── config/              ← Configuration loading and defaults
```

**Default scanned ports:** 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 80 (HTTP), 443 (HTTPS), 554 (RTSP), 1883 (MQTT), 5683 (CoAP), 8080 (HTTP-Alt), 8443 (HTTPS-Alt), 8883 (MQTT-TLS), 9000 (UPnP)

---

## Prerequisites

### Required

- **Go 1.21 or later** — [https://go.dev/dl](https://go.dev/dl)
- **Git**

### Required for real network scanning (raw socket access)

| Platform | Requirement |
|---|---|
| Linux / macOS | Run as `root` (`sudo`) — needed for ARP sweep and packet capture |
| Windows | Run terminal as **Administrator** + install **[Npcap](https://npcap.com/)** (enable WinPcap compatibility mode during install) |

> **No root needed for test/demo mode.** The `-test` flag runs a full simulation with synthetic IoT devices — no network access, no Npcap, no administrator rights required.

### Optional

- **Npcap / libpcap** — required only for passive packet capture (`--pcap` flag)

---

## Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd IoT-device-Scanner

# 2. Download Go dependencies
go mod download

# 3. Verify everything builds
go build ./...
go vet ./...
```

Data directories are created automatically on first run. To create them manually:

```bash
mkdir -p data data/fingerprint data/firmware data/reports data/logs reports
```

---

## Quick Start — No Root, No Network Required

The fastest way to explore all features is **simulation mode**, which generates realistic synthetic IoT devices with vulnerabilities, open ports, and fingerprints.

```bash
go run ./cmd/scanner/ -test -dashboard -port 8080
```

Open **http://localhost:8080** in your browser to see the full dashboard with device listings, vulnerability alerts, and the AI assistant.

---

## Running the System

The project exposes two CLI styles. Use whichever matches your workflow.

---

### CLI A — Subcommand style (`./cmd/`) — Primary entry point

This is the most feature-complete entry point, using a structured subcommand interface.

#### Scan only

```bash
# Basic device discovery
go run ./cmd/ scan --range 192.168.1.0/24

# Full scan: fingerprinting + vulnerability checks + credential testing
go run ./cmd/ scan --range 192.168.1.0/24 --full --output scan_results.json

# Enhanced scan: adds SNMP enumeration + MAC OUI lookup + topology map
go run ./cmd/ scan --range 192.168.1.0/24 --full --enhanced --output scan_results.json
```

On Linux/macOS, prefix with `sudo`:

```bash
sudo go run ./cmd/ scan --range 192.168.1.0/24 --full --enhanced --output scan_results.json
```

#### Dashboard only (loads previously saved results)

```bash
go run ./cmd/ dashboard --port 8080 --results scan_results.json
```

Open **http://localhost:8080**.

#### Full workflow: scan then view in dashboard

```bash
# Terminal 1 — run the scan (saves to scan_results.json)
sudo go run ./cmd/ scan --range 192.168.1.0/24 --full --enhanced --output scan_results.json

# Terminal 2 — start the dashboard at any time
go run ./cmd/ dashboard --port 8080 --results scan_results.json
```

#### All subcommands

| Command | Description |
|---|---|
| `scan --range <CIDR>` | Set target network (default: `192.168.1.0/24`) |
| `scan --full` | Enable vulnerability + credential scanning |
| `scan --enhanced` | Add SNMP enumeration, MAC OUI lookup, topology |
| `scan --threads <n>` | Concurrent threads (default: `10`) |
| `scan --timeout <duration>` | Network timeout (default: `5s`) |
| `scan --output <file>` | Save results to JSON file |
| `dashboard --port <port>` | Dashboard port (default: `8080`) |
| `dashboard --results <file>` | Pre-load scan results into dashboard |
| `topology generate --input <file>` | Generate topology map from scan results |
| `snmp scan --range <CIDR>` | Dedicated SNMP scan |
| `firmware analyze --file <path>` | Analyze a firmware binary |
| `exploit test --target <IP>` | Test known exploits against a specific device |

Global flags (placed before the subcommand):

| Flag | Description |
|---|---|
| `--verbose` | Enable debug-level logging |
| `--log-level debug\|info\|warn\|error` | Set log verbosity |
| `--config <file>` | Load all settings from a JSON config file |

---

### CLI B — Flag style (`./cmd/scanner/`) — Includes test/demo mode

```bash
# Simulation — no root, no network, full dashboard (best for demo/testing)
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
| `-timeout` | `5` | Network operation timeout (seconds) |
| `-full` | false | Full scan: vuln checks + credential testing |
| `-test` | false | Simulation mode — no network or root needed |
| `-dashboard` | false | Launch web dashboard |
| `-port` | `8080` | Dashboard port |
| `-output` | `results.json` | JSON output file |
| `-verbose` | false | Debug logging |
| `-live-cve` | false | Poll NIST NVD API for new CVEs |
| `-cve-interval` | `60` | CVE poll interval in minutes |
| `-exploit-notify` | false | Alert on newly discovered exploits |
| `-export` | false | Export a report file |
| `-format` | `json` | Export format: `json`, `csv`, `md`, `html` |
| `-export-dir` | `reports` | Directory for exported reports |

---

### CLI C — Integrated scanner (`./`) — Root-level all-in-one

```bash
# Simulation with dashboard
go run . -test -dashboard

# Full scan with every feature enabled
sudo go run . \
  -range 192.168.1.0/24 \
  -full \
  -dashboard -port 8080 \
  -live-cve -exploit-notify \
  -export -format html
```

---

## Passive Packet Capture (Linux/macOS)

Enables continuous background monitoring without active probing after the initial sweep.

```bash
# Find your interface
ip link show        # Linux
ifconfig            # macOS

# Launch with passive capture
sudo go run ./cmd/scanner/ \
  -range 192.168.1.0/24 \
  -full -dashboard \
  -pcap eth0        # replace with your interface name
```

---

## Scanning Modes at a Glance

| Mode | Command | Root Needed | Network Needed | What It Does |
|---|---|---|---|---|
| **Simulation** | `-test -dashboard` | No | No | Full UI with synthetic devices |
| **Basic** | `scan --range ...` | Yes | Yes | ARP discovery + port scan |
| **Full** | `scan --range ... --full` | Yes | Yes | + Credential testing + CVE matching |
| **Enhanced** | `scan --range ... --full --enhanced` | Yes | Yes | + SNMP enum + MAC OUI + topology |
| **Passive** | `-pcap <iface>` | Yes | Yes | Continuous background ARP monitoring |

---

## Configuration File

Load all settings from `config.json` using `--config config.json`:

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

The scanner can export findings in four formats (flag: `-format`, `-export-dir`):

| Format | Flag value | Contents |
|---|---|---|
| JSON | `json` | Full machine-readable device and vulnerability data |
| CSV | `csv` | Spreadsheet-compatible device listing |
| Markdown | `md` | Documentation-ready tables |
| HTML | `html` | Self-contained browser report with styled tables |

Reports are saved to `reports/iot_scan_<YYYYMMDD-HHMMSS>.<ext>`.

---

## Web Dashboard

Accessible at **http://localhost:8080** when `-dashboard` or `--dashboard` is set:

- **Device table** — IP, MAC, vendor, model, OS, firmware version, open ports, CVEs
- **Real-time alerts** — WebSocket-streamed notifications for newly detected devices and HIGH/CRITICAL findings
- **Network topology** — D3.js interactive graph of device relationships
- **Vulnerability summary** — CVE list with CVSS scores and NIST NVD links
- **AI Security Assistant** — Chat interface at `/assistant`; generates prioritized, plain-language remediation checklists from scan findings, aligned with NIST SP 800-213 and the OWASP IoT Top 10
- **Export** — Download results as JSON or HTML directly from the browser

---

## Project File Structure

```
IoT-device-Scanner/
├── cmd/
│   ├── main.go                  # Primary CLI (subcommand-based, urfave/cli)
│   ├── main/main.go             # Alternate CLI (flag-based)
│   └── scanner/
│       ├── main.go              # Scanner CLI (flag-based, test mode)
│       └── main_advanced.go     # Advanced scanner helpers
├── integrated_scanner.go        # Root-level scanner with CVE feed + export
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
│   │   ├── enhanced_scanner.go  # SNMP + MAC + topology orchestration
│   │   └── test_scanner.go      # Simulation/demo scanner
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

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/google/gopacket` | Packet capture via libpcap |
| `github.com/gin-gonic/gin` | Web dashboard HTTP server |
| `github.com/urfave/cli/v2` | Subcommand CLI framework |
| `github.com/sirupsen/logrus` | Structured logging |
| `github.com/fatih/color` | Terminal color output |

Full list in `go.mod`.

---

## Limitations

- **MAC address randomization** — iOS 14+, Android 10+, and Windows 10 v1903+ use per-network randomized MACs, causing re-connecting devices to appear as new unknowns. Mitigation requires multi-dimensional identification (DHCP fingerprinting, TLS JA3, behavioral profiling).
- **Encrypted traffic** — Passive fingerprinting is limited to unencrypted protocols; increasing TLS adoption by IoT vendors reduces traffic-analysis utility.
- **Single subnet scope** — ARP-based discovery is bounded by a single Layer-2 broadcast domain. Multi-VLAN environments require one scanner instance per segment.
- **Windows constraints** — Full ARP sweep and packet capture on Windows require Npcap and an Administrator terminal. Features degrade gracefully without it.
- **Legal notice** — Active scanning and credential testing are **only lawful on networks for which you hold explicit authorization**. Unauthorized use may violate applicable computer fraud legislation (e.g., Qatar Cybercrime Law). All evaluation reported in the accompanying paper was conducted on an isolated dedicated testbed.

---

## Academic Context

This tool was designed, implemented, and evaluated as the course project for **CMPS 485: Computer Security**, College of Engineering, Department of Computer Science and Engineering, Spring 2026.

The accompanying paper documents:
- A five-scenario evaluation on a controlled 14-device physical IoT testbed
- Comparative analysis against arpwatch v2.1 as a passive-ARP baseline
- Per-phase scan timing benchmarks
- Discussion of MAC randomization, encrypted traffic scope, and generalizability limitations
- Future directions including ML-based anomaly detection, distributed multi-segment deployment, and automated CVE database synchronization

**Selected references:** Miettinen et al. (2017) IoT Sentinel; Sivanathan et al. (2018) IoT device classification; Meidan et al. (2018) N-BaIoT; NIST SP 800-213; OWASP IoT Top 10 (2023).
