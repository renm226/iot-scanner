package models

import "time"

type Device struct {
	IP                 string
	MAC                string
	Hostname           string
	Vendor             string
	Model              string
	FirmwareVersion    string
	OpenPorts          map[int]string
	OperatingSystem    string
	Vulnerabilities    []Vulnerability
	DefaultCredentials []Credential
	Banners            map[int]string
	LastSeen           time.Time
	Services           map[string]string
	Tags               []string
	MACAddress         string
}

type Vulnerability struct {
	ID          string
	CVE         string
	Name        string
	Title       string
	Description string
	Severity    string
	CVSS        float64
	References  []string
	Remediation string
	Exploitable bool
	ExploitRef  string
}

type Credential struct {
	Service  string
	Port     int
	Username string
	Password string
	Valid    bool
}
