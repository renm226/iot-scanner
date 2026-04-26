// Dashboard Initialization
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializeModals();
    initializeDummyData();
    initializeCharts();
    setupEventListeners();
});

// Navigation functionality
function initializeNavigation() {
    // Mobile menu toggle
    const burger = document.querySelector('.navbar-burger');
    const menu = document.querySelector('.navbar-menu');
    
    burger.addEventListener('click', () => {
        burger.classList.toggle('is-active');
        menu.classList.toggle('is-active');
    });

    // Section navigation
    const navLinks = document.querySelectorAll('.menu-list a');
    const sections = document.querySelectorAll('.dashboard-section');
    
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            // Update active link
            navLinks.forEach(l => l.classList.remove('is-active'));
            link.classList.add('is-active');
            
            // Show corresponding section
            const targetId = link.id.replace('nav-', 'section-');
            sections.forEach(section => {
                section.classList.add('is-hidden');
                if (section.id === targetId) {
                    section.classList.remove('is-hidden');
                }
            });
        });
    });
}

// Initialize modal functionality
function initializeModals() {
    // Device details modal
    const modal = document.getElementById('device-details-modal');
    const closeButtons = modal.querySelectorAll('.delete, .modal-card-foot .button:not(.is-success)');
    
    closeButtons.forEach(button => {
        button.addEventListener('click', () => {
            modal.classList.remove('is-active');
        });
    });
}

// Initialize with dummy data for demo purposes
function initializeDummyData() {
    // Overview stats
    updateStats({
        total_devices: 24,
        identified_devices: 18,
        vulnerable_devices: 7,
        default_creds_devices: 5
    });

    // Critical security issues
    const criticalIssues = [
        { device: 'Hikvision Camera', ip: '192.168.1.108', issue: 'Default credentials (admin/12345)', severity: 'High' },
        { device: 'TP-Link Router', ip: '192.168.1.1', issue: 'Outdated firmware (known CVE-2019-7406)', severity: 'Critical' },
        { device: 'Dahua IP Camera', ip: '192.168.1.110', issue: 'Authentication bypass vulnerability', severity: 'Critical' },
        { device: 'Netgear Router', ip: '192.168.1.254', issue: 'Weak encryption (WEP)', severity: 'High' }
    ];
    
    const criticalIssuesTable = document.querySelector('#critical-issues-table tbody');
    criticalIssuesTable.innerHTML = '';
    
    criticalIssues.forEach(issue => {
        const severityClass = issue.severity === 'Critical' ? 'has-text-danger' : 'has-text-warning';
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${issue.device}</td>
            <td>${issue.ip}</td>
            <td>${issue.issue}</td>
            <td class="${severityClass} has-text-weight-bold">${issue.severity}</td>
            <td>
                <button class="button is-small is-info view-device-btn" data-ip="${issue.ip}">
                    <span class="icon is-small"><i class="fas fa-search"></i></span>
                    <span>View</span>
                </button>
            </td>
        `;
        criticalIssuesTable.appendChild(row);
    });

    // Add device cards
    const devicesContainer = document.getElementById('devices-container');
    const devices = generateSampleDevices();
    
    devicesContainer.innerHTML = '';
    devices.forEach(device => {
        let deviceClass = '';
        let statusBadge = '';
        
        if (device.vulnerabilities > 0) {
            deviceClass = 'is-vulnerable';
            statusBadge = '<span class="tag is-danger status-badge">Vulnerable</span>';
        } else if (device.defaultCreds) {
            deviceClass = 'has-default-creds';
            statusBadge = '<span class="tag is-warning status-badge">Default Creds</span>';
        }
        
        let deviceIcon = '<i class="fas fa-question-circle"></i>';
        if (device.type === 'camera') {
            deviceIcon = '<i class="fas fa-video"></i>';
        } else if (device.type === 'router') {
            deviceIcon = '<i class="fas fa-network-wired"></i>';
        } else if (device.type === 'thermostat') {
            deviceIcon = '<i class="fas fa-temperature-high"></i>';
        } else if (device.type === 'speaker') {
            deviceIcon = '<i class="fas fa-volume-up"></i>';
        } else if (device.type === 'light') {
            deviceIcon = '<i class="fas fa-lightbulb"></i>';
        }
        
        const card = document.createElement('div');
        card.className = `device-card ${deviceClass}`;
        card.innerHTML = `
            ${statusBadge}
            <div class="device-header">
                <div class="device-icon">${deviceIcon}</div>
                <div>
                    <div class="device-name">${device.name}</div>
                    <div class="device-ip">${device.ip}</div>
                </div>
            </div>
            <div class="device-details">
                <div class="device-meta">
                    <div class="device-meta-label">Vendor:</div>
                    <div>${device.vendor}</div>
                </div>
                <div class="device-meta">
                    <div class="device-meta-label">Model:</div>
                    <div>${device.model}</div>
                </div>
                <div class="device-meta">
                    <div class="device-meta-label">MAC:</div>
                    <div>${device.mac}</div>
                </div>
                <div class="device-meta">
                    <div class="device-meta-label">Open Ports:</div>
                    <div>${device.openPorts.join(', ')}</div>
                </div>
            </div>
            <div class="buttons mt-3">
                <button class="button is-small is-info view-device-btn" data-ip="${device.ip}">
                    <span class="icon is-small"><i class="fas fa-search"></i></span>
                    <span>Details</span>
                </button>
                <button class="button is-small is-warning" data-ip="${device.ip}">
                    <span class="icon is-small"><i class="fas fa-shield-alt"></i></span>
                    <span>Secure</span>
                </button>
            </div>
        `;
        devicesContainer.appendChild(card);
    });

    // Add devices to exploit device select
    const exploitDeviceSelect = document.getElementById('exploit-device-select');
    exploitDeviceSelect.innerHTML = '<option value="">Select a device</option>';
    
    devices.forEach(device => {
        const option = document.createElement('option');
        option.value = device.ip;
        option.textContent = `${device.name} (${device.ip})`;
        exploitDeviceSelect.appendChild(option);
    });

    // Add exploit tests
    const exploitTestsContainer = document.getElementById('exploit-tests-container');
    const exploitTests = [
        { id: 'CVE-2017-8225', name: 'IP Camera Authentication Bypass', description: 'Tests for auth bypass in multiple IP camera vendors', severity: 'High' },
        { id: 'DWST-COMMAND-INJECTION', name: 'D-Link Command Injection', description: 'Command injection vulnerability in D-Link routers', severity: 'Critical' },
        { id: 'WEAK-TLS', name: 'TLS/SSL Weakness Scanner', description: 'Checks for weak TLS/SSL configurations', severity: 'Medium' },
        { id: 'UPnP-EXPLOIT', name: 'UPnP Vulnerability Scanner', description: 'Tests for vulnerable UPnP implementations', severity: 'Medium' }
    ];
    
    exploitTestsContainer.innerHTML = '';
    exploitTests.forEach(test => {
        const severityClass = getSeverityClass(test.severity);
        
        const testItem = document.createElement('div');
        testItem.className = 'exploit-test-item';
        testItem.innerHTML = `
            <div class="exploit-test-checkbox">
                <input type="checkbox" id="test-${test.id}" class="exploit-test-check" value="${test.id}">
            </div>
            <div class="exploit-test-info">
                <div class="exploit-test-name">${test.name}</div>
                <div class="exploit-test-description">${test.description}</div>
                <div class="tag ${severityClass} is-light mt-2">${test.severity}</div>
            </div>
        `;
        exploitTestsContainer.appendChild(testItem);
    });

    // Add vulnerability table data
    const vulnTable = document.querySelector('#vulnerabilities-table tbody');
    vulnTable.innerHTML = '';
    
    const vulnerabilities = [
        { cve: 'CVE-2017-7921', name: 'Hikvision IP Camera Auth Bypass', device: 'Hikvision Camera (192.168.1.108)', severity: 'High', description: 'Authentication bypass vulnerability allowing unauthenticated access', remediation: 'Update firmware to version V5.4.5 build 170124 or later' },
        { cve: 'CVE-2019-11477', name: 'TCP SACK Panic', device: 'TP-Link Router (192.168.1.1)', severity: 'Medium', description: 'Linux kernel vulnerability that can lead to denial of service', remediation: 'Update router firmware to latest version' },
        { cve: 'CVE-2018-10088', name: 'D-Link Router Command Injection', device: 'D-Link Router (192.168.1.120)', severity: 'Critical', description: 'Command injection vulnerability via the web interface', remediation: 'Update to the latest firmware' },
        { cve: 'CVE-2019-12780', name: 'Smart TV Information Leakage', device: 'Samsung TV (192.168.1.135)', severity: 'Low', description: 'Exposes sensitive user information through API', remediation: 'Update TV firmware' }
    ];
    
    vulnerabilities.forEach(vuln => {
        const severityClass = getSeverityClass(vuln.severity);
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${vuln.cve}</td>
            <td>${vuln.name}</td>
            <td>${vuln.device}</td>
            <td><span class="tag ${severityClass}">${vuln.severity}</span></td>
            <td>${vuln.description}</td>
            <td>${vuln.remediation}</td>
        `;
        vulnTable.appendChild(row);
    });

    // Setup scan history
    const scanHistoryTable = document.querySelector('#scan-history-table tbody');
    scanHistoryTable.innerHTML = '';
    
    const scanHistory = [
        { date: '2025-05-16 19:30:45', devices: 24, vulnerabilities: 12 },
        { date: '2025-05-15 14:22:10', devices: 23, vulnerabilities: 14 },
        { date: '2025-05-14 09:15:32', devices: 21, vulnerabilities: 10 }
    ];
    
    scanHistory.forEach(scan => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${scan.date}</td>
            <td>${scan.devices}</td>
            <td>${scan.vulnerabilities}</td>
            <td>
                <button class="button is-small is-info">
                    <span class="icon is-small"><i class="fas fa-download"></i></span>
                    <span>Download</span>
                </button>
            </td>
        `;
        scanHistoryTable.appendChild(row);
    });

    // Add event listeners to all device view buttons
    document.querySelectorAll('.view-device-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            const device = devices.find(d => d.ip === ip);
            if (device) {
                showDeviceDetails(device);
            }
        });
    });
}

// Initialize charts
function initializeCharts() {
    // Device Types Chart
    const deviceTypesCtx = document.getElementById('deviceTypesChart').getContext('2d');
    const deviceTypesChart = new Chart(deviceTypesCtx, {
        type: 'doughnut',
        data: {
            labels: ['Cameras', 'Routers', 'Smart Speakers', 'Thermostats', 'Smart TVs', 'Other'],
            datasets: [{
                data: [6, 3, 4, 2, 3, 6],
                backgroundColor: [
                    '#3298dc', // blue
                    '#48c774', // green
                    '#ffdd57', // yellow
                    '#f14668', // red
                    '#9253a1', // purple
                    '#d3d3d3'  // gray
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });

    // Vulnerability Severity Chart
    const vulnSeverityCtx = document.getElementById('vulnerabilitySeverityChart').getContext('2d');
    const vulnSeverityChart = new Chart(vulnSeverityCtx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                label: 'Number of Vulnerabilities',
                data: [3, 6, 8, 5],
                backgroundColor: [
                    '#f14668', // red
                    '#ffdd57', // yellow
                    '#3298dc', // blue
                    '#48c774'  // green
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

// Setup event listeners
function setupEventListeners() {
    // Start scan button
    document.getElementById('startScanBtn').addEventListener('click', function() {
        const statusBar = document.getElementById('statusBar');
        statusBar.className = 'notification is-warning';
        statusBar.innerHTML = `
            <span class="icon">
                <i class="fas fa-spinner fa-pulse"></i>
            </span>
            <span>Scan in progress... This may take a few minutes.</span>
        `;

        // Simulate scan completion after 3 seconds
        setTimeout(() => {
            statusBar.className = 'notification is-success';
            statusBar.innerHTML = `
                <span class="icon">
                    <i class="fas fa-check-circle"></i>
                </span>
                <span>Scan completed successfully. Found 24 devices, 7 with vulnerabilities.</span>
            `;
        }, 3000);
    });

    // Export button
    document.getElementById('exportBtn').addEventListener('click', function() {
        window.location.href = '/api/export/json';
    });

    // Exploit device select
    document.getElementById('exploit-device-select').addEventListener('change', function() {
        const runButton = document.getElementById('run-exploits-btn');
        if (this.value) {
            runButton.removeAttribute('disabled');
        } else {
            runButton.setAttribute('disabled', 'disabled');
        }
    });

    // Run exploits button
    document.getElementById('run-exploits-btn').addEventListener('click', function() {
        const selectedTests = document.querySelectorAll('.exploit-test-check:checked');
        if (selectedTests.length === 0) {
            alert('Please select at least one exploit test');
            return;
        }

        const deviceIp = document.getElementById('exploit-device-select').value;
        const resultsContainer = document.getElementById('exploit-results-container');
        
        resultsContainer.innerHTML = `
            <div class="notification is-info">
                <span class="icon">
                    <i class="fas fa-spinner fa-pulse"></i>
                </span>
                <span>Running exploit tests against ${deviceIp}...</span>
            </div>
        `;

        // Simulate test completion after 2 seconds
        setTimeout(() => {
            resultsContainer.innerHTML = '';
            
            // Random results for demo
            selectedTests.forEach(test => {
                const testId = test.value;
                const testName = document.querySelector(`label[for="test-${testId}"]`)?.textContent || testId;
                const successful = Math.random() > 0.7; // 30% chance of successful exploit
                
                const resultItem = document.createElement('div');
                resultItem.className = `exploit-result-item ${successful ? 'is-success' : 'is-failure'}`;
                
                resultItem.innerHTML = `
                    <h3 class="is-size-6 has-text-weight-bold">${testName}</h3>
                    <p>${successful ? 'Exploit succeeded!' : 'Exploit failed'}</p>
                    <p class="is-size-7 mt-2">${successful ? 'Device is vulnerable' : 'Device appears to be secure against this exploit'}</p>
                `;
                
                resultsContainer.appendChild(resultItem);
            });
        }, 2000);
    });

    // Settings form
    document.getElementById('settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        alert('Settings saved');
    });

    // Export buttons
    document.getElementById('export-json-btn').addEventListener('click', function() {
        window.location.href = '/api/export/json';
    });
    
    document.getElementById('export-csv-btn').addEventListener('click', function() {
        window.location.href = '/api/export/csv';
    });
    
    document.getElementById('export-report-btn').addEventListener('click', function() {
        window.location.href = '/api/export/report';
    });
}

// Helper functions
function updateStats(stats) {
    document.getElementById('total-devices').textContent = stats.total_devices;
    document.getElementById('identified-devices').textContent = stats.identified_devices;
    document.getElementById('vulnerable-devices').textContent = stats.vulnerable_devices;
    document.getElementById('default-creds-devices').textContent = stats.default_creds_devices;
}

function showDeviceDetails(device) {
    const modal = document.getElementById('device-details-modal');
    const content = document.getElementById('device-details-content');
    
    // Generate vulnerability list
    let vulnList = '';
    if (device.vulnerabilities > 0) {
        vulnList = `
            <div class="content">
                <h3 class="is-size-5">Vulnerabilities</h3>
                <ul>
                    ${device.vulnerabilityDetails.map(v => `<li><strong>${v.name}</strong> - ${v.description}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    // Generate open ports list
    const portsList = device.openPorts.map(p => `<li>${p}</li>`).join('');
    
    content.innerHTML = `
        <div class="columns">
            <div class="column is-4">
                <div class="has-text-centered mb-4">
                    <span class="icon is-large">
                        <i class="fas fa-${getDeviceIcon(device.type)} fa-3x"></i>
                    </span>
                    <h2 class="title is-4 mt-2">${device.name}</h2>
                    <p class="subtitle is-6">${device.vendor} ${device.model}</p>
                </div>
                <div class="content">
                    <p><strong>IP Address:</strong> ${device.ip}</p>
                    <p><strong>MAC Address:</strong> ${device.mac}</p>
                    <p><strong>Firmware:</strong> ${device.firmware || 'Unknown'}</p>
                    <p><strong>Last Seen:</strong> ${device.lastSeen || 'Now'}</p>
                </div>
            </div>
            <div class="column is-8">
                <div class="content">
                    <h3 class="is-size-5">Open Ports</h3>
                    <ul>
                        ${portsList}
                    </ul>
                </div>
                ${vulnList}
                ${device.defaultCreds ? `
                <div class="notification is-warning">
                    <p><strong>Default Credentials Detected!</strong></p>
                    <p>This device is using default credentials, which is a serious security risk.</p>
                </div>` : ''}
            </div>
        </div>
    `;
    
    modal.classList.add('is-active');
}

function getDeviceIcon(type) {
    switch (type) {
        case 'camera': return 'video';
        case 'router': return 'network-wired';
        case 'speaker': return 'volume-up';
        case 'thermostat': return 'temperature-high';
        case 'tv': return 'tv';
        case 'light': return 'lightbulb';
        default: return 'question-circle';
    }
}

function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'is-danger';
        case 'high': return 'is-warning';
        case 'medium': return 'is-info';
        case 'low': return 'is-success';
        default: return 'is-light';
    }
}

// Generate sample devices
function generateSampleDevices() {
    return [
        {
            name: 'Hikvision Camera',
            ip: '192.168.1.108',
            mac: '00:11:22:33:44:55',
            vendor: 'Hikvision',
            model: 'DS-2CD2142FWD-I',
            type: 'camera',
            openPorts: ['80/HTTP', '554/RTSP'],
            vulnerabilities: 2,
            defaultCreds: true,
            vulnerabilityDetails: [
                { name: 'CVE-2017-7921', description: 'Authentication bypass vulnerability' },
                { name: 'Default Credentials', description: 'Using default password (admin/12345)' }
            ]
        },
        {
            name: 'TP-Link Router',
            ip: '192.168.1.1',
            mac: 'AA:BB:CC:DD:EE:FF',
            vendor: 'TP-Link',
            model: 'Archer C7',
            type: 'router',
            openPorts: ['80/HTTP', '443/HTTPS', '53/DNS'],
            vulnerabilities: 1,
            defaultCreds: false,
            vulnerabilityDetails: [
                { name: 'CVE-2019-7406', description: 'Remote code execution in HTTP daemon' }
            ]
        },
        {
            name: 'Nest Thermostat',
            ip: '192.168.1.120',
            mac: '11:22:33:44:55:66',
            vendor: 'Google',
            model: 'Nest Learning Thermostat',
            type: 'thermostat',
            openPorts: ['80/HTTP', '443/HTTPS', '8080/HTTP-ALT'],
            vulnerabilities: 0,
            defaultCreds: false
        },
        {
            name: 'Echo Dot',
            ip: '192.168.1.130',
            mac: '22:33:44:55:66:77',
            vendor: 'Amazon',
            model: 'Echo Dot (3rd Gen)',
            type: 'speaker',
            openPorts: ['80/HTTP', '5000/UPnP'],
            vulnerabilities: 0,
            defaultCreds: false
        },
        {
            name: 'Samsung TV',
            ip: '192.168.1.135',
            mac: '33:44:55:66:77:88',
            vendor: 'Samsung',
            model: 'UN55MU8000',
            type: 'tv',
            openPorts: ['80/HTTP', '8001/HTTP-ALT', '9090/WebSocket'],
            vulnerabilities: 1,
            defaultCreds: false,
            vulnerabilityDetails: [
                { name: 'CVE-2019-12780', description: 'Information leakage vulnerability' }
            ]
        },
        {
            name: 'Dahua IP Camera',
            ip: '192.168.1.110',
            mac: '44:55:66:77:88:99',
            vendor: 'Dahua',
            model: 'IPC-HDW5231R-ZE',
            type: 'camera',
            openPorts: ['80/HTTP', '554/RTSP', '37777/Custom'],
            vulnerabilities: 2,
            defaultCreds: true,
            vulnerabilityDetails: [
                { name: 'CVE-2021-33044', description: 'Authentication bypass vulnerability' },
                { name: 'Default Credentials', description: 'Using default password (admin/admin)' }
            ]
        }
    ];
}
