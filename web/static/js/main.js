/**
 * IoT Scanner Dashboard JavaScript
 * Main functionality for scan, logs, and AI assistant
 */

// Global variables for state management
let logs = [];
let scanHistory = [];

// Document ready handler
document.addEventListener('DOMContentLoaded', function() {
    console.log('IoT Scanner Dashboard initialized');
    
    // Initialize UI components
    initializeUI();
    
    // Load initial data
    loadScanHistory();
    loadInitialLogs();
    
    // Set up event listeners
    setupEventListeners();
    
    // Add initial log
    addLogEntry('INFO', 'System', 'Dashboard initialized');
});

// Initialize UI components
function initializeUI() {
    // Mobile menu toggle
    const burger = document.querySelector('.navbar-burger');
    const menu = document.querySelector('.navbar-menu');
    
    if (burger && menu) {
        burger.addEventListener('click', () => {
            burger.classList.toggle('is-active');
            menu.classList.toggle('is-active');
        });
    }
}

// Set up all event listeners
function setupEventListeners() {
    // Start Scan button
    const startScanBtn = document.getElementById('startScanBtn');
    if (startScanBtn) {
        startScanBtn.addEventListener('click', function() {
            console.log('Start Scan button clicked');
            showScanModal();
        });
    }
    
    // Export button
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            console.log('Export button clicked');
            exportData();
        });
    }
    
    // AI Assistant button
    const assistantBtn = document.querySelector('a[href="/assistant"]');
    if (assistantBtn) {
        assistantBtn.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('AI Assistant button clicked');
            window.open('/assistant', '_blank');
        });
    }
    
    // Log filter controls
    const logLevelFilter = document.getElementById('log-level-filter');
    if (logLevelFilter) {
        logLevelFilter.addEventListener('change', filterLogs);
    }
    
    // Export logs button
    const exportLogsBtn = document.getElementById('export-logs-btn');
    if (exportLogsBtn) {
        exportLogsBtn.addEventListener('click', exportLogs);
    }
}
