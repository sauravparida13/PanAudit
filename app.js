// Main application JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Form validation
    var forms = document.querySelectorAll('.needs-validation');
    Array.prototype.slice.call(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Firewall form enhancements
    initFirewallForm();
    
    // Scan progress tracking
    initScanProgressTracking();
    
    // Report download handling
    initReportDownloads();
});

function initFirewallForm() {
    const testConnectionBtn = document.querySelector('button[name="test_connection"]');
    const firewallForm = document.querySelector('form');
    
    if (testConnectionBtn && firewallForm) {
        testConnectionBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Validate required fields
            const requiredFields = firewallForm.querySelectorAll('input[required]');
            let allValid = true;
            
            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    field.classList.add('is-invalid');
                    allValid = false;
                } else {
                    field.classList.remove('is-invalid');
                }
            });
            
            if (!allValid) {
                showAlert('Please fill in all required fields before testing connection.', 'warning');
                return;
            }
            
            // Show loading state
            const originalText = testConnectionBtn.innerHTML;
            testConnectionBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Testing...';
            testConnectionBtn.disabled = true;
            
            // Simulate connection test (in real implementation, this would be an AJAX call)
            setTimeout(() => {
                testConnectionBtn.innerHTML = originalText;
                testConnectionBtn.disabled = false;
                // The actual test is handled by the server
                firewallForm.submit();
            }, 1000);
        });
    }
}

function initScanProgressTracking() {
    // Check if we're on a scan results page with running scans
    const allBadges = document.querySelectorAll('.badge');
    const runningScans = Array.from(allBadges).filter(el => el.textContent.trim() === 'Running');
    
    if (runningScans.length > 0) {
        // Refresh page every 30 seconds to update scan status
        setTimeout(() => {
            window.location.reload();
        }, 30000);
    }
    
    // If on scan results page, check for auto-refresh
    const scanStatusElements = document.querySelectorAll('[data-scan-id]');
    scanStatusElements.forEach(element => {
        const scanId = element.getAttribute('data-scan-id');
        if (scanId) {
            checkScanStatus(scanId);
        }
    });
}

function checkScanStatus(scanId) {
    fetch(`/api/scan/${scanId}/status`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'running') {
                // Update progress if available
                const progressElement = document.querySelector(`[data-scan-id="${scanId}"] .progress-bar`);
                if (progressElement && data.total_checks > 0) {
                    const completed = data.passed_checks + data.failed_checks + data.skipped_checks;
                    const percentage = (completed / data.total_checks) * 100;
                    progressElement.style.width = `${percentage}%`;
                }
                
                // Check again in 5 seconds
                setTimeout(() => checkScanStatus(scanId), 5000);
            } else if (data.status === 'completed') {
                // Refresh page to show final results
                window.location.reload();
            }
        })
        .catch(error => {
            console.error('Error checking scan status:', error);
        });
}

function initReportDownloads() {
    const downloadButtons = document.querySelectorAll('[data-download-type]');
    
    downloadButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const downloadType = this.getAttribute('data-download-type');
            const scanId = this.getAttribute('data-scan-id');
            
            // Show loading state
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Generating...';
            this.disabled = true;
            
            // Reset button after download
            setTimeout(() => {
                this.innerHTML = originalText;
                this.disabled = false;
            }, 3000);
        });
    });
}

function showAlert(message, type = 'info') {
    const alertContainer = document.querySelector('.container');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    alertContainer.insertBefore(alert, alertContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alert);
        bsAlert.close();
    }, 5000);
}

// Utility functions
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    if (seconds < 60) {
        return `${Math.round(seconds)}s`;
    } else if (seconds < 3600) {
        return `${Math.round(seconds / 60)}m`;
    } else {
        return `${Math.round(seconds / 3600)}h`;
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showAlert('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy: ', err);
        showAlert('Failed to copy to clipboard', 'error');
    });
}

// Export functions for global use
window.CISApp = {
    showAlert,
    formatBytes,
    formatDuration,
    copyToClipboard,
    checkScanStatus
};
