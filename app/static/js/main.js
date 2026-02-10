/**
 * Sentinel Logger - Main JavaScript
 */

// ============================================
// Theme Management (Dark/Light Mode)
// ============================================

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    setTheme(savedTheme);
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    updateThemeIcon(theme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('themeIcon');
    if (icon) {
        if (theme === 'dark') {
            icon.classList.remove('bi-moon-fill');
            icon.classList.add('bi-sun-fill');
        } else {
            icon.classList.remove('bi-sun-fill');
            icon.classList.add('bi-moon-fill');
        }
    }
}

// Initialize theme on page load
initTheme();

// ============================================
// Initialize tooltips and popovers
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize Bootstrap popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

/**
 * Format file size to human readable format
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format date to local string
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @param {function} callback - Optional callback after copy
 */
function copyToClipboard(text, callback) {
    navigator.clipboard.writeText(text).then(function() {
        if (callback) callback(true);
    }).catch(function(err) {
        console.error('Failed to copy:', err);
        if (callback) callback(false);
    });
}

/**
 * Show loading spinner in an element
 * @param {string} elementId - ID of the element
 */
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2 text-muted">Loading...</p>
            </div>
        `;
    }
}

/**
 * Hide loading spinner
 * @param {string} elementId - ID of the element
 * @param {string} content - Content to replace spinner with
 */
function hideLoading(elementId, content) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = content;
    }
}

/**
 * Debounce function for search inputs
 * @param {function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Highlight search term in text
 * @param {string} text - Original text
 * @param {string} term - Search term to highlight
 * @returns {string} Text with highlighted term
 */
function highlightSearchTerm(text, term) {
    if (!term) return text;
    const regex = new RegExp(`(${term})`, 'gi');
    return text.replace(regex, '<span class="search-highlight">$1</span>');
}

/**
 * Filter table rows based on search and filter criteria
 * @param {string} tableId - ID of the table
 * @param {object} filters - Filter criteria
 */
function filterTable(tableId, filters) {
    const table = document.getElementById(tableId);
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(function(row) {
        let visible = true;

        for (const [key, value] of Object.entries(filters)) {
            if (value && value !== '') {
                const cellValue = row.dataset[key] || '';
                if (!cellValue.toLowerCase().includes(value.toLowerCase())) {
                    visible = false;
                    break;
                }
            }
        }

        row.style.display = visible ? '' : 'none';
    });
}

/**
 * Make API call with error handling
 * @param {string} url - API endpoint
 * @param {object} options - Fetch options
 * @returns {Promise} API response
 */
async function apiCall(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

/**
 * Update issue status via API
 * @param {number} issueId - Issue ID
 * @param {string} status - New status
 */
async function updateIssueStatus(issueId, status) {
    try {
        await apiCall(`/api/issues/${issueId}`, {
            method: 'PATCH',
            body: JSON.stringify({ status: status })
        });
        location.reload();
    } catch (error) {
        alert('Failed to update issue status');
    }
}

/**
 * Export data to file
 * @param {string} data - Data to export
 * @param {string} filename - File name
 * @param {string} type - MIME type
 */
function exportToFile(data, filename, type) {
    const blob = new Blob([data], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Keyboard shortcuts
 */
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K for search focus
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[name="q"]');
        if (searchInput) {
            searchInput.focus();
        }
    }

    // Escape to close modals
    if (e.key === 'Escape') {
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(function(modal) {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) {
                bsModal.hide();
            }
        });
    }
});

/**
 * Confirm before delete actions
 * @param {string} message - Confirmation message
 * @returns {boolean} User confirmation
 */
function confirmDelete(message) {
    return confirm(message || 'Are you sure you want to delete this item?');
}

// ============================================
// Global Connection Banner System
// ============================================

/**
 * Show a connection status banner at the top of the page or inside a target container.
 * Types: 'connecting' (blue spinner), 'connected' (green check, auto-hides),
 *        'error' (red warning), 'info' (blue info), 'warning' (yellow)
 * @param {string} type - Banner type
 * @param {string} message - Message to display
 * @param {object} opts - Options: { containerId, autoHide, duration }
 */
function showBanner(type, message, opts = {}) {
    const containerId = opts.containerId || 'globalBanner';
    let banner = document.getElementById(containerId);

    // Create banner element if it doesn't exist
    if (!banner) {
        banner = document.createElement('div');
        banner.id = containerId;
        // Try to insert inside main content area, fallback to body
        const main = document.querySelector('main') || document.querySelector('.container-fluid') || document.body;
        main.prepend(banner);
    }

    const styles = {
        connecting: { bg: '#eff6ff', border: '#bfdbfe', color: '#1e40af', icon: '<span class="spinner-border spinner-border-sm"></span>' },
        connected:  { bg: '#f0fdf4', border: '#bbf7d0', color: '#166534', icon: '<i class="bi bi-check-circle-fill"></i>' },
        error:      { bg: '#fef2f2', border: '#fecaca', color: '#991b1b', icon: '<i class="bi bi-exclamation-triangle-fill"></i>' },
        info:       { bg: '#eff6ff', border: '#bfdbfe', color: '#1e40af', icon: '<i class="bi bi-info-circle-fill"></i>' },
        warning:    { bg: '#fffbeb', border: '#fde68a', color: '#92400e', icon: '<i class="bi bi-exclamation-circle-fill"></i>' },
        success:    { bg: '#f0fdf4', border: '#bbf7d0', color: '#166534', icon: '<i class="bi bi-check-circle-fill"></i>' },
    };

    const s = styles[type] || styles.info;

    banner.style.cssText = `padding: 10px 16px; border-radius: 8px; margin-bottom: 10px; font-size: 0.9rem; display: flex; align-items: center; gap: 8px; background: ${s.bg}; border: 1px solid ${s.border}; color: ${s.color};`;
    banner.innerHTML = `${s.icon} <span>${message}</span>`;

    // Clear any existing auto-hide timer
    if (banner._hideTimer) {
        clearTimeout(banner._hideTimer);
        banner._hideTimer = null;
    }

    // Auto-hide for success/connected banners
    const autoHide = opts.autoHide !== undefined ? opts.autoHide : (type === 'connected' || type === 'success');
    if (autoHide) {
        const duration = opts.duration || 4000;
        banner._hideTimer = setTimeout(() => {
            banner.style.display = 'none';
        }, duration);
    }
}

/**
 * Hide a connection status banner
 * @param {string} containerId - Banner element ID (default: 'globalBanner')
 */
function hideBanner(containerId) {
    const banner = document.getElementById(containerId || 'globalBanner');
    if (banner) {
        if (banner._hideTimer) {
            clearTimeout(banner._hideTimer);
            banner._hideTimer = null;
        }
        banner.style.display = 'none';
    }
}

// Expose functions globally
window.QALogAnalyzer = {
    formatFileSize,
    formatDate,
    copyToClipboard,
    showLoading,
    hideLoading,
    debounce,
    highlightSearchTerm,
    filterTable,
    apiCall,
    updateIssueStatus,
    exportToFile,
    confirmDelete,
    showBanner,
    hideBanner
};
