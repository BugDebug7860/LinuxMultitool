// Main JavaScript for Multi-Tool

document.addEventListener('DOMContentLoaded', function() {
    // Enable all tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Target input URL/domain formatting
    const targetInput = document.getElementById('target');
    if (targetInput) {
        targetInput.addEventListener('blur', function() {
            let value = this.value.trim();
            
            // If the input doesn't start with http:// or https:// and doesn't look like an IP,
            // assume it's a domain and add https://
            if (value && !value.match(/^https?:\/\//) && !value.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}$/)) {
                if (!value.match(/^www\./)) {
                    // If it doesn't start with www., assume the user wants https://
                    this.value = 'https://' + value;
                } else {
                    // If it starts with www., also add https://
                    this.value = 'https://' + value;
                }
            }
        });
    }

    // Tool selection validation
    const analyzeForm = document.getElementById('quickAnalyzeForm');
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', function(e) {
            const toolSelect = document.getElementById('tool');
            const targetInput = document.getElementById('target');
            
            if (toolSelect.value === "") {
                e.preventDefault();
                alert('Please select a tool to use.');
                return false;
            }
            
            if (targetInput.value.trim() === "") {
                e.preventDefault();
                alert('Please enter a domain or URL to analyze.');
                return false;
            }
            
            return true;
        });
    }
    
    // Add active class to current nav link
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPath) {
            link.classList.add('active');
        }
    });
});