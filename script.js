document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const resultBox = document.getElementById('result');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const scanHistorySection = document.getElementById('scanHistory');
    const historyList = document.getElementById('historyList');
    const clearHistoryButton = document.getElementById('clearHistoryButton');
    const detailedResultsDiv = document.getElementById('detailedResults'); // NEW: Get detailed results div
    const detailsList = document.getElementById('detailsList');           // NEW: Get UL for details

    let scanHistory = [];
    const MAX_HISTORY_ITEMS = 10;

    // --- History Functions (No changes needed here, but keeping for context) ---

    function loadHistory() {
        const storedHistory = localStorage.getItem('urlScanHistory');
        if (storedHistory) {
            scanHistory = JSON.parse(storedHistory);
        }
        renderHistory();
    }

    function saveHistory() {
        localStorage.setItem('urlScanHistory', JSON.stringify(scanHistory));
        renderHistory();
    }

    function addHistoryItem(url, status, confidence) {
        const timestamp = new Date().toLocaleString();
        scanHistory.unshift({ url, status, confidence, timestamp });

        if (scanHistory.length > MAX_HISTORY_ITEMS) {
            scanHistory = scanHistory.slice(0, MAX_HISTORY_ITEMS);
        }
        saveHistory();
    }

    function renderHistory() {
        historyList.innerHTML = '';

        if (scanHistory.length === 0) {
            scanHistorySection.classList.add('history-hidden');
            return;
        } else {
            scanHistorySection.classList.remove('history-hidden');
        }

        scanHistory.forEach(item => {
            const listItem = document.createElement('li');

            const urlSpan = document.createElement('span');
            urlSpan.classList.add('history-url');
            urlSpan.textContent = item.url;
            listItem.appendChild(urlSpan);

            const statusSpan = document.createElement('span');
            statusSpan.classList.add('history-status', item.status);
            statusSpan.textContent = item.status.toUpperCase();
            listItem.appendChild(statusSpan);

            historyList.appendChild(listItem);
        });
    }

    clearHistoryButton.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all scan history?')) {
            scanHistory = [];
            saveHistory();
        }
    });

    function renderDetailedFeatures(details) {
        detailsList.innerHTML = ''; // Clear previous details

        if (details && Object.keys(details).length > 0) {
            detailedResultsDiv.classList.remove('detailed-results-hidden'); // Show the container
            for (const key in details) {
                if (details.hasOwnProperty(key)) {
                    const dt = document.createElement('dt');
                    dt.textContent = formatFeatureName(key); // Format key for display
                    detailsList.appendChild(dt);

                    const dd = document.createElement('dd');
                    dd.textContent = details[key];
                    detailsList.appendChild(dd);
                }
            }
        } else {
            detailedResultsDiv.classList.add('detailed-results-hidden'); // Hide the container
        }
    }

    // Helper function to format feature names (e.g., "url_length" -> "URL Length")
    function formatFeatureName(name) {
        return name
            .replace(/_/g, ' ') // Replace underscores with spaces
            .replace(/\b\w/g, char => char.toUpperCase()); // Capitalize first letter of each word
    }


    // Function to update the result box with status and styling (MODIFIED)
    function updateResult(status, confidence = null, messageOverride = null, details = null) {
        loadingSpinner.classList.add('spinner-hidden');
        resultBox.className = 'result-box'; // Reset classes

        let message = '';

        // Always ensure the main message paragraph exists
        let mainMessageP = resultBox.querySelector('p');
        if (!mainMessageP) {
            mainMessageP = document.createElement('p');
            resultBox.prepend(mainMessageP);
        }

        // Handle detailed results visibility and rendering
        if (details && Object.keys(details).length > 0) {
            detailedResultsDiv.classList.remove('detailed-results-hidden');
            renderDetailedFeatures(details);
        } else {
            detailedResultsDiv.classList.add('detailed-results-hidden');
            detailsList.innerHTML = ''; // Clear any old details
        }


        if (messageOverride) {
            message = messageOverride;
        } else if (status === 'safe') {
            resultBox.classList.add('safe');
            message = 'This URL appears to be SAFE.';
        } else if (status === 'suspicious') {
            resultBox.classList.add('suspicious');
            message = 'This URL is SUSPICIOUS. Exercise caution.';
        } else if (status === 'dangerous') {
            resultBox.classList.add('dangerous');
            message = 'This URL is DANGEROUS! Do NOT Visit.';
        } else if (status === 'validation-error') {
            resultBox.classList.add('suspicious'); // Use suspicious for client-side validation errors
            message = 'Please enter a valid URL (e.g., https://example.com).';
        } else if (status === 'error') {
            resultBox.classList.add('dangerous'); // Use dangerous for backend errors
            message = `Backend Error: ${messageOverride || 'An error occurred during scanning.'}`;
        }
        else {
            message = 'An unexpected status was received from the scanner.';
        }

        if (confidence !== null && status !== 'validation-error' && status !== 'error') {
            message += ` (Confidence: ${(confidence * 100).toFixed(2)}%)`;
        }

        mainMessageP.textContent = message; // Update the main message


        // Add to history if it's a successful scan from backend
        if (['safe', 'suspicious', 'dangerous'].includes(status)) {
            addHistoryItem(urlInput.value.trim(), status, confidence);
        }
    }

    // Event listener for the scan button (MODIFIED)
    scanButton.addEventListener('click', async () => {
        const url = urlInput.value.trim();

        if (!url) {
            updateResult('validation-error', null, 'URL cannot be empty. Please enter a URL.');
            return;
        }

        // Clear previous detailed results when a new scan starts
        detailedResultsDiv.classList.add('detailed-results-hidden');
        detailsList.innerHTML = '';

        // A more robust URL regex for client-side validation
        // This regex is quite strict, you might want to simplify it if it's too restrictive.
        // For example, just checking for http/https prefix might be enough for a quick client-side check.
        const urlRegex = /^(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/[a-zA-Z0-9]+\.[^\s]{2,}|[a-zA-Z0-9]+\.[^\s]{2,})$/i;

        if (!urlRegex.test(url)) {
            updateResult('validation-error');
            return;
        }

        resultBox.className = 'result-box'; // Reset classes
        // Ensure the main message paragraph is present and updated
        let mainMessageP = resultBox.querySelector('p');
        if (!mainMessageP) {
            mainMessageP = document.createElement('p');
            resultBox.prepend(mainMessageP);
        }
        mainMessageP.textContent = 'Scanning...';

        loadingSpinner.classList.remove('spinner-hidden');

        try {
            // Ensure this matches your FastAPI backend's address and port
            const response = await fetch('http://127.0.0.1:8000/scan_url', { // <-- Check this port!
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            if (!response.ok) {
                // If the backend returns an error status (e.g., 400, 500),
                // we should still try to parse the JSON for a detailed message.
                const errorData = await response.json();
                throw new Error(errorData.detail || `HTTP Error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log(data);

            if (data.status === 'error') {
                // This handles the specific 'error' status returned by your FastAPI's
                // client-side URL validation (e.g., if the regex in main.py fails)
                updateResult('error', null, data.message || 'An internal error occurred in the scanner backend.');
            } else {
                // Corrected: Use data.detailed_features as returned by main.py
                updateResult(data.status, data.confidence, null, data.detailed_features);
            }

        } catch (error) {
            console.error('Network Error scanning URL:', error);
            loadingSpinner.classList.add('spinner-hidden');
            resultBox.className = 'result-box dangerous';
            // Ensure the main message paragraph is present and updated
            let mainMessageP = resultBox.querySelector('p');
            if (!mainMessageP) {
                mainMessageP = document.createElement('p');
                resultBox.prepend(mainMessageP);
            }
            mainMessageP.textContent = `Scan Error: ${error.message}. Make sure the backend is running and accessible.`;
        }
    });

    urlInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            scanButton.click();
        }
    });

    loadHistory();
});