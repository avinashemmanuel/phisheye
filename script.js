document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const resultBox = document.getElementById('result');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const scanHistorySection = document.getElementById('scanHistory');
    const historyList = document.getElementById('historyList');
    const clearHistoryButton = document.getElementById('clearHistoryButton');

    // Array to store scan history
    let scanHistory = [];
    const MAX_HISTORY_ITEMS = 10; // Limit history to last 10 scans

    // History-Functions

    //Load history from localStorage
    function loadHistory() {
        const storedHistory = localStorage.getItem('urlScanHistory');
        if (storedHistory) {
            scanHistory = JSON.parse(storedHistory);
        }
        renderHistory();
    }

    // Save history to localStorage
    function saveHistory() {
        localStorage.setItem('urlScanHistory', JSON.stringify(scanHistory));
        renderHistory();
    }

    // Add a new item to history
    function addHistoryItem(url, status, confidence) {
        const timestamp = new Date().toLocaleString();
        scanHistory.unshift({ url, status, confidence, timestamp }); // Add to the beginning

        // Keep only the latest MAX_HISTORY_ITEMS
        if (scanHistory.length > MAX_HISTORY_ITEMS) {
            scanHistory = scanHistory.slice(0, MAX_HISTORY_ITEMS);
        }
        saveHistory();
    }

    // Render history to the DOM
    function renderHistory() {
        historyList.innerHTML = ''; // Clear existing list

        if (scanHistory.length === 0) {
            scanHistorySection.classList.add('history-hidden'); // Hide section if no history
            return;
        } else {
            scanHistorySection.classList.remove('history-hidden'); // Show section if history exists
        }

        scanHistory.forEach(item => {
            const listItem = document.createElement('li');

            const urlSpan = document.createElement('span');
            urlSpan.classList.add('history-url');
            urlSpan.textContent = item.url;
            listItem.appendChild(urlSpan);

            const statusSpan = document.createElement('span');
            statusSpan.classList.add('history-status', item.status); // Add status class for styling
            statusSpan.textContent = item.status.toUpperCase();
            listItem.appendChild(statusSpan);

            historyList.appendChild(listItem);
        });
    }

    // Clear all history
    clearHistoryButton.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear the scan history?')) {
            scanHistory = [];
            saveHistory();
        }
    });

    // Function to update the result box with status and styling
    // CORRECTED: messageOverride now has a default value of null
    function updateResult(status, confidence = null, messageOverride = null) {
        loadingSpinner.classList.add('spinner-hidden'); // Hide spinner when results are ready
        resultBox.className = 'result-box'; // Reset classes
        let message = '';

        if (messageOverride) { // Use override if provided
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
        } else if (status === 'invalid') { // This is for backend errors or general issues
            resultBox.classList.add('suspicious'); // Use suspicious for general errors
            message = 'Error: Could not determine URL safety.';
        } else if (status === 'validation-error') { // New status for client-side validation
            resultBox.classList.add('suspicious'); // Use suspicious for validation errors
            message = 'Please enter a valid URL (e.g., https://example.com).';
        } else {
            message = 'An unexpected error occurred.';
        }

        if (confidence !== null && status !== 'invalid' && status !== 'validation-error') {
            message += ` (Confidence: ${(confidence * 100).toFixed(2)}%)`;
        }

        resultBox.innerHTML = `<p>${message}</p>`;

        // Add to history if it's a successful scan from backend
        if (['safe', 'suspicious', 'dangerous'].includes(status)) {
            addHistoryItem(urlInput.value.trim(), status, confidence);
        }
    }

    // Event listener for the scan button
    scanButton.addEventListener('click', async () => {
        const url = urlInput.value.trim();

        // --- Enhanced Client-side URL Validation ---
        if (!url) {
            updateResult('validation-error', null, 'URL cannot be empty. Please enter a URL.');
            return;
        }

        // More robust regex for URL validation
        const urlRegex = /^(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/[a-zA-Z0-9]+\.[^\s]{2,}|[a-zA-Z0-9]+\.[^\s]{2,})$/i;

        if (!urlRegex.test(url)) {
            updateResult('validation-error'); // This call is now fine because messageOverride defaults to null
            return;
        }

        // ... (rest of your script.js remains the same) ...

        // --- Show loading state and spinner ---
        resultBox.className = 'result-box';
        resultBox.innerHTML = '<p>Scanning...</p>';
        loadingSpinner.classList.remove('spinner-hidden');

        try {
            const response = await fetch('http://127.0.0.1:8000/scan_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            if (!response.ok) {
                throw new Error(`HTTP Error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log(data);

            updateResult(data.status, data.confidence);

        } catch (error) {
            console.error('Network error scanning URL:', error);
            loadingSpinner.classList.add('spinner-hidden');
            resultBox.className = 'result-box dangerous';
            resultBox.innerHTML = `<p>Error connecting to the scanner: ${error.message}. Make sure the backend is running.</p>`;
        }
    });

    urlInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            scanButton.click();
        }
    });

    // --- Initial Load ---
    loadHistory();
});