document.addEventListener('DOMContentLoaded', async () => {
    const currentUrlElement = document.getElementById('currentUrl');
    const scanButton = document.getElementById('scanButton');
    const resultDiv = document.getElementById('result');
    const resultText = document.getElementById('resultText');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const detailedResultsContainer = document.getElementById('detailedResults');
    const detailsList = document.getElementById('detailsList');

    let activeTabUrl = '';

    // Function to get the current tab's URL
    async function getCurrentTabUrl() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            activeTabUrl = tab.url;
            currentUrlElement.textContent = activeTabUrl;
            scanButton.disabled = false; // Enable scan button once URL is loaded
        } else {
            currentUrlElement.textContent = 'Could not get current URL';
            scanButton.disabled = true;
        }
    }

    // Helper function to format feature names (copied from webapp)
    function formatFeatureName(name) {
        return name
            .replace(/_/g, ' ')
            .replace(/\b\w/g, char => char.toUpperCase());
    }

    // Helper function to render detailed features (copied from webapp)
    function renderDetailedFeatures(details) {
        detailsList.innerHTML = ''; // Clear previous details
        if (details && Object.keys(details).length > 0) {
            detailedResultsContainer.classList.remove('detailed-results-hidden');
            for (const key in details) {
                if (details.hasOwnProperty(key)) {
                    const dt = document.createElement('dt');
                    dt.textContent = formatFeatureName(key);
                    detailsList.appendChild(dt);

                    const dd = document.createElement('dd');
                    dd.textContent = details[key];
                    detailsList.appendChild[dd];
                }
            }
        } else {
            detailedResultsContainer.classList.add('detailed-results-hidden');
        }
    }

    // Function to update the result box (adapted from webapp)
    function updateResultDisplay(status, confidence = null, messageOverride = null, details = null) {
        loadingSpinner.classList.add('spinner-hidden'); // Hide spinner
        resultDiv.classList.remove('hidden'); // Show result box
        resultDiv.className = 'result-box'; // Reset classes

        let message = '';

        if (messageOverride) {
            message = messageOverride;
        } else if (status === 'safe') {
            resultDiv.classList.add('safe');
            message = 'This URL appears to be SAFE.';
        } else if (status === 'suspicious') {
            resultDiv.classList.add('suspicious');
            message = 'This URL is SUSPICIOUS. Exercise caution.';
        } else if (status === 'dangerous') {
            resultDiv.classList.add('dangerous');
            message = 'This URL is DANGEROUS! Do NOT Visit.';
        } else if (status === 'validation-error') {
            resultDiv.classList.add('suspicious');
            message = 'Please enter a valid URL (e.g., https://example.com).';
        } else if (status === 'error') {
            resultDiv.classList.add('dangerous');
            message = `Backend Error: ${messageOverride || 'An error occurred during scanning.'}`;
        } else {
            message = 'An unexpected status was received from the scanner.';
        }

        if (confidence !== null && status !== 'validation-error' && status !== 'error') {
            message += ` (Confidence: ${(confidence * 100).toFixed(2)}%)`;
        }

        resultText.textContent = message;

        // Render detailed features if available
        if (details) {
            renderDetailedFeatures(details);
        } else {
            detailedResultsContainer.classList.add('detailed-results-hidden');
            detailsList.innerHTML = '';
        }
    }

    // Scan function
    scanButton.addEventListener('click', async () => {
        if (!activeTabUrl) {
            updateResultDisplay('validation-error', null, 'No URL to scan.');
            return;
        }

        // Reset UI and show loading
        resultDiv.classList.add('hidden');
        detailedResultsContainer.classList.add('detailed-results-hidden');
        loadingSpinner.classList.remove('spinner-hidden');
        resultText.textContent = '';
        detailsList.innerHTML = '';
        
        try {
            const response = await fetch('http://127.0.0.1:8000/scan_url', {    // IMPORTANT: Ensure your backend is running
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: activeTabUrl }),
            });
            const data = await response.json();
            
            if (!response.ok || data.status === 'error') {
                throw new Error(data.message || 'HTTP Error! status: ${response.status}');
            }

            updateResultDisplay(data.status, data.confidence, null, data.detailed_features);

        } catch (error) {
            console.error('PhishEye Extension Error:', error);
            updateResultDisplay('error', null, 'Failed to connect to the scanner backend (${error.message})');
        } finally {
            loadingSpinner.classList.add('spinner-hidden'); // Ensure spinner is hidden
        }
    });

    // Initialize by getting the current tab's URL
    getCurrentTabUrl();
});