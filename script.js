document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const resultBox = document.getElementById('result');
    const loadingSpinner = document.getElementById('loadingSpinner');

    // Function to update the result box with status and styling
    function updateResult(status, confidence = null) {
        loadingSpinner.classList.add('spinner-hidden');
        resultBox.className = 'result-box'; // Reset classes
        let message = '';

        if (status === 'safe') {
            resultBox.classList.add('safe');
            message = 'This URL appears to be SAFE.';
        } else if (status === 'suspicious') {
            resultBox.classList.add('suspicious');
            message = 'This URL is SUSPICIOUS. Exercise caution.';
        } else if (status === 'dangerous') {
            resultBox.classList.add('dangerous');
            message = 'This URL is DANGEROUS! Do NOT Visit.';
        } else if (status === 'invalid') {
            resultBox.classList.add('suspicious');
            message = 'Please enter a valid URL.';
        } else {
            message = 'Error: Could not determine URL safety.';
        }

        // --- FIX 1: Change statue to status ---
        // --- FIX 2: Use backticks for string interpolation ---
        if (confidence !== null && status !== 'invalid') {
            message += ` (Confidence: ${(confidence * 100).toFixed(2)}%)`;
        }

        // --- FIX 3: Use backticks for string interpolation ---
        resultBox.innerHTML = `<p>${message}</p>`;
    }

    // Event listener for the scan button
    scanButton.addEventListener('click', async () => {
        const url = urlInput.value.trim();

        if (!url) {
            updateResult('invalid');
            return;
        }

        // Basic URL validation (can be more robust)
        try {
            new URL(url); // Throws an error if not a valid URL
        } catch (e) {
            updateResult('invalid');
            return;
        }

        // Show a loading state
        resultBox.className = 'result-box'; // Reset classes
        resultBox.innerHTML = '<p>Scanning...</p>'; // This one is fine with single quotes as no interpolation
        loadingSpinner.classList.remove('spinner-hidden');

        try {
            // Make a POST request to my FastAPI backend
            const response = await fetch('http://127.0.0.1:8000/scan_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            if (!response.ok) {
                // --- FIX 4: Use backticks for string interpolation ---
                throw new Error(`HTTP Error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log(data); // Log the full response for debugging

            // Update the result box based on the backend's response
            updateResult(data.status, data.confidence);

        } catch (error) {
            console.error('Error scanning URL:', error);
            loadingSpinner.classList.add('spinner-hidden');
            resultBox.className = 'result-box dangerous'; // Use dangerous styling for network errors
            // --- FIX 5: Use backticks for string interpolation ---
            resultBox.innerHTML = `<p>Error connecting to the scanner: ${error.message}. Make sure the backend is running.</p>`;
        }
    });

    // Allow pressing Enter key to trigger the Scan button
    urlInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            scanButton.click();
        }
    });
});