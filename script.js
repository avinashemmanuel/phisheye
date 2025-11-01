document .addEventListener('DOMContentLoaded', () => {
    // --- STATE ---
    let scanHistory = [];
    const MAX_HISTORY_ITEMS = 10;
    let currentApiKey = null; // Stores the user's API key
    let currentScanId = null; // Stores the ID of the last scan for feedback

    // --- API ---
    const API_BASE_URL = 'http://127.0.0.1:8000'; // FastAPI backend

    // --- DOM ELEMENTS ---
    // Auth UI
    const authNav = document.getElementById('authNav');
    const showAuthButton = document.getElementById('showAuthButton');
    const userInfo = document.getElementById('userInfo');
    const logoutButton = document.getElementById('logoutButton');

    // Auth Modal
    const authContainer = document.getElementById('authContainer');
    const closeAuthButton = document.getElementById('closeAuthButton');
    const showLoginTab = document.getElementById('showLoginTab');
    const showRegisterTab = document.getElementById('showResgisterTab');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const authMessage = document.getElementById('authMessage');
    const loginEmail = document.getElementById('loginEmail');
    const loginPassword = document.getElementById('loginPassword');
    const registerEmail = document.getElementById('registerEmail');
    const registerPassword = document.getElementById('registerPassword');
    const loginForDetails = document.getElementById('loginForDetails');
    const registerForDetails = document.getElementById('registerForDetails');

    // Scanner UI
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const resultBox = document.getElementById('resultBox');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const resultStatusText = document.getElementById('resultStatusText');
    const confidenceText = document.getElementById('confidenceText');
    const guestMessage = document.getElementById('guestMessage');

    // Detailed Results
    const detailedResultsDiv = document.getElementById('detailedResults');
    const detailsList = document.getElementById('detailsList');

    // Feedback UI
    const feedbackContainer = document.getElementById('feedbackContainer');
    const reportIncorrectButton = document.getElementById('reportIncorrectButton');
    const feedbackThanks = document.getElementById('feedbackThanks');

    // History UI 
    const scanHistorySection = document.getElementById('scanHistory');
    const historyList = document.getElementById('historyList');
    const clearHistoryButton = document.getElementById('clearHistoryButton');

    // --- AUTHENTICATION FUNCTIONS ---

    // Checks localStorage for API key and e-mail, then updates the UI
    function checkLoginState() {
        currentApiKey = localStorage.getItem('phishEyeApiKey');
        const userEmail = localStorage.getItem('phishEyeUserEmail');

        if (currentApiKey && userEmail) {
            // User is logged in
            userInfo.textContent = 'Welcome, ${user_email}';
            userInfo.classList.remove('hidden');
            logoutButton.classList.remove('hidden');
            showAuthButton.classList.add('hidden');
        } else {
            // User is a guest
            userInfo.textContent = '';
            userInfo.classList.add('hidden');
            logoutButton.classList.add('hidden');
            showAuthButton.classList.remove('hidden');
        }
        authContainer.classList.add('hidden'); // Ensure modal is hidden on load
    }


    /**
     * Shows the authentication modal.
     * @param {'login' | 'register'} showTab - Which tab to open by default
     */
    function showAuthModal(showTab = 'login') {
        authContainer.classList.remove('hidden');
        if (showTab === 'login') {
            showLoginTab.click();
        } else {
            showRegisterTab.click();
        }
        authMessage.textContent = '';
    }

    function hideAuthModal() {
        authContainer.classList.add('remove');
    }


    /**
     * Saves user details to localStorage and updates UI after login/register.
     * @param {string} email - User's email
     * @param {string} apiKey - User's new API key
     */
    function handleAuthSuccess(email, apiKey) {
        localStorage.setItem('phishEyeApiKey', apiKey);
        localStorage.setItem('phishEyeUserEmail', email);
        currentApiKey = apiKey;
        checkLoginState();
        hideAuthModal();
        clearResult(); // Clear previous scan result
    }

    // Clears user's details from localStorage and updates UI
    function handleLogout() {
        localStorage.removeItem('phishEyeApiKey');
        localStorage.removeItem('phishEyeUserEmail');
        currentApiKey = null;
        checkLoginState();
        clearResult();
    }

    /**
     * Handles the submit event for both Login and register form
     * @param {Event} e - The form submit event
     * @param {'/login' | '/register'} endpoint - The API endpoint to call
     */
    async function handleAuthFormSubmit(e, endpoint) {
        e.preventDefault();
        authMessage.textContent = '';

        const isRegister = endpoint === '/register';
        const email = isRegister ? registerEmail.value : loginEmail.value;
        const password = isRegister ? registerPassword.value : loginPassword.value;

        if (!email || !password) {
            authMessage.textContent = 'Please fill out all fields.';
            return;
        }

        try {
            const response = await fetch('${API_BASE_URL}${endpoint}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (!response.ok) {
                authMessage.textContent = data.detail || 'An unknown error occured.';
            } else {
                handleAuthSuccess(data.email, data.api_key);
            }
        } catch (error) {
            console.error('Auth Error: ${error}');
            authMessage.textContent = 'Failed to connect to the server.';
        }
    }


    // --- SCANNER & RESULT FUNCITON ---

    // Resets the result box to its default state.
    function clearResult() {
        resultBox.className = 'result-box';
        resultStatusText.textContent = "Enter a URL and click 'Scan' to check its safety!";
        confidenceText.classList.add('hidden');
        guestMessage.classList.add('hidden');
        detailedResultsDiv.classList.add('detailed-results-hidden');
        detailsList.innerHTML ='';
        feedbackContainer.classList.add('hidden');
        feedbackThanks.classList.add('hidden');
        currentScanId = null;
    }

    
    /**
     * Updates the UI with the scan results. Handles tiered display.
     * @param {object} data - The response data from /scan_url
     */
    function updateResult(data) {
        loadingSpinner.classList.add('spinner-hidden');
        resultBox.className = 'result-box'; // Reset

        currentScanId = data.scan_id; // Always store the scan_id

        if (data.status === 'safe') {
            resultBox.classList.add('safe');
            resultStatusText.textContent = 'This URL appears to be SAFE.'
        } else if (data.status === 'suspicious') {
            resultBox.classList.add('suspicious');
            resultStatusText.textContent = 'This URL is SUSPICIOUS. Exercise caution.';
        } else if (data.status === 'dangerous') {
            resultBox.classList.add('dangerous');
            resultStatusText.textContent = 'This URL is DANGEROUS! Do NOT Visit.';
        }

        // --- TIERED CONTENT ---
        if (data.confidence !== undefined) {
            // This is a registered user (full response)
            confidenceText.textContent = '(Confidence: ${(data.confidence * 100).toFixed(2)}%)';
            confidenceText.classList.remove('hidden');
            guestMessage.classList.add('hidden');
            renderDetailedFeatures(data.detailed_features);
            feedbackContainer.classList.remove('hidden');
            feedbackThanks.classList.add('hidden'); // Reset thanks message

            // Add to history (only for registered users)
            addHistoryItem(urlInput.value.trim(), data.status, data.confidence);
        } else {
            // This is a GUEST (limited response)
            confidenceText.classList.add('hidden');
            guestMessage.classList.remove('hidden'); // Show "Login for details"
            detailedResultsDiv.classList.add('detailed-results-hidden');
            feedbackContainer.classList.add('hidden');
        }
    }


    /**
     * Renders the key-value pairs of detailed features
     */
    function renderDetailedFeatures(details) {
        detailsList.innerHTML = '';
        if (details && Object.keys(details).length > 0) {
            detailedResultsDiv.classList.remove('detailed-results-hidden');
            for (const key in details) {
                if (details.hasOwnProperty(key)) {
                    const dt = document.createElement('dt');
                    dt.textContent = formatFeatureName(key);
                    detailsList.appendChild(dt);

                    const dd = document.createElement('dd');
                    dd.textContent = details[key];
                    detailsList.appendChild(dd)
                }
            }
        } else {
            detailedResultsDiv.classList.add('detailed-results-hidden');
        }
    }


    /**
     * Formats feature names for display
     */
    function formatFeatureName(name) {
        return name
            .replace(/_/g, ' ')
            .replace(/\b\w/g, char => char.toUpperCase());
    }


    /**
     * Handles the main scan button click
     */
    async function handleScan() {
        const url = urlInput.value.trim();

        // Client-side validation
        if (!url) {
            alert('Please enter a URL.');
        }
        const urlRegex = /^(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/[a-zA-Z0-9]+\.[^\s]{2,}|[a-zA-Z0-9]+\.[^\s]{2,})$/i;
        if (!urlRegex.test(url)) {
            alert('Please enter a valid URL (e.g., https://example.com).');
            return;
        }

        clearResult(); // Clear previous results
        loadingSpinner.classList.remove('spinner-hidden');
        resultStatusText.textContent = 'Scanning...';

        try {
            const headers = { 'Content-Type': 'application/json' };
            if (currentApiKey) {
                headers['Authorization'] = currentApiKey; // Add API Key if logged in
            }

            const response = await fetch('${API_BASE_URL}/scan_url', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ url: url }),
            });

            const data = await response.json();

            if (!response.ok) {
                // This catches 4xx and 5xx errors from the backend
                throw new Error(data.detail || 'An error occured during scanning.');
            }

            // Handle successful scan (guest or user)
            updateResult(data);
        } catch (error) {
            console.error('Scan Error:', error);
            loadingSpinner.classList.add('spinner-hidden');
            resultBox.className = 'result-box dangerous';
            resultStatusText.textContent = 'Scan Error: ${error.message}';
        }
    }


    /**
     * Sends feedback for an incorrect scan
     * @param {'false_positive' | 'false_negative'} reportType
     */
    async function sendFeedback(reportType) {
        if (!currentApiKey || !currentScanId) {
            alert('You must be logged in to report feedback.');
            return;
        }

        try {
            const response = await fetch('${API_BASE_URL}/report_feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': currentApiKey
                },
                body: JSON.stringify({
                    scan_id: currentScanId,
                    report_type: reportType
                })
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Could not send feedback.');
            }

            // Show "Thanks" message and hide button
            feedbackThanks.classList.remove('hidden');
            reportIncorrectButton.classList.add('hidden'); // Hide to prevent double submit

            // Re-show button after a delay
            setTimeout(() => {
                feedbackThanks.classList.add('hidden');
                reportIncorrectButton.classList.remove('hidden');
            }, 3000);
        } catch (error) {
            console.error('Feedback Error:', error);
            alert('Error: ${error.message}');
        }
    }


    // --- HISTORY FUNCTIONS ---
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
        }
        scanHistorySection.classList.remove('history-hidden');
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


    // --- EVENT LISTENERS ---

    // Auth Modal
    showAuthButton.addEventListener('click', () => showAuthModal('login'));
    closeAuthButton.addEventListener('click', hideAuthModal);
    loginForDetails.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('login'); });
    registerForDetails.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('register'); });
    logoutButton.addEventListener('click', handleLogout);

    // Auth Tabs
    showLoginTab.addEventListener('click', () => {
        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');
        showLoginTab.classList.add('active');
        showRegisterTab.classList.remove('active');
        authMessage.textContent = '';
    });
    showRegisterTab.addEventListener('click', () => {
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
        showLoginTab.classList.remove('active');
        showRegisterTab.classList.add('active');
        authMessage.textContent = '';
    });

    // Auth Forms
    loginForm.addEventListener('submit', (e) => handleAuthFormSubmit(e, '/login'));
    registerForm.addEventListener('submit', (e) => handleAuthFormSubmit(e, '/register'));

    // Scanner
    scanButton.addEventListener('click', handleScan);
    urlInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') scanButton.click();
    });


    // Feedback
    // Assuming "incorrect" means a "false negative" (it was dangerous)
    // or "false positive" (it was safe). Default to false_negative
    reportIncorrectButton.addEventListener('click', () => sendFeedback('false_negative'));

    // History
    clearHistoryButton.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all scan history?')) {
            scanHistory = [];
            saveHistory();
        }
    });


    // --- INITIALIZATION ---
    loadHistory(); // Load history from localStorage
    checkLoginState(); // Check if user is already logged in
})