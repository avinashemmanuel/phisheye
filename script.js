document.addEventListener('DOMContentLoaded', () => {
    // --- STATE ---
    let scanHistory = [];
    const MAX_HISTORY_ITEMS = 10;
    let currentApiKey = null; // Stores the user's API key
    let currentScanId = null; // Stores the ID of the last scan for feedback

    // --- API ---
    const API_BASE_URL = 'http://127.0.0.1:8000'; // Your FastAPI backend

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
    const showRegisterTab = document.getElementById('showRegisterTab');
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
    const resultBox = document.getElementById('result'); 
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

    function checkLoginState() {
        currentApiKey = localStorage.getItem('phishEyeApiKey');
        const userEmail = localStorage.getItem('phishEyeUserEmail');

        if (currentApiKey && userEmail) {
            userInfo.textContent = `Welcome, ${userEmail}`;
            userInfo.classList.remove('hidden');
            logoutButton.classList.remove('hidden');
            showAuthButton.classList.add('hidden');
        } else {
            userInfo.textContent = '';
            userInfo.classList.add('hidden');
            logoutButton.classList.add('hidden');
            showAuthButton.classList.remove('hidden');
        }
        authContainer.classList.add('hidden');
    }

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
        authContainer.classList.add('hidden');
    }

    function handleAuthSuccess(email, apiKey) {
        localStorage.setItem('phishEyeApiKey', apiKey);
        localStorage.setItem('phishEyeUserEmail', email);
        currentApiKey = apiKey;
        checkLoginState();
        hideAuthModal();
        clearResult();
    }

    function handleLogout() {
        localStorage.removeItem('phishEyeApiKey');
        localStorage.removeItem('phishEyeUserEmail');
        currentApiKey = null;
        checkLoginState();
        clearResult();
    }

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
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (!response.ok) {
                authMessage.textContent = data.detail || 'An unknown error occurred.';
            } else {
                handleAuthSuccess(data.email, data.api_key);
            }
        } catch (error) {
            console.error(`Auth Error: ${error}`);
            authMessage.textContent = 'Failed to connect to the server.';
        }
    }


    // --- SCANNER & RESULT FUNCTIONS ---

    function clearResult() {
        resultBox.className = 'result-box';
        resultStatusText.textContent = "Enter a URL and click 'Scan' to check its safety!";
        
        // Use the standard .hidden class
        confidenceText.classList.add('hidden');
        guestMessage.classList.add('hidden');
        detailedResultsDiv.classList.add('hidden');
        detailsList.innerHTML = '';
        feedbackContainer.classList.add('hidden');
        feedbackThanks.classList.add('hidden');
        currentScanId = null;
    }

    function updateResult(data) {
        loadingSpinner.classList.add('spinner-hidden'); // This is the one special class
        resultBox.className = 'result-box';
        
        currentScanId = data.scan_id;

        if (data.status === 'safe') {
            resultBox.classList.add('safe');
            resultStatusText.textContent = 'This URL appears to be SAFE.';
        } else if (data.status === 'suspicious') {
            resultBox.classList.add('suspicious');
            resultStatusText.textContent = 'This URL is SUSPICIOUS. Exercise caution.';
        } else if (data.status === 'dangerous') {
            resultBox.classList.add('dangerous');
            resultStatusText.textContent = 'This URL is DANGEROUS! Do NOT Visit.';
        }

        // --- TIERED CONTENT ---
        if (data.confidence !== undefined) {
            // REGISTERED USER
            confidenceText.textContent = `(Confidence: ${(data.confidence * 100).toFixed(2)}%)`;
            confidenceText.classList.remove('hidden');
            guestMessage.classList.add('hidden');
            renderDetailedFeatures(data.detailed_features);
            feedbackContainer.classList.remove('hidden');
            feedbackThanks.classList.add('hidden');
            
            addHistoryItem(urlInput.value.trim(), data.status, data.confidence);
        } else {
            // GUEST
            confidenceText.classList.add('hidden');
            guestMessage.classList.remove('hidden');
            detailedResultsDiv.classList.add('hidden');
            feedbackContainer.classList.add('hidden');
        }
    }

    function renderDetailedFeatures(details) {
        detailsList.innerHTML = '';
        if (details && Object.keys(details).length > 0) {
            detailedResultsDiv.classList.remove('hidden'); // Use .hidden
            for (const key in details) {
                if (details.hasOwnProperty(key)) {
                    const dt = document.createElement('dt');
                    dt.textContent = formatFeatureName(key);
                    detailsList.appendChild(dt);

                    const dd = document.createElement('dd');
                    dd.textContent = details[key];
                    detailsList.appendChild(dd);
                }
            }
        } else {
            detailedResultsDiv.classList.add('hidden'); // Use .hidden
        }
    }

    function formatFeatureName(name) {
        return name
            .replace(/_/g, ' ')
            .replace(/\b\w/g, char => char.toUpperCase());
    }

    async function handleScan() {
        const url = urlInput.value.trim();

        // Simplified, more reliable client-side validation
        if (!url) {
            alert('Please enter a URL.');
            return;
        }
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
             // A basic check. The backend will do the real validation.
             if (!url.includes('.')) { 
                alert('Please enter a valid URL.');
                return;
             }
             // Let's just ask them to add it.
             alert('Please include http:// or https:// in your URL.');
             return;
        }

        clearResult();
        loadingSpinner.classList.remove('spinner-hidden');
        resultStatusText.textContent = 'Scanning...';

        try {
            const headers = { 'Content-Type': 'application/json' };
            if (currentApiKey) {
                headers['Authorization'] = currentApiKey;
            }

            const response = await fetch(`${API_BASE_URL}/scan_url`, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ url: url }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'An error occurred during scanning.');
            }
            
            updateResult(data);

        } catch (error) {
            console.error('Scan Error:', error);
            loadingSpinner.classList.add('spinner-hidden');
            resultBox.className = 'result-box dangerous';
            resultStatusText.textContent = `Scan Error: ${error.message}`;
        }
    }

    async function sendFeedback(reportType) {
        if (!currentApiKey || !currentScanId) {
            alert('You must be logged in to report feedback.');
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/report_feedback`, {
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

            feedbackThanks.classList.remove('hidden');
            reportIncorrectButton.classList.add('hidden');
            
            setTimeout(() => {
                feedbackThanks.classList.add('hidden');
                reportIncorrectButton.classList.remove('hidden');
            }, 3000);

        } catch (error) {
            console.error('Feedback Error:', error);
            alert(`Error: ${error.message}`);
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
        if (scanHistory.length === 0 || !currentApiKey) { // Don't show for guests
            scanHistorySection.classList.add('hidden'); // Use .hidden
            return;
        }
        scanHistorySection.classList.remove('hidden'); // Use .hidden
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

    showAuthButton.addEventListener('click', () => showAuthModal('login'));
    closeAuthButton.addEventListener('click', hideAuthModal);
    loginForDetails.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('login'); });
    registerForDetails.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('register'); });
    logoutButton.addEventListener('click', handleLogout);

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

    loginForm.addEventListener('submit', (e) => handleAuthFormSubmit(e, '/login'));
    registerForm.addEventListener('submit', (e) => handleAuthFormSubmit(e, '/register'));

    scanButton.addEventListener('click', handleScan);
    urlInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') scanButton.click();
    });

    reportIncorrectButton.addEventListener('click', () => sendFeedback('false_negative')); 

    clearHistoryButton.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all scan history?')) {
            scanHistory = [];
            saveHistory();
        }
    });

    // --- INITIALIZATION ---
    loadHistory();
    checkLoginState();
    clearResult(); // Ensure a clean state on load
});