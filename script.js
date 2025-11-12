// script.js
// PhishEye frontend controller (updated: admin UI removed)

document.addEventListener('DOMContentLoaded', () => {
  // --- STATE ---
  let scanHistory = [];
  const MAX_HISTORY_ITEMS = 10;
  let currentApiKey = null;      // stored API key (Bearer)
  let currentScanId = null;      // last scan id for feedback
  let lastScanResponse = null;   // full server response for last scan

  const API_BASE_URL = 'http://127.0.0.1:8000'; // change if your backend is elsewhere

  // --- DOM ELEMENTS ---
  // Auth bits
  const showAuthButton = document.getElementById('showAuthButton');
  const authContainer = document.getElementById('authContainer');
  const closeAuthButton = document.getElementById('closeAuthButton');
  const showLoginTab = document.getElementById('showLoginTab');
  const showRegisterTab = document.getElementById('showRegisterTab');

  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const loginEmail = document.getElementById('loginEmail');
  const loginPassword = document.getElementById('loginPassword');
  const registerEmail = document.getElementById('registerEmail');
  const registerPassword = document.getElementById('registerPassword');
  const authMessage = document.getElementById('authMessage');

  const userInfo = document.getElementById('userInfo');
  const logoutButton = document.getElementById('logoutButton');

  // Scanner bits
  const urlInput = document.getElementById('urlInput');
  const scanButton = document.getElementById('scanButton');
  const loadingSpinner = document.getElementById('loadingSpinner');
  const resultBox = document.getElementById('result');
  const resultStatusText = document.getElementById('resultStatusText');
  const confidenceText = document.getElementById('confidenceText');
  const guestMessage = document.getElementById('guestMessage');

  // Details
  const detailedResultsDiv = document.getElementById('detailedResults');
  const detailsList = document.getElementById('detailsList');

  // Feedback
  const feedbackContainer = document.getElementById('feedbackContainer');
  const reportIncorrectButton = document.getElementById('reportIncorrectButton');
  const feedbackThanks = document.getElementById('feedbackThanks');

  // History
  const scanHistorySection = document.getElementById('scanHistory');
  const historyList = document.getElementById('historyList');
  const clearHistoryButton = document.getElementById('clearHistoryButton');

  // --- UTIL: API fetch wrapper ---
  async function apiFetch(path, opts = {}) {
    const url = API_BASE_URL + path;
    const headers = new Headers(opts.headers || {});
    headers.set('Content-Type', 'application/json');

    if (currentApiKey) {
      headers.set('Authorization', `Bearer ${currentApiKey}`);
    }

    const response = await fetch(url, {
      ...opts,
      headers,
    });

    const text = await response.text();
    let json;
    try {
      json = text ? JSON.parse(text) : {};
    } catch (e) {
      json = { raw: text };
    }

    if (!response.ok) {
      const err = new Error(json.detail || json.message || `HTTP ${response.status}`);
      err.status = response.status;
      err.body = json;
      throw err;
    }
    return json;
  }

  // --- AUTH / UI state ---
  function loadStateFromStorage() {
    const storedKey = localStorage.getItem('phishEyeApiKey');
    const storedEmail = localStorage.getItem('phishEyeUserEmail');
    currentApiKey = storedKey || null;

    if (currentApiKey && storedEmail) {
      userInfo.textContent = `Welcome — ${storedEmail}`;
      userInfo.classList.remove('hidden');
      logoutButton.classList.remove('hidden');
      showAuthButton.classList.add('hidden');
    } else {
      userInfo.textContent = '';
      userInfo.classList.add('hidden');
      logoutButton.classList.add('hidden');
      showAuthButton.classList.remove('hidden');
    }
  }

  function showAuthModal(tab = 'login') {
    authContainer.classList.remove('hidden');
    authMessage.textContent = '';
    if (tab === 'login') {
      showLoginTab.click();
    } else {
      showRegisterTab.click();
    }
  }

  function hideAuthModal() {
    authContainer.classList.add('hidden');
  }

  function handleAuthSuccess(email, apiKey) {
    localStorage.setItem('phishEyeApiKey', apiKey);
    localStorage.setItem('phishEyeUserEmail', email);
    currentApiKey = apiKey;
    loadStateFromStorage();
    hideAuthModal();
    clearResult();
    renderHistory();
  }

  function handleLogout() {
    localStorage.removeItem('phishEyeApiKey');
    localStorage.removeItem('phishEyeUserEmail');
    currentApiKey = null;
    loadStateFromStorage();
    clearResult();
    renderHistory();
  }

  async function submitAuthForm(e, endpoint) {
    e.preventDefault();
    authMessage.textContent = '';

    const isRegister = endpoint === '/register';
    const email = isRegister ? registerEmail.value.trim() : loginEmail.value.trim();
    const password = isRegister ? registerPassword.value : loginPassword.value;

    if (!email || !password) {
      authMessage.textContent = 'Please fill in both email and password.';
      return;
    }

    try {
      const res = await fetch(API_BASE_URL + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();
      if (!res.ok) {
        authMessage.textContent = data.detail || data.message || 'Auth failed';
        return;
      }
      // backend returns { email, api_key }
      handleAuthSuccess(data.email, data.api_key);
    } catch (err) {
      console.error('Auth error', err);
      authMessage.textContent = 'Failed to reach server.';
    }
  }

  // --- RESULTS & UI helpers ---
  function clearResult() {
    resultBox.className = 'result-box';
    resultStatusText.textContent = "Enter a URL and click 'Scan' to check it.";
    loadingSpinner.classList.add('spinner-hidden');
    confidenceText.classList.add('hidden');
    guestMessage.classList.add('hidden');
    detailedResultsDiv.classList.add('hidden');
    detailsList.innerHTML = '';
    feedbackContainer.classList.add('hidden');
    feedbackThanks.classList.add('hidden');
    currentScanId = null;
    lastScanResponse = null;
  }

  function renderDetailedFeatures(details) {
    detailsList.innerHTML = '';
    if (!details || Object.keys(details).length === 0) {
      detailedResultsDiv.classList.add('hidden');
      return;
    }
    detailedResultsDiv.classList.remove('hidden');
    for (const k of Object.keys(details)) {
      const dt = document.createElement('dt');
      dt.textContent = k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      const dd = document.createElement('dd');
      dd.textContent = typeof details[k] === 'object' ? JSON.stringify(details[k]) : String(details[k]);
      detailsList.appendChild(dt);
      detailsList.appendChild(dd);
    }
  }

  function updateResultUI(data, scannedUrl) {
    loadingSpinner.classList.add('spinner-hidden');
    resultBox.classList.remove('safe', 'suspicious', 'dangerous');
    currentScanId = data.scan_id || null;
    lastScanResponse = data;

    const status = data.status || 'unknown';
    if (status === 'safe') {
      resultBox.classList.add('safe');
      resultStatusText.textContent = 'This URL appears SAFE.';
    } else if (status === 'suspicious') {
      resultBox.classList.add('suspicious');
      resultStatusText.textContent = 'This URL is SUSPICIOUS — be careful.';
    } else if (status === 'dangerous') {
      resultBox.classList.add('dangerous');
      resultStatusText.textContent = 'This URL is DANGEROUS — do NOT visit.';
    } else {
      resultStatusText.textContent = `Result: ${status}`;
    }

    // Tiered content:
    if (data.confidence !== undefined) {
      confidenceText.textContent = `(Confidence: ${(data.confidence * 100).toFixed(2)}%)`;
      confidenceText.classList.remove('hidden');
      guestMessage.classList.add('hidden');
      renderDetailedFeatures(data.detailed_features || {});
      feedbackContainer.classList.remove('hidden');
      feedbackThanks.classList.add('hidden');
      addHistoryItem(scannedUrl, status, data.confidence);
    } else {
      confidenceText.classList.add('hidden');
      guestMessage.classList.remove('hidden');
      detailedResultsDiv.classList.add('hidden');
      feedbackContainer.classList.add('hidden');
      addHistoryItem(scannedUrl, status, null);
    }
  }

  // --- HISTORY ---
  function loadHistoryFromStorage() {
    try {
      const raw = localStorage.getItem('urlScanHistory') || '[]';
      scanHistory = JSON.parse(raw);
    } catch (e) {
      scanHistory = [];
    }
  }

  function saveHistoryToStorage() {
    localStorage.setItem('urlScanHistory', JSON.stringify(scanHistory));
    renderHistory();
  }

  function addHistoryItem(url, status, confidence) {
    const item = { url, status, confidence, timestamp: new Date().toLocaleString() };
    scanHistory.unshift(item);
    if (scanHistory.length > MAX_HISTORY_ITEMS) scanHistory = scanHistory.slice(0, MAX_HISTORY_ITEMS);
    saveHistoryToStorage();
  }

  function renderHistory() {
    historyList.innerHTML = '';
    // only show history to logged-in users (you can change this)
    if (!currentApiKey || scanHistory.length === 0) {
      scanHistorySection.classList.add('hidden');
      return;
    }
    scanHistorySection.classList.remove('hidden');
    for (const it of scanHistory) {
      const li = document.createElement('li');
      const left = document.createElement('span');
      left.className = 'history-url';
      left.textContent = it.url;
      const right = document.createElement('span');
      right.className = `history-status ${it.status}`;
      right.textContent = it.status.toUpperCase();
      const t = document.createElement('div');
      t.className = 'history-ts';
      t.textContent = it.timestamp;
      li.appendChild(left);
      li.appendChild(right);
      li.appendChild(t);
      historyList.appendChild(li);
    }
  }

  // --- SCAN & FEEDBACK ---
  async function performScan() {
    const url = urlInput.value.trim();
    if (!url) { alert('Please enter a URL.'); return; }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      alert('Please include http:// or https:// in the URL.');
      return;
    }

    clearResult();
    loadingSpinner.classList.remove('spinner-hidden');
    resultStatusText.textContent = 'Scanning...';

    try {
      const payload = { url };
      const data = await apiFetch('/scan_url', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      updateResultUI(data, url);
    } catch (err) {
      console.error('Scan error', err);
      loadingSpinner.classList.add('spinner-hidden');
      resultBox.classList.remove('safe','suspicious','dangerous');
      resultBox.classList.add('dangerous');
      resultStatusText.textContent = `Scan failed: ${err.message || 'Unknown error'}`;
    }
  }

  async function sendFeedback(reportType) {
    if (!currentApiKey || !currentScanId) {
      alert('You need to be logged in and have a scan result to report feedback.');
      return;
    }

    try {
      const payload = { scan_id: currentScanId, report_type: reportType };
      await apiFetch('/report_feedback', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      // show thanks notice briefly
      feedbackThanks.classList.remove('hidden');
      reportIncorrectButton.classList.add('hidden');
      setTimeout(() => {
        feedbackThanks.classList.add('hidden');
        reportIncorrectButton.classList.remove('hidden');
      }, 3000);
    } catch (err) {
      console.error('Feedback error', err);
      alert('Failed to send feedback: ' + (err.message || 'Unknown error'));
    }
  }

  // --- EVENT BINDINGS ---
  // Auth modal toggle
  showAuthButton && showAuthButton.addEventListener('click', () => showAuthModal('login'));
  closeAuthButton && closeAuthButton.addEventListener('click', hideAuthModal);

  showLoginTab && showLoginTab.addEventListener('click', () => {
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
    showLoginTab.classList.add('active');
    showRegisterTab.classList.remove('active');
    authMessage.textContent = '';
  });

  showRegisterTab && showRegisterTab.addEventListener('click', () => {
    registerForm.classList.remove('hidden');
    loginForm.classList.add('hidden');
    showRegisterTab.classList.add('active');
    showLoginTab.classList.remove('active');
    authMessage.textContent = '';
  });

  loginForm && loginForm.addEventListener('submit', (e) => submitAuthForm(e, '/login'));
  registerForm && registerForm.addEventListener('submit', (e) => submitAuthForm(e, '/register'));
  logoutButton && logoutButton.addEventListener('click', handleLogout);

  // Scan controls
  scanButton && scanButton.addEventListener('click', performScan);
  urlInput && urlInput.addEventListener('keypress', (ev) => {
    if (ev.key === 'Enter') scanButton.click();
  });

  // Feedback
  reportIncorrectButton && reportIncorrectButton.addEventListener('click', () => sendFeedback('false_positive'));

  // History
  clearHistoryButton && clearHistoryButton.addEventListener('click', () => {
    if (!confirm('Clear scan history?')) return;
    scanHistory = [];
    saveHistoryToStorage();
  });

  // --- INIT ---
  loadHistoryFromStorage();
  currentApiKey = localStorage.getItem('phishEyeApiKey');
  loadStateFromStorage();
  clearResult();
  renderHistory();
});
