// defensive width logging & forcing (helps debug host-enforced narrowness)
(function forceWidth() {
  try {
    const w = 360;
    // set on documentElement and body as a fallback
    document.documentElement.style.width = w + 'px';
    document.documentElement.style.minWidth = w + 'px';
    window.addEventListener('load', () => {
      try {
        document.body.style.width = w + 'px';
        document.body.style.minWidth = w + 'px';
      } catch (e) {}
      // log computed sizes for debugging
      console.log('popup sizes (computed): html=', document.documentElement.clientWidth,
                  'body=', document.body.clientWidth,
                  'innerWidth=', window.innerWidth);
    });
  } catch (e) {
    console.warn('forceWidth failed', e);
  }
})();

document.addEventListener('DOMContentLoaded', () => {
  const currentUrlElement = document.getElementById('currentUrl');
  const scanButton = document.getElementById('scanButton');
  const resultDiv = document.getElementById('result');
  const resultText = document.getElementById('resultText');
  const loadingSpinner = document.getElementById('loadingSpinner');
  const detailedResultsContainer = document.getElementById('detailedResults');
  const detailsList = document.getElementById('detailsList');
  const confidenceFill = document.getElementById('confidenceFill');
  const confidencePercent = document.getElementById('confidencePercent');
  const confidenceWrap = document.getElementById('confidenceWrap');
  const resultBadge = document.getElementById('resultBadge');
  const copyUrlBtn = document.getElementById('copyUrlBtn');
  const openTabBtn = document.getElementById('openTabBtn');
  const reportBtn = document.getElementById('reportBtn');
  const reportDialog = document.getElementById('reportDialog');
  const sendReportBtn = document.getElementById('sendReportBtn');
  const cancelReportBtn = document.getElementById('cancelReportBtn');
  const reportNote = document.getElementById('reportNote');
  const closeResult = document.getElementById('closeResult');
  const takeActionBtn = document.getElementById('takeActionBtn');

  let activeTabUrl = '';

  // Get the active tab URL
  async function getCurrentTabUrl() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        activeTabUrl = tab.url;
        currentUrlElement.textContent = activeTabUrl;
        setFaviconFromTab(tab);
        scanButton.disabled = false;
      } else {
        currentUrlElement.textContent = 'Could not get current URL';
        scanButton.disabled = true;
      }
    } catch (err) {
      currentUrlElement.textContent = 'Could not get current URL';
      scanButton.disabled = true;
      console.error('Error getting tab URL', err);
    }
  }

  function setFaviconFromTab(tab) {
    const fav = document.getElementById('favicon');
    try {
      if (tab.favIconUrl) {
        fav.style.backgroundImage = `url(${tab.favIconUrl})`;
        fav.style.backgroundSize = 'cover';
      } else {
        fav.style.background = '';
      }
    } catch (e) { /* ignore */ }
  }

  function showSpinner() { loadingSpinner.classList.remove('hidden'); }
  function hideSpinner() { loadingSpinner.classList.add('hidden'); }
  function showResult() { resultDiv.classList.remove('hidden'); }
  function hideResult() { resultDiv.classList.add('hidden'); }

  function resetResultDisplay() {
    hideSpinner();
    confidenceWrap.classList.add('hidden');
    confidenceFill.style.width = '0%';
    confidencePercent.textContent = '0%';
    resultBadge.className = 'badge neutral';
    resultText.textContent = '';
    detailsList.innerHTML = '';
    detailedResultsContainer.hidden = true;
    takeActionBtn.hidden = true;
  }

  function setBadgeAndText(status, confidence = null, message = '') {
    if (status === 'safe') {
      resultBadge.className = 'badge safe';
      resultBadge.textContent = '✅ Safe';
      resultText.textContent = message || 'This URL appears safe.';
      takeActionBtn.hidden = false;
      takeActionBtn.textContent = 'Open (Proceed)';
      takeActionBtn.onclick = () => openUrlInNewTab(activeTabUrl);
    } else if (status === 'suspicious') {
      resultBadge.className = 'badge warn';
      resultBadge.textContent = '⚠ Suspicious';
      resultText.textContent = message || 'This URL looks suspicious. Exercise caution.';
      takeActionBtn.hidden = false;
      takeActionBtn.textContent = 'Open with Caution';
      takeActionBtn.onclick = () => openUrlInNewTab(activeTabUrl);
    } else if (status === 'dangerous') {
      resultBadge.className = 'badge danger';
      resultBadge.textContent = '⛔ Phishing Detected';
      resultText.textContent = message || 'This URL is dangerous. Do NOT visit.';
      takeActionBtn.hidden = true;
    } else if (status === 'validation-error') {
      resultBadge.className = 'badge warn';
      resultBadge.textContent = '⚠ Invalid URL';
      resultText.textContent = message || 'Please use a valid URL.';
    } else {
      resultBadge.className = 'badge neutral';
      resultBadge.textContent = 'Not scanned';
      resultText.textContent = message || 'An unexpected result occurred.';
    }

    if (typeof confidence === 'number' && confidence >= 0) {
      confidenceWrap.classList.remove('hidden');
      const pct = Math.max(0, Math.min(100, Math.round(confidence * 100)));
      confidenceFill.style.width = pct + '%';
      confidencePercent.textContent = pct + '%';
    }
  }

  function renderDetailedFeatures(details) {
    detailsList.innerHTML = '';
    if (details && Object.keys(details).length) {
      detailedResultsContainer.hidden = false;
      for (const key of Object.keys(details)) {
        const dt = document.createElement('dt');
        dt.textContent = formatFeatureName(key);
        const dd = document.createElement('dd');
        dd.textContent = String(details[key]);
        detailsList.appendChild(dt);
        detailsList.appendChild(dd);
      }
    } else {
      detailedResultsContainer.hidden = true;
    }
  }

  function formatFeatureName(name) {
    return name.replace(/_/g, ' ').replace(/\b\w/g, ch => ch.toUpperCase());
  }

  function openUrlInNewTab(url) {
    if (!url) return;
    chrome.tabs.create({ url });
  }

  copyUrlBtn.addEventListener('click', async () => {
    if (!activeTabUrl) return;
    try {
      await navigator.clipboard.writeText(activeTabUrl);
      copyUrlBtn.textContent = 'Copied';
      setTimeout(() => copyUrlBtn.textContent = 'Copy', 1200);
    } catch (e) {
      console.error('Clipboard write failed', e);
    }
  });

  openTabBtn.addEventListener('click', () => {
    if (activeTabUrl) openUrlInNewTab(activeTabUrl);
  });

  reportBtn.addEventListener('click', () => {
    if (typeof reportDialog.showModal === 'function') {
      reportDialog.showModal();
      reportNote.value = '';
    } else {
      const note = prompt('Report note (optional):');
      if (note !== null) submitReport(note);
    }
  });

  cancelReportBtn?.addEventListener('click', () => {
    try { reportDialog.close(); } catch(e){}
  });

  sendReportBtn.addEventListener('click', (ev) => {
    ev.preventDefault();
    const note = reportNote.value.trim();
    submitReport(note);
    try { reportDialog.close(); } catch(e){}
  });

  function submitReport(note) {
    console.log('User report', { url: activeTabUrl, note });
    reportBtn.textContent = 'Reported';
    setTimeout(() => reportBtn.textContent = 'Report', 1400);
  }

  closeResult.addEventListener('click', () => {
    resetResultDisplay();
    hideResult();
  });

  scanButton.addEventListener('click', async () => {
    if (!activeTabUrl) {
      setBadgeAndText('validation-error', null, 'No URL available.');
      showResult();
      return;
    }

    resetResultDisplay();
    showResult();
    showSpinner();
    setBadgeAndText('scanning', null, 'Scanning…');

    try {
      const response = await fetch('http://127.0.0.1:8000/scan_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeTabUrl })
      });

      const data = await response.json();
      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || `HTTP ${response.status}`);
      }

      const status = data.status || 'error';
      const confidence = typeof data.confidence === 'number' ? data.confidence : null;
      const details = data.detailed_features || {};

      setBadgeAndText(status, confidence, null);
      renderDetailedFeatures(details);
    } catch (err) {
      console.error('Scan failed', err);
      setBadgeAndText('error', null, 'Failed to connect to the scanner backend.');
    } finally {
      hideSpinner();
    }
  });

  // initialize
  resetResultDisplay();
  hideResult();
  getCurrentTabUrl();
});
