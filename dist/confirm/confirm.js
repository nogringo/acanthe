// Confirmation popup logic

const params = new URLSearchParams(window.location.search);
const requestId = params.get('requestId');
const action = params.get('action');
const origin = params.get('origin');
const rpName = params.get('rpName');
const userName = params.get('userName');

// Update UI based on action type
const iconEl = document.getElementById('icon');
const titleEl = document.getElementById('title');
const subtitleEl = document.getElementById('subtitle');
const siteEl = document.getElementById('site');
const originEl = document.getElementById('origin');
const userRowEl = document.getElementById('user-row');
const userEl = document.getElementById('user');
const warningEl = document.getElementById('warning');

if (action === 'create') {
  iconEl.textContent = '🔑';
  titleEl.textContent = 'Create Passkey';
  subtitleEl.textContent = 'A website wants to create a passkey';
  warningEl.textContent = 'This will create a new passkey for this site stored in your extension.';

  if (userName) {
    userRowEl.style.display = 'flex';
    userEl.textContent = userName;
  }
} else if (action === 'get') {
  iconEl.textContent = '🔓';
  titleEl.textContent = 'Use Passkey';
  subtitleEl.textContent = 'A website wants to authenticate you';
  warningEl.textContent = 'This will sign you in using your stored passkey.';
}

siteEl.textContent = rpName || new URL(origin).hostname;
originEl.textContent = origin;

// Handle buttons
document.getElementById('cancel-btn').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    action: 'confirmResponse',
    requestId,
    confirmed: false
  });
  window.close();
});

document.getElementById('confirm-btn').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    action: 'confirmResponse',
    requestId,
    confirmed: true
  });
  window.close();
});

// Auto-close on timeout (60 seconds)
setTimeout(() => {
  chrome.runtime.sendMessage({
    action: 'confirmResponse',
    requestId,
    confirmed: false
  });
  window.close();
}, 60000);
