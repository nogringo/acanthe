// Popup logic for Passkey Manager

document.addEventListener('DOMContentLoaded', init);

// DOM Elements
const setupScreen = document.getElementById('setup-screen');
const unlockScreen = document.getElementById('unlock-screen');
const mainScreen = document.getElementById('main-screen');
const setupForm = document.getElementById('setup-form');
const unlockForm = document.getElementById('unlock-form');
const lockBtn = document.getElementById('lock-btn');
const passkeysList = document.getElementById('passkeys-list');
const setupError = document.getElementById('setup-error');
const unlockError = document.getElementById('unlock-error');

// Initialize popup
async function init() {
  const setupStatus = await sendMessage('checkSetup');

  if (!setupStatus.isSetup) {
    showScreen('setup');
  } else {
    const lockStatus = await sendMessage('isUnlocked');
    if (lockStatus.unlocked) {
      showScreen('main');
      loadPasskeys();
    } else {
      showScreen('unlock');
    }
  }

  setupEventListeners();
}

// Show specific screen
function showScreen(screen) {
  setupScreen.classList.add('hidden');
  unlockScreen.classList.add('hidden');
  mainScreen.classList.add('hidden');

  switch (screen) {
    case 'setup':
      setupScreen.classList.remove('hidden');
      break;
    case 'unlock':
      unlockScreen.classList.remove('hidden');
      break;
    case 'main':
      mainScreen.classList.remove('hidden');
      break;
  }
}

// Setup event listeners
function setupEventListeners() {
  setupForm.addEventListener('submit', handleSetup);
  unlockForm.addEventListener('submit', handleUnlock);
  lockBtn.addEventListener('click', handleLock);
}

// Handle master password setup
async function handleSetup(e) {
  e.preventDefault();

  const password = document.getElementById('setup-password').value;
  const confirm = document.getElementById('setup-confirm').value;

  if (password !== confirm) {
    showError(setupError, 'Passwords do not match');
    return;
  }

  if (password.length < 8) {
    showError(setupError, 'Password must be at least 8 characters');
    return;
  }

  const result = await sendMessage('setupMasterPassword', { password });

  if (result.success) {
    showScreen('main');
    loadPasskeys();
  } else {
    showError(setupError, result.error);
  }
}

// Handle unlock
async function handleUnlock(e) {
  e.preventDefault();

  const password = document.getElementById('unlock-password').value;

  const result = await sendMessage('unlock', { password });

  if (result.success) {
    showScreen('main');
    loadPasskeys();
    document.getElementById('unlock-password').value = '';
    hideError(unlockError);
  } else {
    showError(unlockError, result.error);
  }
}

// Handle lock
async function handleLock() {
  await sendMessage('lock');
  showScreen('unlock');
}

// Load and display passkeys
async function loadPasskeys() {
  const result = await sendMessage('getPasskeys');

  if (!result.success) {
    passkeysList.innerHTML = '<p class="empty-state">Error loading passkeys</p>';
    return;
  }

  if (result.passkeys.length === 0) {
    passkeysList.innerHTML = '<p class="empty-state">No passkeys stored yet.</p>';
    return;
  }

  passkeysList.innerHTML = result.passkeys.map(passkey => `
    <div class="passkey-item" data-id="${passkey.credentialId}">
      <div class="passkey-info">
        <div class="passkey-site">${escapeHtml(passkey.rpName || passkey.rpId)}</div>
        <div class="passkey-user">${escapeHtml(passkey.userDisplayName || passkey.userName)}</div>
        <div class="passkey-date">${formatDate(passkey.createdAt)}</div>
      </div>
      <div class="passkey-actions">
        <button class="btn btn-danger delete-btn" data-id="${passkey.credentialId}">Delete</button>
      </div>
    </div>
  `).join('');

  // Add delete handlers
  document.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', handleDelete);
  });
}

// Handle passkey deletion
async function handleDelete(e) {
  const credentialId = e.target.dataset.id;

  if (!confirm('Are you sure you want to delete this passkey?')) {
    return;
  }

  const result = await sendMessage('deletePasskey', { credentialId });

  if (result.success) {
    loadPasskeys();
  } else {
    alert('Failed to delete passkey: ' + result.error);
  }
}

// Send message to background script
function sendMessage(action, data = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action, data }, (response) => {
      resolve(response || { success: false, error: 'No response' });
    });
  });
}

// Show error message
function showError(element, message) {
  element.textContent = message;
  element.classList.remove('hidden');
}

// Hide error message
function hideError(element) {
  element.classList.add('hidden');
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Format date
function formatDate(timestamp) {
  if (!timestamp) return 'Unknown';
  const date = new Date(timestamp);
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}
