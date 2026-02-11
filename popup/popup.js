// Popup logic for Passkey Manager

document.addEventListener('DOMContentLoaded', init);

// DOM Elements
const setupScreen = document.getElementById('setup-screen');
const unlockScreen = document.getElementById('unlock-screen');
const mainScreen = document.getElementById('main-screen');
const settingsScreen = document.getElementById('settings-screen');
const changePasswordScreen = document.getElementById('change-password-screen');

const setupForm = document.getElementById('setup-form');
const unlockForm = document.getElementById('unlock-form');
const changePasswordForm = document.getElementById('change-password-form');

const lockBtn = document.getElementById('lock-btn');
const settingsBtn = document.getElementById('settings-btn');
const backBtn = document.getElementById('back-btn');
const backFromPasswordBtn = document.getElementById('back-from-password-btn');
const exportBtn = document.getElementById('export-btn');
const importBtn = document.getElementById('import-btn');
const changePasswordBtn = document.getElementById('change-password-btn');
const resetBtn = document.getElementById('reset-btn');

const passkeysList = document.getElementById('passkeys-list');
const searchInput = document.getElementById('search-input');
const clearSearchBtn = document.getElementById('clear-search');
const currentSiteSection = document.getElementById('current-site-section');
const currentSitePasskeys = document.getElementById('current-site-passkeys');
const currentSiteName = document.getElementById('current-site-name');

const setupError = document.getElementById('setup-error');
const unlockError = document.getElementById('unlock-error');
const changePasswordError = document.getElementById('change-password-error');
const changePasswordSuccess = document.getElementById('change-password-success');

const modalOverlay = document.getElementById('modal-overlay');
const modalIcon = document.getElementById('modal-icon');
const modalTitle = document.getElementById('modal-title');
const modalMessage = document.getElementById('modal-message');
const modalActions = document.getElementById('modal-actions');

// Sync elements
const syncDisabled = document.getElementById('sync-disabled');
const syncEnabled = document.getElementById('sync-enabled');
const createSyncBtn = document.getElementById('create-sync-btn');
const joinSyncBtn = document.getElementById('join-sync-btn');
const syncKeyDisplay = document.getElementById('sync-key-display');
const toggleSyncKeyBtn = document.getElementById('toggle-sync-key');
const copySyncKeyBtn = document.getElementById('copy-sync-key');
const syncRelaysList = document.getElementById('sync-relays-list');
const editRelaysBtn = document.getElementById('edit-relays-btn');
const syncNowBtn = document.getElementById('sync-now-btn');
const disableSyncBtn = document.getElementById('disable-sync-btn');
const syncLastSync = document.getElementById('sync-last-sync');

// Join sync modal
const joinSyncModal = document.getElementById('join-sync-modal');
const joinSyncNsec = document.getElementById('join-sync-nsec');
const joinSyncCancel = document.getElementById('join-sync-cancel');
const joinSyncConfirm = document.getElementById('join-sync-confirm');
const joinSyncError = document.getElementById('join-sync-error');

// Relays modal
const relaysModal = document.getElementById('relays-modal');
const relaysTextarea = document.getElementById('relays-textarea');
const relaysCancel = document.getElementById('relays-cancel');
const relaysSave = document.getElementById('relays-save');
const relaysError = document.getElementById('relays-error');

let allPasskeys = [];
let currentTabUrl = null;
let previousScreen = 'main';
let currentSyncNsec = null;

// Initialize popup
async function init() {
  // Get current tab URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      currentTabUrl = new URL(tab.url).hostname;
    }
  } catch (e) {
    // Silent fail - currentTabUrl will remain null
  }

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
  settingsScreen.classList.add('hidden');
  changePasswordScreen.classList.add('hidden');

  switch (screen) {
    case 'setup':
      setupScreen.classList.remove('hidden');
      document.getElementById('setup-password').focus();
      break;
    case 'unlock':
      unlockScreen.classList.remove('hidden');
      document.getElementById('unlock-password').focus();
      break;
    case 'main':
      mainScreen.classList.remove('hidden');
      break;
    case 'settings':
      settingsScreen.classList.remove('hidden');
      loadSyncStatus();
      break;
    case 'change-password':
      changePasswordScreen.classList.remove('hidden');
      document.getElementById('current-password').focus();
      break;
  }
}

// Setup event listeners
function setupEventListeners() {
  setupForm.addEventListener('submit', handleSetup);
  unlockForm.addEventListener('submit', handleUnlock);
  changePasswordForm.addEventListener('submit', handleChangePassword);

  lockBtn.addEventListener('click', handleLock);
  settingsBtn.addEventListener('click', () => {
    previousScreen = 'main';
    showScreen('settings');
  });
  backBtn.addEventListener('click', () => showScreen(previousScreen));
  backFromPasswordBtn.addEventListener('click', () => showScreen('settings'));

  // Password visibility toggles
  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', togglePasswordVisibility);
  });

  // Password strength indicator
  const setupPassword = document.getElementById('setup-password');
  setupPassword.addEventListener('input', updatePasswordStrength);

  // Search functionality
  searchInput.addEventListener('input', handleSearch);
  clearSearchBtn.addEventListener('click', clearSearch);

  // Settings actions
  exportBtn.addEventListener('click', handleExport);
  importBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('import/import.html') });
  });
  changePasswordBtn.addEventListener('click', () => showScreen('change-password'));
  resetBtn.addEventListener('click', handleReset);

  // Sync actions
  createSyncBtn.addEventListener('click', handleCreateSync);
  joinSyncBtn.addEventListener('click', () => {
    joinSyncNsec.value = '';
    joinSyncError.classList.add('hidden');
    joinSyncModal.classList.remove('hidden');
  });
  toggleSyncKeyBtn.addEventListener('click', toggleSyncKeyVisibility);
  copySyncKeyBtn.addEventListener('click', copySyncKey);
  editRelaysBtn.addEventListener('click', openRelaysModal);
  syncNowBtn.addEventListener('click', handleSyncNow);
  disableSyncBtn.addEventListener('click', handleDisableSync);

  // Join sync modal
  joinSyncCancel.addEventListener('click', () => joinSyncModal.classList.add('hidden'));
  joinSyncConfirm.addEventListener('click', handleJoinSync);

  // Relays modal
  relaysCancel.addEventListener('click', () => relaysModal.classList.add('hidden'));
  relaysSave.addEventListener('click', handleSaveRelays);
}

// Toggle password visibility
function togglePasswordVisibility(e) {
  const targetId = e.currentTarget.dataset.target;
  const input = document.getElementById(targetId);
  const btn = e.currentTarget;

  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
  } else {
    input.type = 'password';
    btn.textContent = '👁️';
  }
}

// Update password strength indicator
function updatePasswordStrength(e) {
  const password = e.target.value;
  const strengthFill = document.querySelector('.strength-fill');
  const strengthText = document.querySelector('.strength-text');

  if (!password) {
    strengthFill.className = 'strength-fill';
    strengthText.textContent = 'Enter a password';
    return;
  }

  const strength = calculatePasswordStrength(password);

  if (strength < 2) {
    strengthFill.className = 'strength-fill weak';
    strengthText.textContent = 'Weak';
  } else if (strength < 4) {
    strengthFill.className = 'strength-fill medium';
    strengthText.textContent = 'Medium';
  } else {
    strengthFill.className = 'strength-fill strong';
    strengthText.textContent = 'Strong';
  }
}

// Calculate password strength
function calculatePasswordStrength(password) {
  let strength = 0;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
  if (/\d/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;
  return strength;
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

// Handle change password
async function handleChangePassword(e) {
  e.preventDefault();

  hideError(changePasswordError);
  hideError(changePasswordSuccess);

  const currentPassword = document.getElementById('current-password').value;
  const newPassword = document.getElementById('new-password').value;
  const confirmNewPassword = document.getElementById('confirm-new-password').value;

  if (newPassword !== confirmNewPassword) {
    showError(changePasswordError, 'New passwords do not match');
    return;
  }

  if (newPassword.length < 8) {
    showError(changePasswordError, 'New password must be at least 8 characters');
    return;
  }

  const result = await sendMessage('changePassword', {
    currentPassword,
    newPassword
  });

  if (result.success) {
    showSuccess(changePasswordSuccess, 'Password updated successfully');
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-new-password').value = '';
  } else {
    showError(changePasswordError, result.error || 'Failed to change password');
  }
}

// Handle reset
async function handleReset() {
  const confirmed = await showConfirm(
    '⚠️',
    'Reset Extension?',
    'This will permanently delete ALL your passkeys and cannot be undone.',
    'Reset',
    'Cancel',
    true
  );

  if (!confirmed) return;

  const doubleConfirm = await showConfirm(
    '🗑️',
    'Last Chance',
    'Are you absolutely sure? All passkeys will be permanently deleted.',
    'Delete All',
    'Cancel',
    true
  );

  if (!doubleConfirm) return;

  const result = await sendMessage('reset');

  if (result.success) {
    showScreen('setup');
  } else {
    await showAlert('❌', 'Reset Failed', result.error || 'Unknown error');
  }
}

// Load and display passkeys
async function loadPasskeys() {
  const result = await sendMessage('getPasskeys');

  if (!result.success) {
    passkeysList.innerHTML = '<div class="empty-state"><div class="empty-icon">⚠️</div><h4>Error loading passkeys</h4></div>';
    return;
  }

  allPasskeys = result.passkeys;
  renderPasskeys(allPasskeys);
  renderCurrentSitePasskeys();
}

// Render current site passkeys
function renderCurrentSitePasskeys() {
  if (!currentTabUrl) {
    currentSiteSection.classList.add('hidden');
    return;
  }

  const sitePasskeys = allPasskeys.filter(p => p.rpId === currentTabUrl);

  if (sitePasskeys.length === 0) {
    currentSiteSection.classList.add('hidden');
    return;
  }

  currentSiteSection.classList.remove('hidden');
  currentSiteName.textContent = currentTabUrl;
  currentSitePasskeys.innerHTML = sitePasskeys.map(passkey => renderPasskeyItem(passkey, true)).join('');

  // Add delete handlers
  currentSitePasskeys.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', handleDelete);
  });
}

// Render passkeys list
function renderPasskeys(passkeys) {
  if (passkeys.length === 0) {
    passkeysList.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔑</div>
        <h4>No passkeys yet</h4>
        <p>Visit a website that supports passkeys to create one.</p>
      </div>
    `;
    return;
  }

  // Group by site
  const grouped = {};
  passkeys.forEach(passkey => {
    const site = passkey.rpId;
    if (!grouped[site]) grouped[site] = [];
    grouped[site].push(passkey);
  });

  // Sort sites alphabetically
  const sortedSites = Object.keys(grouped).sort();

  let html = '';
  sortedSites.forEach(site => {
    html += `<div class="site-group">`;
    html += `<div class="site-group-header">${escapeHtml(site)}</div>`;
    grouped[site].forEach(passkey => {
      html += renderPasskeyItem(passkey, false);
    });
    html += `</div>`;
  });

  passkeysList.innerHTML = html;

  // Add delete handlers
  passkeysList.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', handleDelete);
  });
}

// Render single passkey item
function renderPasskeyItem(passkey, isCurrentSite) {
  const initial = (passkey.userDisplayName || passkey.userName || '?')[0].toUpperCase();
  const className = isCurrentSite ? 'passkey-item current-site' : 'passkey-item';

  return `
    <div class="${className}" data-id="${passkey.credentialId}">
      <div class="passkey-avatar">${initial}</div>
      <div class="passkey-info">
        <div class="passkey-site">${escapeHtml(passkey.rpName || passkey.rpId)}</div>
        <div class="passkey-user">${escapeHtml(passkey.userDisplayName || passkey.userName || 'Unknown')}</div>
        <div class="passkey-meta">
          <span class="passkey-date">${formatDate(passkey.createdAt)}</span>
        </div>
      </div>
      <div class="passkey-actions">
        <button class="btn btn-danger delete-btn" data-id="${passkey.credentialId}">Delete</button>
      </div>
    </div>
  `;
}

// Handle search
function handleSearch(e) {
  const query = e.target.value.toLowerCase().trim();

  if (query) {
    clearSearchBtn.classList.remove('hidden');
    const filtered = allPasskeys.filter(p =>
      (p.rpId && p.rpId.toLowerCase().includes(query)) ||
      (p.rpName && p.rpName.toLowerCase().includes(query)) ||
      (p.userName && p.userName.toLowerCase().includes(query)) ||
      (p.userDisplayName && p.userDisplayName.toLowerCase().includes(query))
    );

    if (filtered.length === 0) {
      passkeysList.innerHTML = `
        <div class="no-results">
          <div class="no-results-icon">🔍</div>
          <p>No passkeys found for "${escapeHtml(query)}"</p>
        </div>
      `;
    } else {
      renderPasskeys(filtered);
    }
  } else {
    clearSearchBtn.classList.add('hidden');
    renderPasskeys(allPasskeys);
  }
}

// Clear search
function clearSearch() {
  searchInput.value = '';
  clearSearchBtn.classList.add('hidden');
  renderPasskeys(allPasskeys);
}

// Handle passkey deletion
async function handleDelete(e) {
  e.stopPropagation();
  const credentialId = e.target.dataset.id;

  const confirmed = await showConfirm(
    '🗑️',
    'Delete Passkey?',
    'This passkey will be permanently deleted and cannot be recovered.',
    'Delete',
    'Cancel',
    true
  );

  if (!confirmed) return;

  // Optimistic UI: remove from display immediately
  allPasskeys = allPasskeys.filter(pk => pk.credentialId !== credentialId);
  renderPasskeys(allPasskeys);
  renderCurrentSitePasskeys();

  // Then delete in background
  const result = await sendMessage('deletePasskey', { credentialId });

  if (!result.success) {
    // Reload if failed
    await showAlert('❌', 'Delete Failed', result.error);
    loadPasskeys();
  }
}

// Handle export
async function handleExport() {
  if (allPasskeys.length === 0) {
    await showAlert('📭', 'Nothing to Export', 'You don\'t have any passkeys yet.');
    return;
  }

  const result = await sendMessage('exportPasskeysBitwarden');

  if (!result.success) {
    await showAlert('❌', 'Export Failed', result.error || 'Unknown error');
    return;
  }

  const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `bitwarden_export_${new Date().toISOString().replace(/[:.]/g, '').slice(0, 15)}.json`;
  a.click();

  URL.revokeObjectURL(url);
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

// Show success message
function showSuccess(element, message) {
  element.textContent = message;
  element.classList.remove('hidden');
}

// Hide error/success message
function hideError(element) {
  element.classList.add('hidden');
}

// Show modal alert (replaces alert())
function showAlert(icon, title, message) {
  return new Promise((resolve) => {
    modalIcon.textContent = icon;
    modalTitle.textContent = title;
    modalMessage.textContent = message;
    modalActions.innerHTML = '<button class="btn btn-primary" id="modal-ok">OK</button>';
    modalOverlay.classList.remove('hidden');

    document.getElementById('modal-ok').addEventListener('click', () => {
      modalOverlay.classList.add('hidden');
      resolve();
    });
  });
}

// Show modal confirm (replaces confirm())
function showConfirm(icon, title, message, confirmText = 'Confirm', cancelText = 'Cancel', isDanger = false) {
  return new Promise((resolve) => {
    modalIcon.textContent = icon;
    modalTitle.textContent = title;
    modalMessage.textContent = message;

    const btnClass = isDanger ? 'btn btn-danger' : 'btn btn-primary';
    modalActions.innerHTML = `
      <button class="btn btn-secondary" id="modal-cancel">${cancelText}</button>
      <button class="${btnClass}" id="modal-confirm">${confirmText}</button>
    `;
    modalOverlay.classList.remove('hidden');

    document.getElementById('modal-cancel').addEventListener('click', () => {
      modalOverlay.classList.add('hidden');
      resolve(false);
    });

    document.getElementById('modal-confirm').addEventListener('click', () => {
      modalOverlay.classList.add('hidden');
      resolve(true);
    });
  });
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

// Format date
function formatDate(timestamp) {
  if (!timestamp) return 'Unknown';
  const date = new Date(timestamp);
  const now = new Date();
  const diff = now - date;

  // Less than 24 hours ago
  if (diff < 86400000) {
    const hours = Math.floor(diff / 3600000);
    if (hours === 0) {
      const minutes = Math.floor(diff / 60000);
      return minutes <= 1 ? 'Just now' : `${minutes}m ago`;
    }
    return `${hours}h ago`;
  }

  // Less than 7 days
  if (diff < 604800000) {
    const days = Math.floor(diff / 86400000);
    return days === 1 ? 'Yesterday' : `${days} days ago`;
  }

  // Default format
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

// ==================== SYNC FUNCTIONS ====================

// Load and display sync status
async function loadSyncStatus() {
  const result = await sendMessage('getSyncStatus');

  if (!result.success) {
    return;
  }

  if (result.enabled) {
    syncDisabled.classList.add('hidden');
    syncEnabled.classList.remove('hidden');

    // Load and display nsec
    const keyResult = await sendMessage('getNostrKey');
    if (keyResult.success) {
      currentSyncNsec = keyResult.nsec;
      syncKeyDisplay.value = keyResult.nsec;
      syncKeyDisplay.type = 'password';
    }

    // Display relays
    renderRelays(result.relays);

    // Display last sync
    if (result.lastSync > 0) {
      syncLastSync.textContent = `Last sync: ${formatDate(result.lastSync * 1000)}`;
    } else {
      syncLastSync.textContent = 'Last sync: never';
    }
  } else {
    syncDisabled.classList.remove('hidden');
    syncEnabled.classList.add('hidden');
    currentSyncNsec = null;
  }
}

// Render relays list
function renderRelays(relays) {
  syncRelaysList.innerHTML = relays.map(relay =>
    `<div class="sync-relay-item">${escapeHtml(relay)}</div>`
  ).join('');
}

// Handle create sync
async function handleCreateSync() {
  const confirmed = await showConfirm(
    '🔄',
    'Create Sync?',
    'This will generate a new sync key. Share this key with your other devices to sync passkeys.',
    'Create',
    'Cancel'
  );

  if (!confirmed) return;

  createSyncBtn.disabled = true;
  createSyncBtn.textContent = 'Creating...';

  const result = await sendMessage('createSync');

  createSyncBtn.disabled = false;
  createSyncBtn.textContent = 'Create new sync';

  if (result.success) {
    loadSyncStatus();
  } else {
    await showAlert('❌', 'Failed', result.error || 'Failed to create sync');
  }
}

// Handle join sync
async function handleJoinSync() {
  const nsec = joinSyncNsec.value.trim();

  if (!nsec) {
    joinSyncError.textContent = 'Please enter a sync key';
    joinSyncError.classList.remove('hidden');
    return;
  }

  if (!nsec.startsWith('nsec1')) {
    joinSyncError.textContent = 'Invalid sync key format (should start with nsec1)';
    joinSyncError.classList.remove('hidden');
    return;
  }

  joinSyncConfirm.disabled = true;
  joinSyncConfirm.textContent = 'Joining...';

  const result = await sendMessage('joinSync', { nsec });

  joinSyncConfirm.disabled = false;
  joinSyncConfirm.textContent = 'Join';

  if (result.success) {
    joinSyncModal.classList.add('hidden');
    await showAlert('✅', 'Sync Joined', 'Successfully joined sync. Your passkeys will now be synchronized.');
    loadSyncStatus();
    loadPasskeys();
  } else {
    joinSyncError.textContent = result.error || 'Failed to join sync';
    joinSyncError.classList.remove('hidden');
  }
}

// Toggle sync key visibility
function toggleSyncKeyVisibility() {
  if (syncKeyDisplay.type === 'password') {
    syncKeyDisplay.type = 'text';
    toggleSyncKeyBtn.textContent = '🙈';
  } else {
    syncKeyDisplay.type = 'password';
    toggleSyncKeyBtn.textContent = '👁️';
  }
}

// Copy sync key
async function copySyncKey() {
  if (currentSyncNsec) {
    try {
      await navigator.clipboard.writeText(currentSyncNsec);
      copySyncKeyBtn.textContent = '✓';
      setTimeout(() => {
        copySyncKeyBtn.textContent = '📋';
      }, 2000);
    } catch (e) {
      await showAlert('❌', 'Copy Failed', 'Failed to copy to clipboard');
    }
  }
}

// Open relays modal
async function openRelaysModal() {
  const result = await sendMessage('getSyncStatus');
  if (result.success && result.relays) {
    relaysTextarea.value = result.relays.join('\n');
  }
  relaysError.classList.add('hidden');
  relaysModal.classList.remove('hidden');
}

// Handle save relays
async function handleSaveRelays() {
  const lines = relaysTextarea.value.split('\n').map(l => l.trim()).filter(l => l);

  if (lines.length === 0) {
    relaysError.textContent = 'Please enter at least one relay';
    relaysError.classList.remove('hidden');
    return;
  }

  // Validate relay URLs
  for (const relay of lines) {
    if (!relay.startsWith('wss://') && !relay.startsWith('ws://')) {
      relaysError.textContent = `Invalid relay URL: ${relay}`;
      relaysError.classList.remove('hidden');
      return;
    }
  }

  relaysSave.disabled = true;
  relaysSave.textContent = 'Saving...';

  const result = await sendMessage('updateRelays', { relays: lines });

  relaysSave.disabled = false;
  relaysSave.textContent = 'Save';

  if (result.success) {
    relaysModal.classList.add('hidden');
    loadSyncStatus();
  } else {
    relaysError.textContent = result.error || 'Failed to save relays';
    relaysError.classList.remove('hidden');
  }
}

// Handle sync now
async function handleSyncNow() {
  syncNowBtn.disabled = true;
  syncNowBtn.textContent = 'Syncing...';

  const result = await sendMessage('syncNow');

  syncNowBtn.disabled = false;
  syncNowBtn.textContent = 'Sync now';

  if (result.success) {
    loadSyncStatus();
    loadPasskeys();
    await showAlert('✅', 'Sync Complete', `Synced ${result.merged} passkeys, published ${result.published} updates.`);
  } else {
    await showAlert('❌', 'Sync Failed', result.error || 'Unknown error');
  }
}

// Handle disable sync
async function handleDisableSync() {
  const confirmed = await showConfirm(
    '⚠️',
    'Disable Sync?',
    'Your passkeys will remain on this device, but will no longer sync with other devices. The sync key will be deleted.',
    'Disable',
    'Cancel',
    true
  );

  if (!confirmed) return;

  const result = await sendMessage('disableSync');

  if (result.success) {
    loadSyncStatus();
  } else {
    await showAlert('❌', 'Failed', result.error || 'Failed to disable sync');
  }
}
