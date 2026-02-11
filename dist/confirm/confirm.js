// Confirmation popup logic

const params = new URLSearchParams(window.location.search);
const requestId = params.get('requestId');
const action = params.get('action');
const origin = params.get('origin');
const rpName = params.get('rpName');
const userName = params.get('userName');
const accountsJson = params.get('accounts');

let selectedCredentialId = null;
let accounts = [];

// Parse accounts if provided
try {
  if (accountsJson) {
    accounts = JSON.parse(decodeURIComponent(accountsJson));
  }
} catch (e) {
  console.error('Failed to parse accounts:', e);
}

// Update UI based on action type
const iconEl = document.getElementById('icon');
const titleEl = document.getElementById('title');
const subtitleEl = document.getElementById('subtitle');
const siteEl = document.getElementById('site');
const actionDescEl = document.getElementById('action-description');
const accountsSectionEl = document.getElementById('accounts-section');
const accountsListEl = document.getElementById('accounts-list');
const userInfoEl = document.getElementById('user-info');
const userNameEl = document.getElementById('user-name');
const confirmBtn = document.getElementById('confirm-btn');

// Set site name
const siteName = rpName || (origin ? new URL(origin).hostname : '-');
siteEl.textContent = siteName;

if (action === 'create') {
  // Registration flow
  iconEl.textContent = '🔑';
  titleEl.textContent = 'Create Passkey';
  subtitleEl.textContent = 'A new passkey will be created';
  actionDescEl.innerHTML = `<strong>${siteName}</strong> wants to create a passkey for your account. This passkey will be stored securely in this extension.`;
  confirmBtn.textContent = 'Create Passkey';

  if (userName) {
    userInfoEl.style.display = 'block';
    userNameEl.textContent = userName;
  }

} else if (action === 'get') {
  // Authentication flow
  iconEl.textContent = '🔓';
  titleEl.textContent = 'Sign In';
  subtitleEl.textContent = 'Use your passkey to authenticate';
  actionDescEl.innerHTML = `<strong>${siteName}</strong> wants to verify your identity using a passkey.`;
  confirmBtn.textContent = 'Sign In';

  // Show account selection if multiple accounts
  if (accounts.length > 0) {
    accountsSectionEl.style.display = 'block';

    accounts.forEach((account, index) => {
      const accountEl = document.createElement('div');
      accountEl.className = 'account-item' + (index === 0 ? ' selected' : '');
      accountEl.dataset.credentialId = account.credentialId;
      accountEl.innerHTML = `
        <div class="account-radio"></div>
        <span class="account-icon">👤</span>
        <div class="account-info">
          <div class="account-name">${escapeHtml(account.userDisplayName || account.userName || 'Unknown')}</div>
          <div class="account-detail">${escapeHtml(account.userName || '')}</div>
        </div>
      `;
      accountEl.addEventListener('click', () => selectAccount(accountEl, account.credentialId));
      accountsListEl.appendChild(accountEl);
    });

    // Select first account by default
    if (accounts.length > 0) {
      selectedCredentialId = accounts[0].credentialId;
    }
  } else if (userName) {
    // Single account, show info
    userInfoEl.style.display = 'block';
    userNameEl.textContent = userName;
  }
}

// Select account
function selectAccount(element, credentialId) {
  document.querySelectorAll('.account-item').forEach(el => el.classList.remove('selected'));
  element.classList.add('selected');
  selectedCredentialId = credentialId;
}

// Handle confirm
document.getElementById('confirm-btn').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    action: 'confirmResponse',
    requestId,
    confirmed: true,
    selectedCredentialId
  });
  window.close();
});

// Handle cancel
document.getElementById('cancel-btn').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    action: 'confirmResponse',
    requestId,
    confirmed: false
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

// Escape HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}
