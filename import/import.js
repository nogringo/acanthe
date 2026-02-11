// Import page logic

const stepSelect = document.getElementById('step-select');
const stepPreview = document.getElementById('step-preview');
const stepResult = document.getElementById('step-result');

const fileDrop = document.getElementById('file-drop');
const fileInput = document.getElementById('import-file');
const selectFileBtn = document.getElementById('select-file-btn');

const previewCount = document.getElementById('preview-count');
const previewList = document.getElementById('preview-list');
const backBtn = document.getElementById('back-btn');
const importBtn = document.getElementById('import-btn');

const resultIcon = document.getElementById('result-icon');
const resultMessage = document.getElementById('result-message');
const closeBtn = document.getElementById('close-btn');

let pendingImportData = null;
let parsedPasskeys = []; // Full parsed data for selective import
let existingCredentialIds = new Set();

// File selection
selectFileBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  fileInput.click();
});

fileDrop.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
  if (e.target.files[0]) {
    handleFile(e.target.files[0]);
  }
});

// Drag and drop
fileDrop.addEventListener('dragover', (e) => {
  e.preventDefault();
  fileDrop.classList.add('dragover');
});

fileDrop.addEventListener('dragleave', () => {
  fileDrop.classList.remove('dragover');
});

fileDrop.addEventListener('drop', (e) => {
  e.preventDefault();
  fileDrop.classList.remove('dragover');
  if (e.dataTransfer.files[0]) {
    handleFile(e.dataTransfer.files[0]);
  }
});

// Handle file
async function handleFile(file) {
  try {
    const text = await file.text();
    const data = JSON.parse(text);

    // Get existing passkeys to detect duplicates
    const existingResult = await chrome.runtime.sendMessage({ action: 'getPasskeys' });
    if (existingResult.success && existingResult.passkeys) {
      existingCredentialIds = new Set(existingResult.passkeys.map(p => p.credentialId));
    }

    parsedPasskeys = extractPasskeys(data);

    if (parsedPasskeys.length === 0) {
      showResult(false, 'No passkeys found', 'The selected file does not contain any passkeys.');
      return;
    }

    pendingImportData = data;
    showPreview(parsedPasskeys);

  } catch (error) {
    showResult(false, 'Invalid file', 'Could not read the file. Make sure it\'s a valid JSON export.');
  }
}

// Convert UUID to base64 (same as background.js)
function uuidToBase64(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;
  if (!uuidRegex.test(uuid)) {
    return uuid;
  }
  const hex = uuid.replace(/-/g, '');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function extractPasskeys(data) {
  const passkeys = [];
  if (data.items && Array.isArray(data.items)) {
    for (const item of data.items) {
      if (!item.login?.fido2Credentials) continue;
      for (const cred of item.login.fido2Credentials) {
        const credentialId = uuidToBase64(cred.credentialId);
        passkeys.push({
          credentialId: credentialId,
          originalCredentialId: cred.credentialId,
          site: cred.rpName || cred.rpId || item.name,
          user: cred.userDisplayName || cred.userName || 'Unknown',
          isDuplicate: existingCredentialIds.has(credentialId)
        });
      }
    }
  }
  return passkeys;
}

function showPreview(passkeys) {
  const duplicateCount = passkeys.filter(p => p.isDuplicate).length;
  const newCount = passkeys.length - duplicateCount;

  let countText = `${passkeys.length} passkey${passkeys.length > 1 ? 's' : ''} found`;
  if (duplicateCount > 0) {
    countText += ` (${duplicateCount} already exist${duplicateCount > 1 ? '' : 's'})`;
  }
  previewCount.textContent = countText;

  previewList.innerHTML = passkeys.map((p, index) => {
    const initial = (p.user || '?')[0].toUpperCase();
    const checked = !p.isDuplicate ? 'checked' : '';
    const disabled = p.isDuplicate ? 'disabled' : '';
    const duplicateClass = p.isDuplicate ? ' duplicate' : '';
    const duplicateBadge = p.isDuplicate ? '<span class="duplicate-badge">Already exists</span>' : '';

    return `
      <label class="preview-item${duplicateClass}">
        <input type="checkbox" class="preview-checkbox" data-index="${index}" ${checked} ${disabled}>
        <div class="preview-avatar">${initial}</div>
        <div class="preview-info">
          <div class="preview-site">${escapeHtml(p.site)}${duplicateBadge}</div>
          <div class="preview-user">${escapeHtml(p.user)}</div>
        </div>
      </label>
    `;
  }).join('');

  updateImportButton();

  // Listen for checkbox changes
  previewList.querySelectorAll('.preview-checkbox').forEach(cb => {
    cb.addEventListener('change', updateImportButton);
  });

  stepSelect.classList.add('hidden');
  stepPreview.classList.remove('hidden');
}

function updateImportButton() {
  const checkedCount = previewList.querySelectorAll('.preview-checkbox:checked').length;
  importBtn.disabled = checkedCount === 0;
  importBtn.textContent = checkedCount === 0 ? 'Select passkeys to import' : `Import ${checkedCount} passkey${checkedCount > 1 ? 's' : ''}`;
}

// Navigation
backBtn.addEventListener('click', () => {
  stepPreview.classList.add('hidden');
  stepSelect.classList.remove('hidden');
  pendingImportData = null;
  fileInput.value = '';
});

// Import
importBtn.addEventListener('click', async () => {
  if (!pendingImportData) return;

  // Get selected credential IDs
  const selectedIds = new Set();
  previewList.querySelectorAll('.preview-checkbox:checked').forEach(cb => {
    const index = parseInt(cb.dataset.index, 10);
    selectedIds.add(parsedPasskeys[index].originalCredentialId);
  });

  if (selectedIds.size === 0) return;

  // Filter the original data to only include selected items
  const filteredData = {
    ...pendingImportData,
    items: pendingImportData.items.map(item => {
      if (!item.login?.fido2Credentials) return null;
      const filteredCreds = item.login.fido2Credentials.filter(cred =>
        selectedIds.has(cred.credentialId)
      );
      if (filteredCreds.length === 0) return null;
      return {
        ...item,
        login: {
          ...item.login,
          fido2Credentials: filteredCreds
        }
      };
    }).filter(Boolean)
  };

  importBtn.disabled = true;
  importBtn.textContent = 'Importing...';

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'importPasskeysBitwarden',
      data: { jsonData: JSON.stringify(filteredData) }
    });

    if (result.success) {
      showResult(true, 'Import complete!', `Imported: ${result.imported} passkey(s)`);
    } else {
      showResult(false, 'Import failed', result.error || 'Unknown error');
    }
  } catch (error) {
    showResult(false, 'Import failed', error.message);
  }
});

function showResult(success, title, message) {
  resultIcon.textContent = success ? '✓' : '✕';
  resultIcon.className = 'result-icon' + (success ? '' : ' error');
  resultMessage.innerHTML = `<h2>${escapeHtml(title)}</h2><p>${escapeHtml(message).replace(/\n/g, '<br>')}</p>`;

  stepSelect.classList.add('hidden');
  stepPreview.classList.add('hidden');
  stepResult.classList.remove('hidden');
}

closeBtn.addEventListener('click', () => {
  window.close();
});

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
