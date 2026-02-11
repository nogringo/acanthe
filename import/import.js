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

    const passkeys = extractPasskeys(data);

    if (passkeys.length === 0) {
      showResult(false, 'No passkeys found', 'The selected file does not contain any passkeys.');
      return;
    }

    pendingImportData = text;
    showPreview(passkeys);

  } catch (error) {
    showResult(false, 'Invalid file', 'Could not read the file. Make sure it\'s a valid JSON export.');
  }
}

function extractPasskeys(data) {
  const passkeys = [];
  if (data.items && Array.isArray(data.items)) {
    for (const item of data.items) {
      if (!item.login?.fido2Credentials) continue;
      for (const cred of item.login.fido2Credentials) {
        passkeys.push({
          site: cred.rpName || cred.rpId || item.name,
          user: cred.userDisplayName || cred.userName || 'Unknown'
        });
      }
    }
  }
  return passkeys;
}

function showPreview(passkeys) {
  previewCount.textContent = `${passkeys.length} passkey${passkeys.length > 1 ? 's' : ''} found:`;

  previewList.innerHTML = passkeys.map(p => {
    const initial = (p.user || '?')[0].toUpperCase();
    return `
      <div class="preview-item">
        <div class="preview-avatar">${initial}</div>
        <div class="preview-info">
          <div class="preview-site">${escapeHtml(p.site)}</div>
          <div class="preview-user">${escapeHtml(p.user)}</div>
        </div>
      </div>
    `;
  }).join('');

  stepSelect.classList.add('hidden');
  stepPreview.classList.remove('hidden');
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

  importBtn.disabled = true;
  importBtn.textContent = 'Importing...';

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'importPasskeysBitwarden',
      data: { jsonData: pendingImportData }
    });

    if (result.success) {
      showResult(true, 'Import complete!', `Imported: ${result.imported} passkey(s)\nSkipped (duplicates): ${result.skipped}`);
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
