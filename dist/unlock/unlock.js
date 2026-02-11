// Unlock popup logic

const params = new URLSearchParams(window.location.search);
const requestId = params.get('requestId');
const origin = params.get('origin');

// Update UI
document.getElementById('site').textContent = origin ? new URL(origin).hostname : '-';

// Focus password field
document.getElementById('password').focus();

// Handle form submission
document.getElementById('unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const password = document.getElementById('password').value;
  const errorEl = document.getElementById('error');

  if (!password) {
    errorEl.textContent = 'Please enter your password';
    errorEl.style.display = 'block';
    return;
  }

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'unlock',
      data: { password }
    });

    if (result.success) {
      // Notify background that unlock was successful
      chrome.runtime.sendMessage({
        action: 'unlockResponse',
        requestId,
        unlocked: true
      });
      window.close();
    } else {
      errorEl.textContent = result.error || 'Invalid password';
      errorEl.style.display = 'block';
      document.getElementById('password').select();
    }
  } catch (error) {
    errorEl.textContent = 'An error occurred';
    errorEl.style.display = 'block';
  }
});

// Handle cancel
document.getElementById('cancel-btn').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    action: 'unlockResponse',
    requestId,
    unlocked: false
  });
  window.close();
});

// Auto-close on timeout (60 seconds)
setTimeout(() => {
  chrome.runtime.sendMessage({
    action: 'unlockResponse',
    requestId,
    unlocked: false
  });
  window.close();
}, 60000);

// Handle Enter key
document.getElementById('password').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    document.getElementById('unlock-form').dispatchEvent(new Event('submit'));
  }
});
