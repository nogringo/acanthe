// Content script - injects the WebAuthn override script into pages

(function() {
  // Inject the script into the page context
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('injected.js');
  script.onload = function() {
    this.remove();
  };
  (document.head || document.documentElement).appendChild(script);

  // Listen for messages from the injected script
  window.addEventListener('message', async (event) => {
    if (event.source !== window) return;

    const { type, action, data, requestId } = event.data;

    if (type !== 'PASSKEY_EXTENSION_REQUEST') return;

    try {
      // Forward request to background script
      const response = await chrome.runtime.sendMessage({
        action,
        data: {
          ...data,
          origin: window.location.origin
        }
      });

      // Send response back to injected script
      window.postMessage({
        type: 'PASSKEY_EXTENSION_RESPONSE',
        requestId,
        response
      }, '*');
    } catch (error) {
      window.postMessage({
        type: 'PASSKEY_EXTENSION_RESPONSE',
        requestId,
        response: { success: false, error: error.message }
      }, '*');
    }
  });

  // Notify injected script that content script is ready
  window.postMessage({ type: 'PASSKEY_EXTENSION_READY' }, '*');
})();
