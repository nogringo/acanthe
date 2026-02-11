// Injected script - overrides navigator.credentials for WebAuthn interception

(function() {
  'use strict';

  let requestCounter = 0;
  const pendingRequests = new Map();

  // Helper to generate unique request IDs
  function generateRequestId() {
    return `req_${++requestCounter}_${Date.now()}`;
  }

  // Helper to convert ArrayBuffer to Base64
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Helper to convert Base64 to ArrayBuffer
  function base64ToArrayBuffer(base64) {
    // Handle URL-safe base64
    const normalized = base64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Send message to content script and wait for response
  function sendMessage(action, data) {
    return new Promise((resolve, reject) => {
      const requestId = generateRequestId();

      pendingRequests.set(requestId, { resolve, reject });

      window.postMessage({
        type: 'PASSKEY_EXTENSION_REQUEST',
        action,
        data,
        requestId
      }, '*');

      // Timeout after 60 seconds
      setTimeout(() => {
        if (pendingRequests.has(requestId)) {
          pendingRequests.delete(requestId);
          reject(new Error('Request timeout'));
        }
      }, 60000);
    });
  }

  // Listen for responses from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    const { type, requestId, response } = event.data;

    if (type !== 'PASSKEY_EXTENSION_RESPONSE') return;

    const pending = pendingRequests.get(requestId);
    if (pending) {
      pendingRequests.delete(requestId);
      pending.resolve(response);
    }
  });

  // Serialize PublicKeyCredentialCreationOptions for messaging
  function serializeCreationOptions(options) {
    const serialized = {
      publicKey: {
        rp: options.publicKey.rp,
        user: {
          ...options.publicKey.user,
          id: arrayBufferToBase64(options.publicKey.user.id)
        },
        challenge: arrayBufferToBase64(options.publicKey.challenge),
        pubKeyCredParams: options.publicKey.pubKeyCredParams,
        timeout: options.publicKey.timeout,
        authenticatorSelection: options.publicKey.authenticatorSelection,
        attestation: options.publicKey.attestation
      }
    };

    if (options.publicKey.excludeCredentials) {
      serialized.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
        type: c.type,
        id: arrayBufferToBase64(c.id),
        transports: c.transports
      }));
    }

    return serialized;
  }

  // Serialize PublicKeyCredentialRequestOptions for messaging
  function serializeRequestOptions(options) {
    const serialized = {
      publicKey: {
        challenge: arrayBufferToBase64(options.publicKey.challenge),
        timeout: options.publicKey.timeout,
        rpId: options.publicKey.rpId,
        userVerification: options.publicKey.userVerification
      }
    };

    if (options.publicKey.allowCredentials) {
      serialized.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
        type: c.type,
        id: arrayBufferToBase64(c.id),
        transports: c.transports
      }));
    }

    return serialized;
  }

  // Create PublicKeyCredential response object
  function createCredentialResponse(credentialData) {
    const credential = {
      id: credentialData.id,
      rawId: base64ToArrayBuffer(credentialData.rawId),
      type: credentialData.type,
      authenticatorAttachment: credentialData.authenticatorAttachment,
      response: {
        clientDataJSON: base64ToArrayBuffer(credentialData.response.clientDataJSON),
        attestationObject: base64ToArrayBuffer(credentialData.response.attestationObject)
      },
      getClientExtensionResults: () => credentialData.clientExtensionResults || {}
    };

    // Add ArrayBuffer getters
    Object.defineProperty(credential.response, 'getTransports', {
      value: () => ['internal'],
      writable: false
    });

    Object.defineProperty(credential.response, 'getPublicKey', {
      value: () => null,
      writable: false
    });

    Object.defineProperty(credential.response, 'getPublicKeyAlgorithm', {
      value: () => -7, // ES256
      writable: false
    });

    Object.defineProperty(credential.response, 'getAuthenticatorData', {
      value: () => {
        // Extract authenticator data from attestation object
        return credential.response.attestationObject;
      },
      writable: false
    });

    return credential;
  }

  // Create PublicKeyCredential assertion response object
  function createAssertionResponse(credentialData) {
    const credential = {
      id: credentialData.id,
      rawId: base64ToArrayBuffer(credentialData.rawId),
      type: credentialData.type,
      authenticatorAttachment: credentialData.authenticatorAttachment,
      response: {
        clientDataJSON: base64ToArrayBuffer(credentialData.response.clientDataJSON),
        authenticatorData: base64ToArrayBuffer(credentialData.response.authenticatorData),
        signature: base64ToArrayBuffer(credentialData.response.signature),
        userHandle: credentialData.response.userHandle ? base64ToArrayBuffer(credentialData.response.userHandle) : null
      },
      getClientExtensionResults: () => credentialData.clientExtensionResults || {}
    };

    return credential;
  }

  // Store original methods
  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  // Override navigator.credentials.create
  navigator.credentials.create = async function(options) {
    // Only intercept WebAuthn requests
    if (!options || !options.publicKey) {
      return originalCreate(options);
    }

    console.log('[Passkey Extension] Intercepting credential creation', options);

    try {
      const serializedOptions = serializeCreationOptions(options);
      console.log('[Passkey Extension] Serialized options:', serializedOptions);

      const response = await sendMessage('createCredential', { options: serializedOptions });
      console.log('[Passkey Extension] Response from background:', response);

      if (response.success) {
        console.log('[Passkey Extension] Credential created successfully');
        const credential = createCredentialResponse(response.credential);
        console.log('[Passkey Extension] Returning credential:', credential);
        return credential;
      } else {
        console.error('[Passkey Extension] Creation failed:', response.error);
        // Throw error instead of falling back to avoid confusion
        throw new DOMException(response.error || 'Creation failed', 'NotAllowedError');
      }
    } catch (error) {
      console.error('[Passkey Extension] Error:', error);
      throw error;
    }
  };

  // Override navigator.credentials.get
  navigator.credentials.get = async function(options) {
    // Only intercept WebAuthn requests
    if (!options || !options.publicKey) {
      return originalGet(options);
    }

    console.log('[Passkey Extension] Intercepting credential request', options);

    try {
      const serializedOptions = serializeRequestOptions(options);
      console.log('[Passkey Extension] Serialized options:', serializedOptions);

      const response = await sendMessage('getAssertion', { options: serializedOptions });
      console.log('[Passkey Extension] Response from background:', response);

      if (response.success) {
        console.log('[Passkey Extension] Assertion created successfully');
        const credential = createAssertionResponse(response.credential);
        console.log('[Passkey Extension] Returning credential:', credential);
        return credential;
      } else {
        console.error('[Passkey Extension] Assertion failed:', response.error);
        // Throw error instead of falling back
        throw new DOMException(response.error || 'Assertion failed', 'NotAllowedError');
      }
    } catch (error) {
      console.error('[Passkey Extension] Error:', error);
      throw error;
    }
  };

  console.log('[Passkey Extension] WebAuthn methods overridden');
})();
