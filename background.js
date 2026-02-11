// Background service worker for Passkey Manager
import {
  encrypt,
  decrypt,
  generateKeyPair,
  sign,
  generateCredentialId,
  sha256,
  hashPassword,
  publicKeyToCose,
  arrayBufferToBase64,
  base64ToArrayBuffer
} from './lib/crypto.js';

// Session state
let sessionKey = null;
let isUnlocked = false;

// Pending confirmation requests
const pendingConfirmations = new Map();

// Storage keys
const STORAGE_KEYS = {
  MASTER_PASSWORD_HASH: 'masterPasswordHash',
  PASSKEYS: 'passkeys',
  SALT: 'salt'
};

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Passkey Manager installed');
});

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse);
  return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
  const { action, data, requestId, confirmed } = message;

  switch (action) {
    case 'checkSetup':
      return await checkSetup();

    case 'setupMasterPassword':
      return await setupMasterPassword(data.password);

    case 'unlock':
      return await unlock(data.password);

    case 'lock':
      return lock();

    case 'isUnlocked':
      return { success: true, unlocked: isUnlocked };

    case 'getPasskeys':
      return await getPasskeys();

    case 'deletePasskey':
      return await deletePasskey(data.credentialId);

    case 'changePassword':
      return await changePassword(data.currentPassword, data.newPassword);

    case 'reset':
      return await resetExtension();

    case 'createCredential':
      return await handleCreateCredential(data.options, data.origin);

    case 'getAssertion':
      return await handleGetAssertion(data.options, data.origin);

    case 'confirmResponse':
      return handleConfirmResponse(requestId, confirmed, message.selectedCredentialId);

    case 'unlockResponse':
      return handleUnlockResponse(requestId, message.unlocked);

    default:
      return { success: false, error: 'Unknown action' };
  }
}

// Show confirmation popup
async function showConfirmation(action, origin, rpName, userName, accounts = null) {
  const requestId = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  return new Promise((resolve) => {
    pendingConfirmations.set(requestId, resolve);

    const params = new URLSearchParams({
      requestId,
      action,
      origin,
      rpName: rpName || '',
      userName: userName || ''
    });

    // Add accounts for selection if provided
    if (accounts && accounts.length > 0) {
      params.set('accounts', encodeURIComponent(JSON.stringify(accounts)));
    }

    // Calculate height based on number of accounts
    const baseHeight = 320;
    const accountHeight = accounts ? Math.min(accounts.length, 4) * 60 : 0;
    const windowHeight = baseHeight + accountHeight;

    chrome.windows.create({
      url: `confirm/confirm.html?${params.toString()}`,
      type: 'popup',
      width: 460,
      height: windowHeight,
      focused: true
    });

    // Timeout after 60 seconds
    setTimeout(() => {
      if (pendingConfirmations.has(requestId)) {
        pendingConfirmations.delete(requestId);
        resolve({ confirmed: false });
      }
    }, 60000);
  });
}

// Handle confirmation response
function handleConfirmResponse(requestId, confirmed, selectedCredentialId) {
  const resolve = pendingConfirmations.get(requestId);
  if (resolve) {
    pendingConfirmations.delete(requestId);
    resolve({ confirmed, selectedCredentialId });
  }
  return { success: true };
}

// Pending unlock requests
const pendingUnlocks = new Map();

// Show unlock popup
async function showUnlockPopup(origin) {
  const requestId = `unlock_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  return new Promise((resolve) => {
    pendingUnlocks.set(requestId, resolve);

    const params = new URLSearchParams({
      requestId,
      origin: origin || ''
    });

    chrome.windows.create({
      url: `unlock/unlock.html?${params.toString()}`,
      type: 'popup',
      width: 450,
      height: 380,
      focused: true
    });

    // Timeout after 60 seconds
    setTimeout(() => {
      if (pendingUnlocks.has(requestId)) {
        pendingUnlocks.delete(requestId);
        resolve(false);
      }
    }, 60000);
  });
}

// Handle unlock response
function handleUnlockResponse(requestId, unlocked) {
  const resolve = pendingUnlocks.get(requestId);
  if (resolve) {
    pendingUnlocks.delete(requestId);
    resolve(unlocked);
  }
  return { success: true };
}

// Handle create credential with confirmation
async function handleCreateCredential(options, origin) {
  if (!isUnlocked) {
    // Show unlock popup
    const unlocked = await showUnlockPopup(origin);
    if (!unlocked || !isUnlocked) {
      return { success: false, error: 'Extension is locked' };
    }
  }

  const { publicKey } = options;
  const rpName = publicKey.rp.name || publicKey.rp.id || new URL(origin).hostname;
  const userName = publicKey.user.displayName || publicKey.user.name;

  // Show confirmation popup
  const result = await showConfirmation('create', origin, rpName, userName);

  if (!result.confirmed) {
    return { success: false, error: 'User denied the request' };
  }

  return await createCredential(options, origin);
}

// Handle get assertion with confirmation
async function handleGetAssertion(options, origin) {
  if (!isUnlocked) {
    // Show unlock popup
    const unlocked = await showUnlockPopup(origin);
    if (!unlocked || !isUnlocked) {
      return { success: false, error: 'Extension is locked' };
    }
  }

  const { publicKey } = options;
  const rpId = publicKey.rpId || new URL(origin).hostname;

  // Check if we have a matching passkey first
  const result = await chrome.storage.local.get(STORAGE_KEYS.PASSKEYS);
  const encryptedData = result[STORAGE_KEYS.PASSKEYS];

  if (!encryptedData || !encryptedData.data) {
    return { success: false, error: 'No passkeys found' };
  }

  let passkeys;
  try {
    passkeys = await decrypt(encryptedData, sessionKey);
  } catch (e) {
    return { success: false, error: 'No passkeys found' };
  }

  // Filter by rpId
  let matchingPasskeys = passkeys.filter(pk => pk.rpId === rpId);

  if (publicKey.allowCredentials && publicKey.allowCredentials.length > 0) {
    const allowedIds = publicKey.allowCredentials.map(c => {
      if (typeof c.id === 'string') return c.id;
      return arrayBufferToBase64(c.id);
    });

    matchingPasskeys = matchingPasskeys.filter(pk => {
      const normalizedPkId = pk.credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      return allowedIds.some(id => {
        const normalizedAllowedId = id.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        return normalizedPkId === normalizedAllowedId || pk.credentialId === id;
      });
    });
  }

  if (matchingPasskeys.length === 0) {
    return { success: false, error: 'No matching passkey found for this site' };
  }

  // Prepare accounts for selection (only metadata, no private keys)
  const accountsForSelection = matchingPasskeys.map(pk => ({
    credentialId: pk.credentialId,
    userName: pk.userName,
    userDisplayName: pk.userDisplayName,
    rpName: pk.rpName
  }));

  // Show confirmation popup with account selection
  const confirmResult = await showConfirmation('get', origin, matchingPasskeys[0].rpName || rpId, null, accountsForSelection);

  if (!confirmResult.confirmed) {
    return { success: false, error: 'User denied the request' };
  }

  // Find the selected passkey
  let selectedPasskey;
  if (confirmResult.selectedCredentialId) {
    selectedPasskey = matchingPasskeys.find(pk => pk.credentialId === confirmResult.selectedCredentialId);
  }
  if (!selectedPasskey) {
    selectedPasskey = matchingPasskeys[0]; // Fallback to first
  }

  return await getAssertion(options, origin, selectedPasskey.credentialId);
}

// Check if master password is set up
async function checkSetup() {
  const result = await chrome.storage.local.get(STORAGE_KEYS.MASTER_PASSWORD_HASH);
  return {
    success: true,
    isSetup: !!result[STORAGE_KEYS.MASTER_PASSWORD_HASH]
  };
}

// Setup master password
async function setupMasterPassword(password) {
  if (!password || password.length < 8) {
    return { success: false, error: 'Password must be at least 8 characters' };
  }

  try {
    // Generate salt for Argon2id
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltBase64 = arrayBufferToBase64(salt);

    // Hash the password with Argon2id for verification
    const passwordHash = await hashPassword(password, salt);

    // Store hash and salt
    await chrome.storage.local.set({
      [STORAGE_KEYS.MASTER_PASSWORD_HASH]: passwordHash,
      [STORAGE_KEYS.SALT]: saltBase64,
      [STORAGE_KEYS.PASSKEYS]: { salt: saltBase64, iv: '', data: '' }
    });

    // Unlock session
    sessionKey = password;
    isUnlocked = true;

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Unlock with password
async function unlock(password) {
  try {
    const result = await chrome.storage.local.get([
      STORAGE_KEYS.MASTER_PASSWORD_HASH,
      STORAGE_KEYS.SALT
    ]);
    const storedHash = result[STORAGE_KEYS.MASTER_PASSWORD_HASH];
    const saltBase64 = result[STORAGE_KEYS.SALT];

    if (!storedHash || !saltBase64) {
      return { success: false, error: 'Master password not set up' };
    }

    // Verify password with Argon2id
    const salt = new Uint8Array(base64ToArrayBuffer(saltBase64));
    const passwordHash = await hashPassword(password, salt);

    if (passwordHash !== storedHash) {
      return { success: false, error: 'Invalid password' };
    }

    sessionKey = password;
    isUnlocked = true;

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Lock session
function lock() {
  sessionKey = null;
  isUnlocked = false;
  return { success: true };
}

// Get all passkeys (metadata only, not private keys)
async function getPasskeys() {
  if (!isUnlocked) {
    return { success: false, error: 'Extension is locked' };
  }

  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.PASSKEYS);
    const encryptedData = result[STORAGE_KEYS.PASSKEYS];

    if (!encryptedData || !encryptedData.data) {
      return { success: true, passkeys: [] };
    }

    const passkeys = await decrypt(encryptedData, sessionKey);

    // Return metadata only (no private keys)
    const metadata = passkeys.map(pk => ({
      credentialId: pk.credentialId,
      rpId: pk.rpId,
      rpName: pk.rpName,
      userName: pk.userName,
      userDisplayName: pk.userDisplayName,
      createdAt: pk.createdAt
    }));

    return { success: true, passkeys: metadata };
  } catch (error) {
    if (error.message.includes('Decryption failed')) {
      return { success: true, passkeys: [] };
    }
    return { success: false, error: error.message };
  }
}

// Delete a passkey
async function deletePasskey(credentialId) {
  if (!isUnlocked) {
    return { success: false, error: 'Extension is locked' };
  }

  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.PASSKEYS);
    const encryptedData = result[STORAGE_KEYS.PASSKEYS];

    let passkeys = [];
    if (encryptedData && encryptedData.data) {
      passkeys = await decrypt(encryptedData, sessionKey);
    }

    passkeys = passkeys.filter(pk => pk.credentialId !== credentialId);

    const newEncrypted = await encrypt(passkeys, sessionKey);
    await chrome.storage.local.set({ [STORAGE_KEYS.PASSKEYS]: newEncrypted });

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Create a new credential (registration)
async function createCredential(options, origin) {
  try {
    const { publicKey } = options;
    const rpId = publicKey.rp.id || new URL(origin).hostname;

    // Generate credential ID and key pair
    const credentialIdBytes = generateCredentialId();
    const credentialId = arrayBufferToBase64(credentialIdBytes);
    const keyPair = await generateKeyPair();

    // Create authenticator data
    const rpIdHash = await sha256(new TextEncoder().encode(rpId));
    const flags = 0x45; // UP (user present) + UV (user verified) + AT (attested credential data)
    const signCount = new Uint8Array([0, 0, 0, 0]);

    // AAGUID (16 bytes of zeros for software authenticator)
    const aaguid = new Uint8Array(16);

    // Credential ID length (2 bytes, big endian)
    const credIdLength = new Uint8Array([(credentialIdBytes.length >> 8) & 0xff, credentialIdBytes.length & 0xff]);

    // COSE public key
    const cosePublicKey = publicKeyToCose(keyPair.publicKey);

    // Construct authenticator data
    const authData = new Uint8Array([
      ...rpIdHash,
      flags,
      ...signCount,
      ...aaguid,
      ...credIdLength,
      ...credentialIdBytes,
      ...cosePublicKey
    ]);

    // Create attestation object (none format)
    const attestationObject = createAttestationObject(authData);

    // Store the passkey
    await storePasskey({
      credentialId,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      rpId,
      rpName: publicKey.rp.name,
      userId: arrayBufferToBase64(publicKey.user.id),
      userName: publicKey.user.name,
      userDisplayName: publicKey.user.displayName,
      createdAt: Date.now(),
      signCount: 0
    });

    // Return response
    return {
      success: true,
      credential: {
        id: credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        rawId: credentialId,
        type: 'public-key',
        response: {
          clientDataJSON: arrayBufferToBase64(createClientDataJSON('webauthn.create', options.publicKey.challenge, origin)),
          attestationObject: arrayBufferToBase64(attestationObject)
        },
        authenticatorAttachment: 'platform',
        clientExtensionResults: {}
      }
    };
  } catch (error) {
    console.error('Create credential error:', error);
    return { success: false, error: error.message };
  }
}

// Get assertion (authentication)
async function getAssertion(options, origin, selectedCredentialId = null) {
  try {
    const { publicKey } = options;
    const rpId = publicKey.rpId || new URL(origin).hostname;

    // Get stored passkeys
    const result = await chrome.storage.local.get(STORAGE_KEYS.PASSKEYS);
    const encryptedData = result[STORAGE_KEYS.PASSKEYS];

    if (!encryptedData || !encryptedData.data) {
      return { success: false, error: 'No passkeys found' };
    }

    let passkeys = await decrypt(encryptedData, sessionKey);

    // Filter by rpId
    let matchingPasskeys = passkeys.filter(pk => pk.rpId === rpId);

    // If allowCredentials is specified, filter by credential ID
    if (publicKey.allowCredentials && publicKey.allowCredentials.length > 0) {
      const allowedIds = publicKey.allowCredentials.map(c => {
        if (typeof c.id === 'string') {
          return c.id;
        }
        return arrayBufferToBase64(c.id);
      });

      matchingPasskeys = matchingPasskeys.filter(pk => {
        const normalizedPkId = pk.credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        return allowedIds.some(id => {
          const normalizedAllowedId = id.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
          return normalizedPkId === normalizedAllowedId || pk.credentialId === id;
        });
      });
    }

    if (matchingPasskeys.length === 0) {
      return { success: false, error: 'No matching passkey found for this site' };
    }

    // Use selected passkey or fallback to first
    let passkey;
    if (selectedCredentialId) {
      passkey = matchingPasskeys.find(pk => pk.credentialId === selectedCredentialId);
    }
    if (!passkey) {
      passkey = matchingPasskeys[0];
    }

    // Increment sign count
    passkey.signCount = (passkey.signCount || 0) + 1;

    // Create authenticator data
    const rpIdHash = await sha256(new TextEncoder().encode(rpId));
    const flags = 0x05; // UP (user present) + UV (user verified)
    const signCountBytes = new Uint8Array([
      (passkey.signCount >> 24) & 0xff,
      (passkey.signCount >> 16) & 0xff,
      (passkey.signCount >> 8) & 0xff,
      passkey.signCount & 0xff
    ]);

    const authData = new Uint8Array([
      ...rpIdHash,
      flags,
      ...signCountBytes
    ]);

    // Create client data JSON
    const clientDataJSON = createClientDataJSON('webauthn.get', publicKey.challenge, origin);

    // Create signature
    const clientDataHash = await sha256(clientDataJSON);
    const signedData = new Uint8Array([...authData, ...clientDataHash]);
    const signature = await sign(passkey.privateKey, signedData);

    // Update stored passkey with new sign count
    const passkeysUpdated = passkeys.map(pk =>
      pk.credentialId === passkey.credentialId ? passkey : pk
    );
    const newEncrypted = await encrypt(passkeysUpdated, sessionKey);
    await chrome.storage.local.set({ [STORAGE_KEYS.PASSKEYS]: newEncrypted });

    return {
      success: true,
      credential: {
        id: passkey.credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        rawId: passkey.credentialId,
        type: 'public-key',
        response: {
          clientDataJSON: arrayBufferToBase64(clientDataJSON),
          authenticatorData: arrayBufferToBase64(authData),
          signature: arrayBufferToBase64(signature),
          userHandle: passkey.userId
        },
        authenticatorAttachment: 'platform',
        clientExtensionResults: {}
      }
    };
  } catch (error) {
    console.error('Get assertion error:', error);
    return { success: false, error: error.message };
  }
}

// Store passkey
async function storePasskey(passkey) {
  const result = await chrome.storage.local.get(STORAGE_KEYS.PASSKEYS);
  const encryptedData = result[STORAGE_KEYS.PASSKEYS];

  let passkeys = [];
  if (encryptedData && encryptedData.data) {
    try {
      passkeys = await decrypt(encryptedData, sessionKey);
    } catch (e) {
      passkeys = [];
    }
  }

  passkeys.push(passkey);

  const newEncrypted = await encrypt(passkeys, sessionKey);
  await chrome.storage.local.set({ [STORAGE_KEYS.PASSKEYS]: newEncrypted });
}

// Convert base64 to base64url
function toBase64Url(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Create client data JSON
function createClientDataJSON(type, challenge, origin) {
  let challengeStr;
  if (typeof challenge === 'string') {
    // Convert from standard base64 to base64url
    challengeStr = toBase64Url(challenge);
  } else if (challenge instanceof ArrayBuffer || challenge instanceof Uint8Array) {
    challengeStr = toBase64Url(arrayBufferToBase64(challenge));
  } else {
    challengeStr = toBase64Url(arrayBufferToBase64(new Uint8Array(Object.values(challenge))));
  }

  const clientData = {
    type,
    challenge: challengeStr,
    origin,
    crossOrigin: false
  };

  return new TextEncoder().encode(JSON.stringify(clientData));
}

// Create attestation object (none format)
function createAttestationObject(authData) {
  // Simple CBOR encoding for attestation object
  // { fmt: "none", attStmt: {}, authData: <bytes> }

  const fmtBytes = new TextEncoder().encode('none');
  const items = [];

  // Map with 3 items
  items.push(0xa3);

  // "fmt" key
  items.push(0x63); // text string of length 3
  items.push(...new TextEncoder().encode('fmt'));
  // "none" value
  items.push(0x64); // text string of length 4
  items.push(...fmtBytes);

  // "attStmt" key
  items.push(0x67); // text string of length 7
  items.push(...new TextEncoder().encode('attStmt'));
  // Empty map value
  items.push(0xa0);

  // "authData" key
  items.push(0x68); // text string of length 8
  items.push(...new TextEncoder().encode('authData'));
  // Byte string value
  if (authData.length <= 255) {
    items.push(0x58, authData.length);
  } else {
    items.push(0x59, (authData.length >> 8) & 0xff, authData.length & 0xff);
  }
  items.push(...authData);

  return new Uint8Array(items);
}

// Change master password
async function changePassword(currentPassword, newPassword) {
  if (!isUnlocked) {
    return { success: false, error: 'Extension is locked' };
  }

  if (!newPassword || newPassword.length < 8) {
    return { success: false, error: 'New password must be at least 8 characters' };
  }

  try {
    // Verify current password
    const result = await chrome.storage.local.get([
      STORAGE_KEYS.MASTER_PASSWORD_HASH,
      STORAGE_KEYS.SALT,
      STORAGE_KEYS.PASSKEYS
    ]);

    const storedHash = result[STORAGE_KEYS.MASTER_PASSWORD_HASH];
    const saltBase64 = result[STORAGE_KEYS.SALT];

    if (!storedHash || !saltBase64) {
      return { success: false, error: 'Master password not set up' };
    }

    const salt = new Uint8Array(base64ToArrayBuffer(saltBase64));
    const currentHash = await hashPassword(currentPassword, salt);

    if (currentHash !== storedHash) {
      return { success: false, error: 'Current password is incorrect' };
    }

    // Decrypt passkeys with old password
    let passkeys = [];
    const encryptedData = result[STORAGE_KEYS.PASSKEYS];
    if (encryptedData && encryptedData.data) {
      passkeys = await decrypt(encryptedData, currentPassword);
    }

    // Generate new salt and hash for new password
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newSaltBase64 = arrayBufferToBase64(newSalt);
    const newPasswordHash = await hashPassword(newPassword, newSalt);

    // Re-encrypt passkeys with new password
    const newEncrypted = await encrypt(passkeys, newPassword);

    // Store new hash, salt and re-encrypted passkeys
    await chrome.storage.local.set({
      [STORAGE_KEYS.MASTER_PASSWORD_HASH]: newPasswordHash,
      [STORAGE_KEYS.SALT]: newSaltBase64,
      [STORAGE_KEYS.PASSKEYS]: newEncrypted
    });

    // Update session key
    sessionKey = newPassword;

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Reset extension (delete all data)
async function resetExtension() {
  try {
    await chrome.storage.local.clear();
    sessionKey = null;
    isUnlocked = false;
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}
