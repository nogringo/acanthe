// Nostr client utilities for vault sync
import {
  generateSecretKey,
  getPublicKey,
  finalizeEvent,
  nip19,
  nip44
} from 'nostr-tools';
import { SimplePool } from 'nostr-tools/pool';

// Default relays
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.primal.net',
  'wss://nostr-01.yakihonne.com',
  'wss://nostr-01.uid.ovh'
];

// Kind for vault sync
const KIND_VAULT = 3078;
const KIND_DELETION = 5;

// App identifier tag (interoperable - Bitwarden format)
const APP_TAG = 'store:vault';

let pool = null;

// Initialize the relay pool
function initPool() {
  if (!pool) {
    pool = new SimplePool({
      enablePing: true,      // Detect disconnections
      enableReconnect: true  // Auto reconnect with backoff
    });
  }
  return pool;
}

// Close all connections
function closePool() {
  try {
    pool?.close();
  } catch (e) {
    console.warn('Error closing pool:', e);
  }
  pool = null;
}

// Generate a new Nostr key pair
function generateNostrKeyPair() {
  const secretKey = generateSecretKey();
  const publicKey = getPublicKey(secretKey);
  return { secretKey, publicKey };
}

// Convert secret key to nsec format
function secretKeyToNsec(secretKey) {
  return nip19.nsecEncode(secretKey);
}

// Convert nsec to secret key
function nsecToSecretKey(nsec) {
  const { type, data } = nip19.decode(nsec);
  if (type !== 'nsec') {
    throw new Error('Invalid nsec format');
  }
  return data;
}

// Convert public key to npub format
function publicKeyToNpub(publicKey) {
  return nip19.npubEncode(publicKey);
}

// Get public key from secret key
function getPublicKeyFromSecret(secretKey) {
  return getPublicKey(secretKey);
}

// Encrypt content using NIP-44 (to self)
function encryptContent(content, secretKey) {
  const publicKey = getPublicKey(secretKey);
  const conversationKey = nip44.getConversationKey(secretKey, publicKey);
  return nip44.encrypt(content, conversationKey);
}

// Decrypt content using NIP-44 (from self)
function decryptContent(encryptedContent, secretKey) {
  const publicKey = getPublicKey(secretKey);
  const conversationKey = nip44.getConversationKey(secretKey, publicKey);
  return nip44.decrypt(encryptedContent, conversationKey);
}

// Convert JWK private key to PKCS#8 base64
async function jwkToPkcs8(jwk) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: jwk.crv },
    true,
    ['sign']
  );
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
  return btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
}

// Convert PKCS#8 base64 to JWK
async function pkcs8ToJwk(pkcs8Base64, algorithm = 'ECDSA', namedCurve = 'P-256') {
  const pkcs8 = Uint8Array.from(atob(pkcs8Base64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: algorithm, namedCurve },
    true,
    ['sign']
  );
  return await crypto.subtle.exportKey('jwk', key);
}

// Convert internal passkey format to Bitwarden fido2Credentials format
async function passKeyToBitwarden(passkey) {
  const keyValue = await jwkToPkcs8(passkey.privateKey);

  return {
    credentialId: passkey.credentialId,
    keyType: 'public-key',
    keyAlgorithm: passkey.privateKey.crv === 'P-256' ? 'ECDSA' : 'ECDSA',
    keyCurve: passkey.privateKey.crv || 'P-256',
    keyValue: keyValue,
    rpId: passkey.rpId,
    rpName: passkey.rpName || passkey.rpId,
    userHandle: passkey.userId || '',
    userName: passkey.userName || '',
    userDisplayName: passkey.userDisplayName || '',
    counter: String(passkey.signCount || 0),
    discoverable: 'true',
    creationDate: passkey.createdAt
      ? new Date(passkey.createdAt).toISOString()
      : new Date().toISOString()
  };
}

// Convert Bitwarden fido2Credentials format to internal passkey format
async function bitwardenToPasskey(fido2Cred) {
  const curve = fido2Cred.keyCurve || 'P-256';
  const privateKeyJwk = await pkcs8ToJwk(fido2Cred.keyValue, 'ECDSA', curve);

  // Derive public key from private key
  const publicKeyJwk = { ...privateKeyJwk };
  delete publicKeyJwk.d;

  return {
    credentialId: fido2Cred.credentialId,
    privateKey: privateKeyJwk,
    publicKey: publicKeyJwk,
    rpId: fido2Cred.rpId,
    rpName: fido2Cred.rpName || fido2Cred.rpId,
    userId: fido2Cred.userHandle || '',
    userName: fido2Cred.userName || '',
    userDisplayName: fido2Cred.userDisplayName || '',
    signCount: parseInt(fido2Cred.counter || '0', 10),
    createdAt: fido2Cred.creationDate
      ? new Date(fido2Cred.creationDate).getTime()
      : Date.now()
  };
}

// Convert internal passkey to Bitwarden vault item
async function passKeyToVaultItem(passkey) {
  const fido2Cred = await passKeyToBitwarden(passkey);
  const now = new Date().toISOString();

  return {
    id: passkey.credentialId, // Use credentialId as item id
    type: 1, // Login type
    name: passkey.rpId,
    notes: null,
    favorite: false,
    fields: [],
    reprompt: 0,
    creationDate: fido2Cred.creationDate,
    revisionDate: now,
    login: {
      uris: [{ uri: `https://${passkey.rpId}/` }],
      username: passkey.userName || null,
      password: null,
      totp: null,
      fido2Credentials: [fido2Cred]
    }
  };
}

// Extract passkeys from Bitwarden vault item
async function vaultItemToPasskeys(item) {
  const passkeys = [];

  if (item.type === 1 && item.login?.fido2Credentials) {
    for (const fido2Cred of item.login.fido2Credentials) {
      try {
        const passkey = await bitwardenToPasskey(fido2Cred);
        passkeys.push(passkey);
      } catch (error) {
        console.error('Failed to convert fido2Credential:', error);
      }
    }
  }

  return passkeys;
}

// Create and sign a vault event
async function createVaultEvent(passkey, secretKey) {
  const vaultItem = await passKeyToVaultItem(passkey);
  const content = JSON.stringify(vaultItem);
  const encryptedContent = encryptContent(content, secretKey);

  const event = {
    kind: KIND_VAULT,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['d', APP_TAG]
    ],
    content: encryptedContent
  };

  return finalizeEvent(event, secretKey);
}

// Create a deletion event (NIP-09)
function createDeletionEvent(eventIdToDelete, secretKey) {
  const event = {
    kind: KIND_DELETION,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['e', eventIdToDelete],
      ['k', KIND_VAULT.toString()]
    ],
    content: ''
  };

  return finalizeEvent(event, secretKey);
}

// Publish an event to relays
async function publishEvent(event, relays = DEFAULT_RELAYS) {
  const p = initPool();
  const results = await Promise.allSettled(
    p.publish(relays, event)
  );

  const successes = results.filter(r => r.status === 'fulfilled').length;
  return { successes, total: relays.length };
}

// Fetch all vault events for a public key
async function fetchVaultEvents(publicKey, relays = DEFAULT_RELAYS, since = 0) {
  const p = initPool();

  const filter = {
    kinds: [KIND_VAULT],
    authors: [publicKey],
    '#d': [APP_TAG]
  };

  if (since > 0) {
    filter.since = since;
  }

  const events = await p.querySync(relays, filter);
  return events;
}

// Fetch deletion events for a public key
async function fetchDeletionEvents(publicKey, relays = DEFAULT_RELAYS, since = 0) {
  const p = initPool();

  const filter = {
    kinds: [KIND_DELETION],
    authors: [publicKey],
    '#k': [KIND_VAULT.toString()]
  };

  if (since > 0) {
    filter.since = since;
  }

  const events = await p.querySync(relays, filter);
  return events;
}

// Subscribe to new vault events
function subscribeToVault(publicKey, relays, onEvent, onEose) {
  const p = initPool();

  const filter = {
    kinds: [KIND_VAULT, KIND_DELETION],
    authors: [publicKey],
    since: Math.floor(Date.now() / 1000)
  };

  const sub = p.subscribeMany(relays, [filter], {
    onevent: onEvent,
    oneose: onEose
  });

  return sub;
}

// Parse a vault event (decrypt and extract vault item)
async function parseVaultEvent(event, secretKey) {
  try {
    const decryptedContent = decryptContent(event.content, secretKey);
    const vaultItem = JSON.parse(decryptedContent);

    return {
      eventId: event.id,
      createdAt: event.created_at,
      vaultItem
    };
  } catch (error) {
    console.error('Failed to parse vault event:', error);
    return null;
  }
}

// Get deleted event IDs from deletion events
function getDeletedEventIds(deletionEvents) {
  const deletedIds = new Set();

  for (const event of deletionEvents) {
    for (const tag of event.tags) {
      if (tag[0] === 'e') {
        deletedIds.add(tag[1]);
      }
    }
  }

  return deletedIds;
}

// Export utilities
export {
  DEFAULT_RELAYS,
  KIND_VAULT,
  KIND_DELETION,
  APP_TAG,
  initPool,
  closePool,
  generateNostrKeyPair,
  secretKeyToNsec,
  nsecToSecretKey,
  publicKeyToNpub,
  getPublicKeyFromSecret,
  encryptContent,
  decryptContent,
  jwkToPkcs8,
  pkcs8ToJwk,
  passKeyToBitwarden,
  bitwardenToPasskey,
  passKeyToVaultItem,
  vaultItemToPasskeys,
  createVaultEvent,
  createDeletionEvent,
  publishEvent,
  fetchVaultEvents,
  fetchDeletionEvents,
  subscribeToVault,
  parseVaultEvent,
  getDeletedEventIds
};
