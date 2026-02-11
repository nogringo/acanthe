// Crypto utilities for passkey encryption/decryption
import { argon2id } from 'hash-wasm';

// Argon2id parameters (OWASP recommendations)
const ARGON2_MEMORY = 65536; // 64 MB
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 4;
const ARGON2_HASH_LENGTH = 32;

const SALT_LENGTH = 16;
const IV_LENGTH = 12;

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Convert ArrayBuffer to Hex string
function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Convert Hex string to ArrayBuffer
function hexToArrayBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

// Derive encryption key from master password using Argon2id
async function deriveKey(password, salt) {
  // Derive key using Argon2id
  const derivedKey = await argon2id({
    password,
    salt,
    parallelism: ARGON2_PARALLELISM,
    iterations: ARGON2_ITERATIONS,
    memorySize: ARGON2_MEMORY,
    hashLength: ARGON2_HASH_LENGTH,
    outputType: 'binary'
  });

  // Import as AES-GCM key
  return crypto.subtle.importKey(
    'raw',
    derivedKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt data with AES-GCM
async function encrypt(data, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(password, salt);

  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(JSON.stringify(data));

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    dataBuffer
  );

  return {
    salt: arrayBufferToBase64(salt),
    iv: arrayBufferToBase64(iv),
    data: arrayBufferToBase64(encryptedBuffer)
  };
}

// Decrypt data with AES-GCM
async function decrypt(encryptedObj, password) {
  const salt = new Uint8Array(base64ToArrayBuffer(encryptedObj.salt));
  const iv = new Uint8Array(base64ToArrayBuffer(encryptedObj.iv));
  const encryptedData = base64ToArrayBuffer(encryptedObj.data);

  const key = await deriveKey(password, salt);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encryptedData
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedBuffer));
  } catch (error) {
    throw new Error('Decryption failed - invalid password');
  }
}

// Generate ECDSA P-256 key pair for passkeys
async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign', 'verify']
  );

  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  return {
    publicKey: publicKeyJwk,
    privateKey: privateKeyJwk
  };
}

// Sign data with ECDSA private key
async function sign(privateKeyJwk, data) {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );

  return new Uint8Array(signature);
}

// Generate random bytes
function generateRandomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

// Generate credential ID
function generateCredentialId() {
  return generateRandomBytes(32);
}

// Hash data with SHA-256
async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

// Hash password with Argon2id for verification
async function hashPassword(password, salt) {
  return argon2id({
    password,
    salt,
    parallelism: ARGON2_PARALLELISM,
    iterations: ARGON2_ITERATIONS,
    memorySize: ARGON2_MEMORY,
    hashLength: ARGON2_HASH_LENGTH,
    outputType: 'hex'
  });
}

// Convert public key JWK to COSE format for WebAuthn
function publicKeyToCose(publicKeyJwk) {
  const x = base64ToArrayBuffer(publicKeyJwk.x.replace(/-/g, '+').replace(/_/g, '/'));
  const y = base64ToArrayBuffer(publicKeyJwk.y.replace(/-/g, '+').replace(/_/g, '/'));

  // COSE Key format for EC2 P-256
  const coseKey = new Map();
  coseKey.set(1, 2);  // kty: EC2
  coseKey.set(3, -7); // alg: ES256
  coseKey.set(-1, 1); // crv: P-256
  coseKey.set(-2, new Uint8Array(x)); // x coordinate
  coseKey.set(-3, new Uint8Array(y)); // y coordinate

  return encodeCBOR(coseKey);
}

// Simple CBOR encoder for COSE key
function encodeCBOR(map) {
  const items = [];

  // Map header (0xa0 + size for small maps)
  items.push(0xa0 + map.size);

  for (const [key, value] of map) {
    // Encode key (integer)
    if (key >= 0 && key <= 23) {
      items.push(key);
    } else if (key >= 0) {
      items.push(0x18, key);
    } else if (key >= -24) {
      items.push(0x20 + (-1 - key));
    } else {
      items.push(0x38, -1 - key);
    }

    // Encode value
    if (typeof value === 'number') {
      if (value >= 0 && value <= 23) {
        items.push(value);
      } else if (value >= 0) {
        items.push(0x18, value);
      } else if (value >= -24) {
        items.push(0x20 + (-1 - value));
      } else {
        items.push(0x38, -1 - value);
      }
    } else if (value instanceof Uint8Array) {
      // Byte string
      if (value.length <= 23) {
        items.push(0x40 + value.length);
      } else if (value.length <= 255) {
        items.push(0x58, value.length);
      } else {
        items.push(0x59, (value.length >> 8) & 0xff, value.length & 0xff);
      }
      items.push(...value);
    }
  }

  return new Uint8Array(items);
}

// Export for ES modules
export {
  encrypt,
  decrypt,
  generateKeyPair,
  sign,
  generateRandomBytes,
  generateCredentialId,
  sha256,
  hashPassword,
  publicKeyToCose,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  arrayBufferToHex,
  hexToArrayBuffer
};
