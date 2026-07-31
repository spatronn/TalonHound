// Server-side AES-256-GCM encryption for revealable Published Feed API keys.
//
// The master key comes from API_KEY_ENCRYPTION_KEY (never persisted with the data):
//   * 64 hex characters  -> 32 raw bytes, or
//   * a base64 / raw string that decodes to exactly 32 bytes.
//
// Each secret is stored as three columns: ciphertext, nonce (IV) and auth tag.
// Nothing here ever logs the plaintext.

import crypto from 'node:crypto';

const IV_LEN = 12; // 96-bit nonce, recommended for GCM
const KEY_LEN = 32; // AES-256

let cachedKey; // undefined = not resolved yet, null = not configured

function decodeConfiguredKey(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;
  if (/^[0-9a-fA-F]{64}$/.test(value)) return Buffer.from(value, 'hex');
  // Accept base64 (or base64url) that decodes to exactly 32 bytes.
  try {
    const b64 = Buffer.from(value, 'base64');
    if (b64.length === KEY_LEN) return b64;
  } catch {
    /* fall through */
  }
  const rawBytes = Buffer.from(value, 'utf8');
  if (rawBytes.length === KEY_LEN) return rawBytes;
  throw Object.assign(
    new Error('API_KEY_ENCRYPTION_KEY must be 64 hex chars or 32 bytes (base64/raw)'),
    { code: 'API_KEY_ENCRYPTION_KEY' }
  );
}

/** @returns {Buffer|null} the 32-byte key, or null when encryption is not configured. */
export function getApiKeyEncryptionKey() {
  if (cachedKey === undefined) {
    cachedKey = decodeConfiguredKey(process.env.API_KEY_ENCRYPTION_KEY);
  }
  return cachedKey;
}

/** Test hook: forget the cached key after mutating process.env. */
export function resetApiKeyEncryptionKeyCache() {
  cachedKey = undefined;
}

export function isApiKeyEncryptionConfigured() {
  return getApiKeyEncryptionKey() != null;
}

/**
 * Encrypt a secret string.
 * @param {string} plaintext
 * @returns {{ ciphertext: Buffer, nonce: Buffer, tag: Buffer }}
 */
export function encryptApiKeySecret(plaintext) {
  const key = getApiKeyEncryptionKey();
  if (!key) {
    throw Object.assign(
      new Error('API_KEY_ENCRYPTION_KEY is not configured'),
      { code: 'API_KEY_ENCRYPTION_KEY' }
    );
  }
  const nonce = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, nonce, tag };
}

/**
 * Decrypt a stored secret. Throws (code: API_KEY_ENCRYPTION_KEY) on wrong key or tamper.
 * @param {{ ciphertext: Buffer, nonce: Buffer, tag: Buffer }} parts
 * @returns {string}
 */
export function decryptApiKeySecret({ ciphertext, nonce, tag }) {
  const key = getApiKeyEncryptionKey();
  if (!key) {
    throw Object.assign(
      new Error('API_KEY_ENCRYPTION_KEY is not configured'),
      { code: 'API_KEY_ENCRYPTION_KEY' }
    );
  }
  if (!Buffer.isBuffer(ciphertext) || !Buffer.isBuffer(nonce) || !Buffer.isBuffer(tag)) {
    throw Object.assign(new Error('Encrypted secret is incomplete'), { code: 'API_KEY_ENCRYPTION_KEY' });
  }
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch (err) {
    throw Object.assign(
      new Error('Failed to decrypt API key (wrong encryption key or corrupt ciphertext)'),
      { code: 'API_KEY_ENCRYPTION_KEY', cause: err }
    );
  }
}
