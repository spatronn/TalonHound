import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getApiKeyEncryptionKey,
  resetApiKeyEncryptionKeyCache,
  isApiKeyEncryptionConfigured,
  encryptApiKeySecret,
  decryptApiKeySecret
} from './apiKeyEncryption.js';

const KEY_A = 'a'.repeat(64); // 32 bytes hex
const KEY_B = 'b'.repeat(64);

function withKey(value) {
  if (value == null) delete process.env.API_KEY_ENCRYPTION_KEY;
  else process.env.API_KEY_ENCRYPTION_KEY = value;
  resetApiKeyEncryptionKeyCache();
}

test('not configured: reports unconfigured and refuses to encrypt', () => {
  withKey(null);
  assert.equal(isApiKeyEncryptionConfigured(), false);
  assert.equal(getApiKeyEncryptionKey(), null);
  assert.throws(() => encryptApiKeySecret('secret'), /not configured/);
});

test('rejects a malformed key', () => {
  withKey('too-short');
  assert.throws(() => getApiKeyEncryptionKey(), /API_KEY_ENCRYPTION_KEY/);
  withKey(null);
});

test('round-trips a secret', () => {
  withKey(KEY_A);
  const secret = 'th_pf_' + 'x'.repeat(40);
  const parts = encryptApiKeySecret(secret);
  assert.ok(Buffer.isBuffer(parts.ciphertext) && parts.ciphertext.length > 0);
  assert.equal(parts.nonce.length, 12);
  assert.equal(parts.tag.length, 16);
  assert.equal(decryptApiKeySecret(parts), secret);
  withKey(null);
});

test('tampered ciphertext fails authentication', () => {
  withKey(KEY_A);
  const parts = encryptApiKeySecret('th_pf_secret');
  parts.ciphertext[0] ^= 0xff;
  assert.throws(() => decryptApiKeySecret(parts), (err) => err.code === 'API_KEY_ENCRYPTION_KEY');
  withKey(null);
});

test('decrypting with a different key fails', () => {
  withKey(KEY_A);
  const parts = encryptApiKeySecret('th_pf_secret');
  withKey(KEY_B);
  assert.throws(() => decryptApiKeySecret(parts), (err) => err.code === 'API_KEY_ENCRYPTION_KEY');
  withKey(null);
});

test('accepts a 32-byte base64 key', () => {
  withKey(Buffer.alloc(32, 7).toString('base64'));
  assert.equal(isApiKeyEncryptionConfigured(), true);
  const parts = encryptApiKeySecret('hello');
  assert.equal(decryptApiKeySecret(parts), 'hello');
  withKey(null);
});
