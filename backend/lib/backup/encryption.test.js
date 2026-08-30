import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { encryptBuffer, decryptBuffer } from './encryption.js';

describe('backup encryption', () => {
  it('round-trips plaintext', () => {
    const key = crypto.randomBytes(32);
    const plain = Buffer.from('talonhound-backup-payload');
    const enc = encryptBuffer(plain, key);
    const dec = decryptBuffer(enc, key);
    assert.deepEqual(dec, plain);
  });

  it('fails with wrong key', () => {
    const key = crypto.randomBytes(32);
    const wrong = crypto.randomBytes(32);
    const enc = encryptBuffer(Buffer.from('secret'), key);
    assert.throws(() => decryptBuffer(enc, wrong));
  });
});
