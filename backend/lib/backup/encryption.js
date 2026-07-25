// Optional AES-256-GCM encryption for backup archives.
// Key is never written into the archive; load from BACKUP_ENCRYPTION_KEY_FILE.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';

const MAGIC = Buffer.from('THB1'); // TalonHound Backup v1 encrypted envelope
const IV_LEN = 12;
const TAG_LEN = 16;

/**
 * Encrypt file at srcPath → destPath.
 * Layout: MAGIC(4) | IV(12) | ciphertext | TAG(16 appended by GCM final)
 * We write MAGIC+IV then stream ciphertext; auth tag is appended at end.
 */
export async function encryptFile(srcPath, destPath, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw Object.assign(new Error('Encryption key must be 32 bytes'), { code: 'ENCRYPTION_KEY' });
  }
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const out = createWriteStream(destPath);
  out.write(MAGIC);
  out.write(iv);

  await pipeline(createReadStream(srcPath), cipher, out);

  // Append auth tag after ciphertext
  const tag = cipher.getAuthTag();
  await fs.promises.appendFile(destPath, tag);
  return destPath;
}

/**
 * Decrypt envelope at srcPath → destPath. Throws on wrong key / tamper.
 */
export async function decryptFile(srcPath, destPath, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw Object.assign(new Error('Encryption key must be 32 bytes'), { code: 'ENCRYPTION_KEY' });
  }
  const stat = await fs.promises.stat(srcPath);
  if (stat.size < MAGIC.length + IV_LEN + TAG_LEN + 1) {
    throw Object.assign(new Error('Encrypted archive is truncated'), { code: 'ENCRYPTION_KEY' });
  }

  const fd = await fs.promises.open(srcPath, 'r');
  try {
    const header = Buffer.alloc(MAGIC.length + IV_LEN);
    await fd.read(header, 0, header.length, 0);
    if (!header.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw Object.assign(new Error('Not an encrypted TalonHound backup'), { code: 'ENCRYPTION_KEY' });
    }
    const iv = header.subarray(MAGIC.length);

    const tag = Buffer.alloc(TAG_LEN);
    await fd.read(tag, 0, TAG_LEN, stat.size - TAG_LEN);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const ciphertextLen = stat.size - MAGIC.length - IV_LEN - TAG_LEN;
    const readStream = fs.createReadStream(srcPath, {
      start: MAGIC.length + IV_LEN,
      end: MAGIC.length + IV_LEN + ciphertextLen - 1
    });
    const out = createWriteStream(destPath);
    try {
      await pipeline(readStream, decipher, out);
    } catch (err) {
      throw Object.assign(new Error('Decryption failed (wrong key or corrupt archive)'), {
        code: 'ENCRYPTION_KEY',
        cause: err
      });
    }
  } finally {
    await fd.close();
  }
  return destPath;
}

export function isEncryptedArchiveFilename(name) {
  return String(name || '').endsWith('.tar.gz.enc');
}

/** Test helper: encrypt/decrypt round-trip in memory for small buffers. */
export function encryptBuffer(plain, key) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, iv, enc, tag]);
}

export function decryptBuffer(blob, key) {
  if (blob.length < MAGIC.length + IV_LEN + TAG_LEN + 1) {
    throw Object.assign(new Error('Truncated'), { code: 'ENCRYPTION_KEY' });
  }
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw Object.assign(new Error('Bad magic'), { code: 'ENCRYPTION_KEY' });
  }
  const iv = blob.subarray(MAGIC.length, MAGIC.length + IV_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const data = blob.subarray(MAGIC.length + IV_LEN, blob.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}
