// SHA-256 checksum helpers for backup payloads.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createReadStream } from 'node:fs';

export function sha256Buffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export async function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Write checksums.sha256 for the listed relative paths under dir.
 * Format matches sha256sum: "<hex>  <relativePath>"
 */
export async function writeChecksumsFile(dir, relativePaths) {
  const lines = [];
  for (const rel of relativePaths) {
    const abs = path.join(dir, rel);
    const digest = await sha256File(abs);
    lines.push(`${digest}  ${rel.replace(/\\/g, '/')}`);
  }
  const out = path.join(dir, 'checksums.sha256');
  await fs.promises.writeFile(out, lines.join('\n') + '\n', 'utf8');
  return out;
}

/**
 * Verify checksums.sha256 against files on disk.
 * @returns {{ ok: boolean, mismatches: string[], missing: string[] }}
 */
export async function verifyChecksumsFile(dir) {
  const file = path.join(dir, 'checksums.sha256');
  let text;
  try {
    text = await fs.promises.readFile(file, 'utf8');
  } catch {
    return { ok: false, mismatches: [], missing: ['checksums.sha256'] };
  }
  const mismatches = [];
  const missing = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const m = trimmed.match(/^([0-9a-fA-F]{64})\s+\*?\s*(.+)$/);
    if (!m) continue;
    const expected = m[1].toLowerCase();
    const rel = m[2].trim();
    const abs = path.join(dir, rel);
    try {
      const actual = await sha256File(abs);
      if (actual !== expected) mismatches.push(rel);
    } catch {
      missing.push(rel);
    }
  }
  return { ok: mismatches.length === 0 && missing.length === 0, mismatches, missing };
}
