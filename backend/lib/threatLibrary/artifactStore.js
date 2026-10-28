/**
 * Safe on-disk artifact storage for Threat Library uploads.
 * Paths are never exposed raw to clients — only storage_key (relative).
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { assertSafeRelativeName } from '../backup/pathSafety.js';

export function getThreatLibraryStorageRoot() {
  return process.env.THREAT_LIBRARY_STORAGE_DIR || '/data/threat-library';
}

/**
 * @param {string} storageKey relative key under storage root
 */
export function resolveStoragePath(storageKey) {
  const root = path.resolve(getThreatLibraryStorageRoot());
  const key = String(storageKey || '').replace(/^[/\\]+/, '');
  // Validate each segment
  for (const part of key.split(/[/\\]/)) {
    if (!part || part === '.' || part === '..') {
      const err = new Error('Invalid storage key');
      err.code = 'unsafe_path';
      throw err;
    }
    try {
      assertSafeRelativeName(part);
    } catch {
      // allow uuid-like and hashed names with limited charset
      if (!/^[A-Za-z0-9._\-]+$/.test(part)) {
        const err = new Error('Invalid storage key segment');
        err.code = 'unsafe_path';
        throw err;
      }
    }
  }
  const full = path.resolve(root, key);
  if (!full.startsWith(root + path.sep) && full !== root) {
    const err = new Error('Path escape blocked');
    err.code = 'unsafe_path';
    throw err;
  }
  return full;
}

/**
 * @param {number|string} reportId
 * @param {Buffer} buffer
 * @param {{ fileName?: string, ext?: string }} [opts]
 */
export async function storeArtifactBuffer(reportId, buffer, opts = {}) {
  const root = getThreatLibraryStorageRoot();
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const ext = opts.ext || path.extname(opts.fileName || '') || '.bin';
  const safeExt = /^\.[A-Za-z0-9]{1,8}$/.test(ext) ? ext : '.bin';
  const dirKey = `reports/${Number(reportId)}`;
  const fileKey = `${dirKey}/${sha256}${safeExt}`;
  const fullDir = resolveStoragePath(dirKey);
  await fs.mkdir(fullDir, { recursive: true, mode: 0o750 });
  const fullPath = resolveStoragePath(fileKey);
  await fs.writeFile(fullPath, buffer, { mode: 0o640 });
  return { storageKey: fileKey.replace(/\\/g, '/'), sha256, sizeBytes: buffer.length };
}

/**
 * @param {string} storageKey
 */
export async function readArtifactBuffer(storageKey) {
  const full = resolveStoragePath(storageKey);
  return fs.readFile(full);
}

/**
 * Read-only comparison of files under reports/ with the storage keys the
 * database references. Unreferenced files are growth nothing will ever read;
 * missing keys are artifacts a refresh/retry would fail to load.
 *
 * @param {Iterable<string>} referencedKeys storage_key values from threat_report_artifacts
 */
export async function auditArtifactConsistency(referencedKeys) {
  const root = path.resolve(getThreatLibraryStorageRoot());
  const referenced = new Set([...referencedKeys].map((k) => String(k).replace(/\\/g, '/')));
  const seen = new Set();
  const result = { files: 0, bytes: 0, unreferenced: [], unreferenced_bytes: 0, missing: [] };
  const reportDirs = await fs.readdir(path.join(root, 'reports'), { withFileTypes: true }).catch((err) => {
    if (err.code === 'ENOENT') return [];
    throw err;
  });
  for (const dir of reportDirs) {
    if (!dir.isDirectory()) continue;
    const files = await fs.readdir(path.join(root, 'reports', dir.name), { withFileTypes: true });
    for (const f of files) {
      if (!f.isFile()) continue;
      const key = `reports/${dir.name}/${f.name}`;
      const { size } = await fs.stat(path.join(root, key));
      seen.add(key);
      result.files += 1;
      result.bytes += size;
      if (!referenced.has(key)) {
        result.unreferenced.push({ key, bytes: size });
        result.unreferenced_bytes += size;
      }
    }
  }
  for (const key of referenced) {
    if (!seen.has(key)) result.missing.push(key);
  }
  return result;
}

/**
 * Best-effort delete of report artifact directory.
 * @param {number|string} reportId
 */
export async function deleteReportArtifacts(reportId) {
  const dirKey = `reports/${Number(reportId)}`;
  try {
    const full = resolveStoragePath(dirKey);
    await fs.rm(full, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
}
