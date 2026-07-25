/**
 * Storage provider interface for backup archives.
 *
 * LocalFilesystemStorage is the only implemented provider in v1.
 * TODO(S3): add S3CompatibleStorage implementing the same methods when an
 * AWS/MinIO dependency is approved. Do not ship a half-working S3 client.
 *
 * Interface contract:
 *   ensureReady()
 *   putFile(localPath, storageKey) -> { storageKey, sizeBytes }
 *   getReadStream(storageKey)
 *   exists(storageKey) -> boolean
 *   delete(storageKey)
 *   resolveAbsolutePath(storageKey)  // local only; may throw on remote
 *   listKeys(prefix?) -> string[]
 *   totalBytes() -> number
 */

import fs from 'node:fs';
import path from 'node:path';
import { createReadStream } from 'node:fs';
import { ensureBackupDir, resolveBackupPath } from '../config.js';
import { assertSafeRelativeName } from '../pathSafety.js';

export class LocalFilesystemStorage {
  /** @param {string} rootDir */
  constructor(rootDir) {
    this.rootDir = path.resolve(rootDir);
  }

  async ensureReady() {
    ensureBackupDir(this.rootDir);
  }

  absolutePath(storageKey) {
    const name = assertSafeRelativeName(storageKey);
    return resolveBackupPath(this.rootDir, name);
  }

  async putFile(localPath, storageKey) {
    await this.ensureReady();
    const dest = this.absolutePath(storageKey);
    // Prefer rename when same filesystem; else copy+unlink
    try {
      await fs.promises.rename(localPath, dest);
    } catch {
      await fs.promises.copyFile(localPath, dest);
      await fs.promises.unlink(localPath).catch(() => {});
    }
    const st = await fs.promises.stat(dest);
    return { storageKey, sizeBytes: st.size, absolutePath: dest };
  }

  getReadStream(storageKey) {
    return createReadStream(this.absolutePath(storageKey));
  }

  async exists(storageKey) {
    try {
      await fs.promises.access(this.absolutePath(storageKey), fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  async delete(storageKey) {
    const p = this.absolutePath(storageKey);
    try {
      await fs.promises.unlink(p);
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
    }
  }

  resolveAbsolutePath(storageKey) {
    return this.absolutePath(storageKey);
  }

  async listKeys(prefix = '') {
    await this.ensureReady();
    const entries = await fs.promises.readdir(this.rootDir);
    return entries.filter((name) => {
      if (name.startsWith('.')) return false;
      if (prefix && !name.startsWith(prefix)) return false;
      return name.endsWith('.tar.gz') || name.endsWith('.tar.gz.enc');
    });
  }

  async totalBytes() {
    await this.ensureReady();
    const keys = await this.listKeys();
    let total = 0;
    for (const key of keys) {
      try {
        const st = await fs.promises.stat(this.absolutePath(key));
        total += st.size;
      } catch {
        /* skip */
      }
    }
    return total;
  }
}

export function createStorageProvider(backupDir) {
  return new LocalFilesystemStorage(backupDir);
}
