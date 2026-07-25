// Backup archive verification (pre-finalize and on-demand verify).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { extractTarGz, listTarGz, safeRmRf } from './archive.js';
import { verifyChecksumsFile, sha256File } from './checksums.js';
import { parseManifest, isCompatibleFormatVersion } from './manifest.js';
import { decryptFile, isEncryptedArchiveFilename } from './encryption.js';
import { dumpContainsExpectedObjects, pgRestoreList } from './pgDump.js';
import { loadEncryptionKey } from './config.js';

/**
 * Verify a finalized archive on disk.
 * @returns {{ ok: boolean, error?: string, errorCode?: string, manifest?: object, archiveChecksum?: string }}
 */
export async function verifyBackupArchive(archivePath, {
  encryptionKey = null,
  skipPgRestoreList = false
} = {}) {
  try {
    const st = await fs.promises.stat(archivePath);
    if (st.size <= 0) {
      return { ok: false, errorCode: 'VERIFY_FAILED', error: 'Archive size is zero' };
    }
    const archiveChecksum = await sha256File(archivePath);

    let workArchive = archivePath;
    const tmpRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-backup-verify-'));
    try {
      if (isEncryptedArchiveFilename(archivePath) || archivePath.endsWith('.enc')) {
        const key = encryptionKey || loadEncryptionKey();
        if (!key) {
          return { ok: false, errorCode: 'ENCRYPTION_KEY', error: 'Encrypted archive requires decryption key' };
        }
        workArchive = path.join(tmpRoot, 'archive.tar.gz');
        await decryptFile(archivePath, workArchive, key);
      }

      // Ensure archive opens
      const entries = await listTarGz(workArchive);
      if (!entries.length) {
        return { ok: false, errorCode: 'VERIFY_FAILED', error: 'Archive is empty' };
      }

      const extractDir = path.join(tmpRoot, 'extract');
      await extractTarGz(workArchive, extractDir);

      // Find bundle root (single top-level directory)
      const top = (await fs.promises.readdir(extractDir)).filter((n) => !n.startsWith('.'));
      if (top.length !== 1) {
        return { ok: false, errorCode: 'VERIFY_FAILED', error: 'Archive must contain a single top-level directory' };
      }
      const bundleDir = path.join(extractDir, top[0]);

      const manifestPath = path.join(bundleDir, 'manifest.json');
      let manifestRaw;
      try {
        manifestRaw = await fs.promises.readFile(manifestPath, 'utf8');
      } catch {
        return { ok: false, errorCode: 'MANIFEST_MISSING', error: 'manifest.json missing' };
      }
      const manifest = parseManifest(manifestRaw);
      if (!isCompatibleFormatVersion(manifest.format_version)) {
        return { ok: false, errorCode: 'VERIFY_FAILED', error: `Incompatible format version ${manifest.format_version}` };
      }

      const checksumResult = await verifyChecksumsFile(bundleDir);
      if (!checksumResult.ok) {
        return {
          ok: false,
          errorCode: 'CHECKSUM_MISMATCH',
          error: `Checksum mismatch: missing=${checksumResult.missing.join(',')} bad=${checksumResult.mismatches.join(',')}`,
          manifest
        };
      }

      const dumpRel = manifest.components?.postgres?.file || 'database/postgres.dump';
      const dumpPath = path.join(bundleDir, dumpRel);
      let dumpStat;
      try {
        dumpStat = await fs.promises.stat(dumpPath);
      } catch {
        // Legacy layout
        const legacy = path.join(bundleDir, 'postgres.dump');
        try {
          dumpStat = await fs.promises.stat(legacy);
        } catch {
          return { ok: false, errorCode: 'VERIFY_FAILED', error: 'postgres.dump missing', manifest };
        }
      }
      if (dumpStat.size <= 0) {
        return { ok: false, errorCode: 'VERIFY_FAILED', error: 'postgres.dump is empty', manifest };
      }

      if (!skipPgRestoreList) {
        const dumpFile = fs.existsSync(path.join(bundleDir, dumpRel))
          ? path.join(bundleDir, dumpRel)
          : path.join(bundleDir, 'postgres.dump');
        const { stdout } = await pgRestoreList(dumpFile);
        const objs = dumpContainsExpectedObjects(stdout);
        if (!objs.ok) {
          return {
            ok: false,
            errorCode: 'VERIFY_FAILED',
            error: `Dump missing expected objects: ${objs.missing.join(', ')}`,
            manifest
          };
        }
      }

      return { ok: true, manifest, archiveChecksum };
    } finally {
      await safeRmRf(tmpRoot);
    }
  } catch (err) {
    return {
      ok: false,
      errorCode: err.code || 'VERIFY_FAILED',
      error: err.message || 'Verification failed'
    };
  }
}

/** Verify an unpacked bundle directory (used mid-backup before packing). */
export async function verifyBundleDirectory(bundleDir, { skipPgRestoreList = false } = {}) {
  const manifestPath = path.join(bundleDir, 'manifest.json');
  const manifest = parseManifest(await fs.promises.readFile(manifestPath, 'utf8'));
  const checksumResult = await verifyChecksumsFile(bundleDir);
  if (!checksumResult.ok) {
    return { ok: false, errorCode: 'CHECKSUM_MISMATCH', error: 'Bundle checksum mismatch', manifest };
  }
  const dumpPath = path.join(bundleDir, 'database', 'postgres.dump');
  const st = await fs.promises.stat(dumpPath);
  if (st.size <= 0) return { ok: false, errorCode: 'VERIFY_FAILED', error: 'Empty dump', manifest };
  if (!skipPgRestoreList) {
    const { stdout } = await pgRestoreList(dumpPath);
    const objs = dumpContainsExpectedObjects(stdout);
    if (!objs.ok) {
      return { ok: false, errorCode: 'VERIFY_FAILED', error: `Missing: ${objs.missing.join(',')}`, manifest };
    }
  }
  return { ok: true, manifest };
}
