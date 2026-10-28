// Restore the Threat Library component of a format-3 backup into
// THREAT_LIBRARY_STORAGE_DIR, in two phases so a failed database restore
// never leaves the file store half-replaced:
//
//   stage  — verify the bundle component, copy it into <root>/.restore-<id>/reports,
//            re-hash every copy, set modes. The live reports/ tree is untouched.
//   commit — rename reports/ → .reports-pre-restore-<id> (rollback copy), then
//            .restore-<id>/reports → reports/. Both renames stay inside one volume.
//   abort  — delete the staging directory.
//
// Run commit only after pg_restore succeeded; the previous tree is kept until an
// operator removes it, so a bad restore can be rolled back by renaming it back.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import {
  THREAT_LIBRARY_COMPONENT_DIR,
  verifyThreatLibraryComponent
} from './threatLibraryComponent.js';

const RESTORE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/;

function restoreError(code, message) {
  return Object.assign(new Error(message), { code });
}

function assertRestoreId(id) {
  if (!RESTORE_ID_RE.test(String(id || ''))) throw restoreError('RESTORE_INVALID_ID', 'Invalid restore id');
}

export function stagingDirFor(storageRoot, restoreId) {
  assertRestoreId(restoreId);
  return path.join(path.resolve(storageRoot), `.restore-${restoreId}`);
}

export function previousDirFor(storageRoot, restoreId) {
  assertRestoreId(restoreId);
  return path.join(path.resolve(storageRoot), `.reports-pre-restore-${restoreId}`);
}

async function sha256Of(file) {
  const hash = crypto.createHash('sha256');
  await pipeline(fs.createReadStream(file), hash);
  return hash.digest('hex');
}

/**
 * @param {{ bundleDir: string, manifest: object, storageRoot: string, restoreId: string, minFreeMarginBytes?: number, statfs?: Function }} input
 * @returns {Promise<{ staged: number, bytes: number, stagingDir: string }>}
 */
export async function stageThreatLibraryRestore({
  bundleDir,
  manifest,
  storageRoot,
  restoreId,
  minFreeMarginBytes = 64 * 1024 * 1024,
  statfs = (p) => fs.promises.statfs(p)
}) {
  const component = manifest?.components?.threat_library;
  if (!component) throw restoreError('TL_COMPONENT_MISSING', 'Backup does not include Threat Library files');
  const verified = await verifyThreatLibraryComponent(bundleDir, component);
  if (!verified.ok) throw restoreError(verified.errorCode, verified.error);

  const root = path.resolve(storageRoot);
  await fs.promises.mkdir(root, { recursive: true, mode: 0o750 });
  const st = await statfs(root);
  const free = Number(st.bavail) * Number(st.bsize);
  if (free < verified.totalBytes + minFreeMarginBytes) {
    throw restoreError(
      'RESTORE_DISK_SPACE',
      `Not enough free space for Threat Library files: need ${verified.totalBytes + minFreeMarginBytes} bytes, have ${free}`
    );
  }

  const staging = stagingDirFor(root, restoreId);
  await fs.promises.rm(staging, { recursive: true, force: true });
  const srcBase = path.join(bundleDir, THREAT_LIBRARY_COMPONENT_DIR);
  try {
    for (const f of verified.index.files) {
      const parts = f.key.split('/');
      const dest = path.join(staging, ...parts);
      await fs.promises.mkdir(path.dirname(dest), { recursive: true, mode: 0o750 });
      await fs.promises.copyFile(path.join(srcBase, ...parts), dest, fs.constants.COPYFILE_EXCL);
      await fs.promises.chmod(dest, 0o640);
      if ((await sha256Of(dest)) !== f.sha256) {
        throw restoreError('TL_ARTIFACT_CORRUPT', `Staged copy does not match checksum: ${f.key}`);
      }
    }
    await fs.promises.mkdir(path.join(staging, 'reports'), { recursive: true, mode: 0o750 });
  } catch (err) {
    await fs.promises.rm(staging, { recursive: true, force: true }).catch(() => {});
    throw err;
  }
  return { staged: verified.index.files.length, bytes: verified.totalBytes, stagingDir: staging };
}

/**
 * Swap the staged tree in. The previous reports/ (if any) is preserved as
 * .reports-pre-restore-<id>; on a failed second rename it is moved back.
 */
export async function commitThreatLibraryRestore({ storageRoot, restoreId }) {
  const root = path.resolve(storageRoot);
  const staged = path.join(stagingDirFor(root, restoreId), 'reports');
  const live = path.join(root, 'reports');
  const previous = previousDirFor(root, restoreId);
  if (!(await fs.promises.stat(staged).catch(() => null))?.isDirectory()) {
    throw restoreError('RESTORE_NOT_STAGED', 'No staged Threat Library restore found');
  }
  if (await fs.promises.stat(previous).catch(() => null)) {
    throw restoreError('RESTORE_PREVIOUS_EXISTS', `${path.basename(previous)} already exists`);
  }
  const hadLive = Boolean(await fs.promises.stat(live).catch(() => null));
  if (hadLive) await fs.promises.rename(live, previous);
  try {
    await fs.promises.rename(staged, live);
  } catch (err) {
    if (hadLive) await fs.promises.rename(previous, live).catch(() => {});
    throw err;
  }
  await fs.promises.rm(stagingDirFor(root, restoreId), { recursive: true, force: true });
  return { previous: hadLive ? path.basename(previous) : null };
}

export async function abortThreatLibraryRestore({ storageRoot, restoreId }) {
  await fs.promises.rm(stagingDirFor(storageRoot, restoreId), { recursive: true, force: true });
}
