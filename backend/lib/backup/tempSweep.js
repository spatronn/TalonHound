// Stale staging cleanup for BACKUP_DIR/.tmp.
//
// runBackup stages each job in `.tmp/<backupId>-<pid>/` and packs the archive to
// `.tmp/.partial-<archive>.<pid>.<ts>`. Both are removed by the owning process on
// success or failure; this sweep only handles what a crashed/killed process left
// behind. An entry is deleted only when it matches one of those two layouts, is
// not owned by a queued/running/verifying backup, and is older than minAgeMs.
// Anything else in `.tmp` is reported as unknown and left alone.

import fs from 'node:fs';
import path from 'node:path';

export const BACKUP_TEMP_MIN_AGE_MS = 6 * 60 * 60 * 1000;

const WORK_DIR_RE = /^(.+)-(\d+)$/;
const PARTIAL_RE = /^\.partial-(.+?)\.tar\.gz(?:\.enc)?\.(\d+)\.(\d+)$/;

/**
 * @param {string} name entry name directly under .tmp
 * @param {boolean} isDir
 * @returns {{ kind: 'work_dir'|'partial_archive', backupId: string } | null}
 */
export function classifyBackupTempEntry(name, isDir) {
  if (isDir) {
    const m = WORK_DIR_RE.exec(name);
    return m ? { kind: 'work_dir', backupId: m[1] } : null;
  }
  const m = PARTIAL_RE.exec(name);
  return m ? { kind: 'partial_archive', backupId: m[1] } : null;
}

async function entryBytes(abs, isDir) {
  if (!isDir) {
    const st = await fs.promises.stat(abs).catch(() => null);
    return st ? st.size : 0;
  }
  let total = 0;
  const stack = [abs];
  while (stack.length) {
    const dir = stack.pop();
    const children = await fs.promises.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const c of children) {
      const p = path.join(dir, c.name);
      if (c.isDirectory()) stack.push(p);
      else if (c.isFile()) total += (await fs.promises.stat(p).catch(() => ({ size: 0 }))).size;
    }
  }
  return total;
}

/**
 * Inspect (and optionally delete) stale staging entries.
 *
 * @param {string} backupDir
 * @param {{
 *   activeBackupIds?: Set<string>,
 *   now?: number,
 *   minAgeMs?: number,
 *   apply?: boolean
 * }} [opts]
 */
export async function sweepStaleBackupTemp(backupDir, {
  activeBackupIds = new Set(),
  now = Date.now(),
  minAgeMs = BACKUP_TEMP_MIN_AGE_MS,
  apply = true
} = {}) {
  const tmpRoot = path.join(backupDir, '.tmp');
  const result = {
    stale: 0,
    stale_bytes: 0,
    deleted: 0,
    deleted_bytes: 0,
    protected: 0,
    unknown: 0,
    failed: 0
  };
  const entries = await fs.promises.readdir(tmpRoot, { withFileTypes: true }).catch((err) => {
    if (err.code === 'ENOENT') return [];
    throw err;
  });
  for (const ent of entries) {
    if (!ent.isDirectory() && !ent.isFile()) {
      result.unknown += 1;
      continue;
    }
    const kind = classifyBackupTempEntry(ent.name, ent.isDirectory());
    if (!kind) {
      result.unknown += 1;
      continue;
    }
    if (activeBackupIds.has(kind.backupId)) {
      result.protected += 1;
      continue;
    }
    const abs = path.join(tmpRoot, ent.name);
    const st = await fs.promises.stat(abs).catch(() => null);
    if (!st || now - st.mtimeMs < minAgeMs) {
      result.protected += 1;
      continue;
    }
    const bytes = await entryBytes(abs, ent.isDirectory());
    result.stale += 1;
    result.stale_bytes += bytes;
    if (!apply) continue;
    try {
      await fs.promises.rm(abs, { recursive: true, force: true });
      result.deleted += 1;
      result.deleted_bytes += bytes;
    } catch {
      result.failed += 1;
    }
  }
  return result;
}
