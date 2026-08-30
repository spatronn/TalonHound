// Generate backup_id and archive filenames.

import crypto from 'node:crypto';

function pad(n, w = 2) {
  return String(n).padStart(w, '0');
}

/** UTC stamp YYYYMMDD-HHMMSS */
export function utcStamp(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
    `-${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`
  );
}

export function generateBackupId(date = new Date()) {
  const short = crypto.randomBytes(4).toString('hex');
  return `backup-${utcStamp(date)}-${short}`;
}

export function archiveFilenameFor(backupId, { encrypted = false } = {}) {
  const base = `${backupId}.tar.gz`;
  return encrypted ? `${base}.enc` : base;
}
