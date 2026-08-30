// Path / filename validation for backup archives (path traversal defence).

const BACKUP_ID_RE = /^backup-[0-9]{8}-[0-9]{6}-[a-zA-Z0-9]{6,16}$/;
const ARCHIVE_NAME_RE = /^backup-[0-9]{8}-[0-9]{6}-[a-zA-Z0-9]{6,16}\.(tar\.gz|tar\.gz\.enc)$/;
const LEGACY_BUNDLE_RE = /^talonhound-[0-9]{8}T[0-9]{6}Z$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidBackupId(value) {
  const s = String(value || '').trim();
  return BACKUP_ID_RE.test(s) || LEGACY_BUNDLE_RE.test(s);
}

export function isValidArchiveFilename(value) {
  const s = String(value || '').trim();
  if (!s || s.includes('/') || s.includes('\\') || s.includes('..')) return false;
  return ARCHIVE_NAME_RE.test(s);
}

export function isValidRowId(value) {
  return UUID_RE.test(String(value || '').trim());
}

export function assertSafeRelativeName(name) {
  const s = String(name || '');
  if (!s || s.includes('\0') || s.includes('/') || s.includes('\\') || s.includes('..') || s.startsWith('.')) {
    const err = new Error('Invalid archive filename');
    err.code = 'INVALID_FILENAME';
    throw err;
  }
  return s;
}

/** Strip secrets / absolute paths from user-facing error messages. */
export function redactErrorMessage(message, { maxLen = 500 } = {}) {
  let s = String(message || 'Operation failed');
  s = s.replace(/PGPASSWORD=\S+/gi, 'PGPASSWORD=***');
  s = s.replace(/password[=:]\s*\S+/gi, 'password=***');
  s = s.replace(/-----BEGIN[\s\S]*?-----END[^-]+-----/g, '[REDACTED_KEY]');
  // Collapse absolute unix/windows paths that look like storage roots
  s = s.replace(/\/data\/backups\/[^\s'"]+/g, '[backup-path]');
  s = s.replace(/[A-Za-z]:\\[^\s'"]+/g, '[backup-path]');
  if (s.length > maxLen) s = s.slice(0, maxLen - 1) + '…';
  return s;
}

export function publicErrorMessage(code, message) {
  const map = {
    DISK_FULL: 'Backup storage is full.',
    PG_DUMP_MISSING: 'PostgreSQL client tools are not available in this container.',
    PG_DUMP_FAILED: 'Database dump failed.',
    PG_CONNECTION: 'Could not connect to PostgreSQL.',
    PERMISSION: 'Permission denied writing backup storage.',
    CHECKSUM_MISMATCH: 'Backup checksum verification failed.',
    MANIFEST_MISSING: 'Backup manifest is missing or unreadable.',
    ENCRYPTION_KEY: 'Encryption key is missing or invalid.',
    ARCHIVE_MISSING: 'Backup archive file was not found.',
    INVALID_FILENAME: 'Invalid backup identifier.',
    CONCURRENT: 'Another backup operation is already running.',
    CONFIRMATION: 'Restore confirmation did not match.',
    SAFETY_FAILED: 'Safety backup before restore failed.',
    NOT_FOUND: 'Backup not found.',
    ACTIVE: 'Cannot delete an active or in-use backup.',
    VERIFY_FAILED: 'Backup verification failed.'
  };
  return map[code] || redactErrorMessage(message) || 'Operation failed';
}
