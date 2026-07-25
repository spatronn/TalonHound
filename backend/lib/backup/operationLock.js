// Concurrent backup operation lock (DB advisory lock + active-row check).

import crypto from 'node:crypto';

/** Stable int4 key derived from a string (for pg_advisory_lock). */
export function advisoryLockKey(name = 'talonhound:system-backup') {
  const hash = crypto.createHash('sha256').update(name).digest();
  // signed 32-bit
  return hash.readInt32BE(0);
}

/**
 * Try to acquire a session-level advisory lock. Caller must hold the client
 * for the duration of the critical section and release with unlock.
 * @returns {Promise<boolean>}
 */
export async function tryAcquireBackupLock(client, key = advisoryLockKey()) {
  const { rows } = await client.query('SELECT pg_try_advisory_lock($1) AS ok', [key]);
  return Boolean(rows[0]?.ok);
}

export async function releaseBackupLock(client, key = advisoryLockKey()) {
  await client.query('SELECT pg_advisory_unlock($1)', [key]);
}

/**
 * Pure helper: given a list of backup rows, is a new backup allowed?
 */
export function canStartBackup(activeCount, maxConcurrent = 1) {
  return activeCount < maxConcurrent;
}

export function assertCanStartBackup(activeCount, maxConcurrent = 1) {
  if (!canStartBackup(activeCount, maxConcurrent)) {
    const err = new Error('Another backup operation is already running');
    err.code = 'CONCURRENT';
    err.status = 409;
    throw err;
  }
}

/** Valid status transitions for system_backups */
const TRANSITIONS = {
  queued: new Set(['running', 'failed', 'interrupted', 'deleted']),
  running: new Set(['verifying', 'failed', 'interrupted']),
  verifying: new Set(['completed', 'failed', 'interrupted']),
  completed: new Set(['deleted']),
  failed: new Set(['queued', 'deleted']),
  interrupted: new Set(['queued', 'deleted']),
  deleted: new Set()
};

export function canTransition(from, to) {
  const set = TRANSITIONS[from];
  return Boolean(set && set.has(to));
}

export function assertTransition(from, to) {
  if (!canTransition(from, to)) {
    const err = new Error(`Invalid backup status transition ${from} → ${to}`);
    err.code = 'INVALID_TRANSITION';
    throw err;
  }
}

const RESTORE_TRANSITIONS = {
  pending_confirmation: new Set(['ready', 'cancelled', 'failed']),
  ready: new Set(['running', 'cancelled', 'failed']),
  running: new Set(['completed', 'failed']),
  completed: new Set(),
  failed: new Set(),
  cancelled: new Set()
};

export function canRestoreTransition(from, to) {
  const set = RESTORE_TRANSITIONS[from];
  return Boolean(set && set.has(to));
}
