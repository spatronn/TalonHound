import bcrypt from 'bcrypt';
import {
  DEFAULT_ADMIN_EMAIL,
  DEFAULT_ADMIN_ROLE
} from './defaultAdminBootstrap.js';

/** The protected system administrator is the same identity as the default local admin. */
export const SYSTEM_ADMIN_EMAIL = DEFAULT_ADMIN_EMAIL;

/** Advisory lock key so concurrent restarts never race on reconcile/provision. */
export const SYSTEM_ADMIN_BOOTSTRAP_LOCK_KEY = 'talonhound:system-admin-bootstrap';

/** Actionable instruction surfaced whenever the system admin cannot be established at startup. */
export const SYSTEM_ADMIN_MANUAL_INSTRUCTION =
  'Create the protected system administrator with the secure CLI: `npm run create-system-admin` ' +
  '(backend). No account is auto-created on an existing install because there is no secure way to ' +
  'deliver an initial password at startup.';

/** Thrown when the invariant cannot be met (no system admin AND no other active admin). */
export class SystemAdminBootstrapError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SystemAdminBootstrapError';
  }
}

async function countActiveAdmins(client) {
  const res = await client.query(
    "SELECT COUNT(*)::int AS n FROM users WHERE role = 'admin' AND status = 'active'"
  );
  return Number(res.rows[0]?.n || 0);
}

/**
 * Resolve a "system admin could not be established" situation. Fails startup only when there is
 * no other active administrator to fall back on; otherwise continues but signals the caller to
 * emit a high-priority, actionable error. Never marks any success state, never touches secrets.
 */
function reportMissing({ log, activeAdminCount, reason }) {
  if (activeAdminCount === 0) {
    throw new SystemAdminBootstrapError(
      `No protected system administrator and no active administrator exists (${reason}). ` +
        `Startup aborted. ${SYSTEM_ADMIN_MANUAL_INSTRUCTION}`
    );
  }
  // Caller (server startup) turns this into a high-priority error log and keeps running.
  return { status: 'missing_manual_required', activeAdminCount, reason };
}

/**
 * Idempotently RECONCILE the protected system administrator flag on startup. This never creates
 * an account and never uses the well-known default password on an existing install:
 *
 *   - Row already flagged            → ensure role = 'admin' (defensive), else no-op.
 *   - admin@talonhound.local exists
 *     and is already an 'admin'      → mark is_system_admin = TRUE (unambiguously the bootstrap
 *                                      account). Password hash + profile are preserved.
 *   - admin@talonhound.local exists
 *     but is NOT an admin            → refuse to silently escalate privileges → missing (see below).
 *   - Account missing, users empty   → clean/uninitialized DB; defer to the first-install default
 *                                      admin bootstrap (which sets must_change_password = TRUE).
 *   - Account missing, users present → the dangerous existing-install case: do NOT auto-create.
 *                                      If another active admin exists, return
 *                                      'missing_manual_required'; otherwise throw
 *                                      SystemAdminBootstrapError so startup fails loudly.
 *
 * Email matching is case-insensitive. Restart-safe via an advisory lock. Never marks a success
 * setting on failure, and never logs a password/hash/token.
 *
 * @param {import('pg').Pool} pool
 * @param {{ logger?: { info?: Function, warn?: Function, error?: Function } }} [opts]
 * @returns {Promise<{ status: 'reconciled' | 'noop' | 'deferred_clean_install' | 'missing_manual_required' | 'skipped_lock', activeAdminCount?: number, reason?: string }>}
 */
export async function ensureSystemAdminAccount(pool, opts = {}) {
  const log = opts.logger || console;
  const client = await pool.connect();
  let lockHeld = false;

  try {
    const lock = await client.query(
      'SELECT pg_try_advisory_lock(hashtext($1)) AS acquired',
      [SYSTEM_ADMIN_BOOTSTRAP_LOCK_KEY]
    );
    lockHeld = Boolean(lock.rows[0]?.acquired);
    if (!lockHeld) {
      // Another instance holds the lock and will perform the reconcile.
      return { status: 'skipped_lock' };
    }

    await client.query('BEGIN');

    const existing = await client.query(
      `SELECT id, role, status, is_system_admin
       FROM users
       WHERE LOWER(username) = LOWER($1)
       FOR UPDATE`,
      [SYSTEM_ADMIN_EMAIL]
    );

    if (existing.rowCount) {
      const row = existing.rows[0];

      if (row.is_system_admin === true) {
        if (row.role !== DEFAULT_ADMIN_ROLE) {
          await client.query('UPDATE users SET role = $2::app_user_role WHERE id = $1', [row.id, DEFAULT_ADMIN_ROLE]);
          await client.query('COMMIT');
          log.info?.('[users] protected system administrator role reconciled to admin');
          return { status: 'reconciled', reason: 'role_fixed' };
        }
        await client.query('COMMIT');
        return { status: 'noop' };
      }

      // Not yet flagged. Only flag when this is unambiguously the bootstrap admin (already admin).
      if (row.role === DEFAULT_ADMIN_ROLE) {
        await client.query('UPDATE users SET is_system_admin = TRUE WHERE id = $1', [row.id]);
        await client.query('COMMIT');
        log.info?.('[users] existing admin@talonhound.local marked as protected system administrator (password/profile preserved)');
        return { status: 'reconciled', reason: 'flag_set' };
      }

      // Email exists but is NOT an admin: cannot safely tell it is the bootstrap account, so we
      // refuse to auto-promote it. Treat the system admin as unestablished.
      const activeAdminCount = await countActiveAdmins(client);
      await client.query('ROLLBACK');
      return reportMissing({ log, activeAdminCount, reason: 'email_exists_non_admin' });
    }

    // Account missing.
    const total = await client.query('SELECT COUNT(*)::int AS n FROM users');
    if (Number(total.rows[0]?.n || 0) === 0) {
      await client.query('ROLLBACK');
      log.info?.('[users] system administrator absent on an empty database; deferring to first-install bootstrap');
      return { status: 'deferred_clean_install' };
    }

    const activeAdminCount = await countActiveAdmins(client);
    await client.query('ROLLBACK');
    return reportMissing({ log, activeAdminCount, reason: 'account_missing' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    if (lockHeld) {
      await client
        .query('SELECT pg_advisory_unlock(hashtext($1))', [SYSTEM_ADMIN_BOOTSTRAP_LOCK_KEY])
        .catch(() => {});
    }
    client.release();
  }
}

/**
 * Operator-initiated provisioning of the protected system administrator (used by the secure CLI,
 * see scripts/create-system-admin.js). Unlike the startup reconcile, this MAY create the account —
 * because the initial password is supplied by the operator (or generated and revealed once on the
 * operator's terminal), never the well-known default. Idempotent:
 *
 *   - Missing  → create it: role admin, status active, is_system_admin = TRUE,
 *                must_change_password = TRUE, password = the provided plaintext (hashed here).
 *   - Present  → reconcile flag + role only; password hash and profile are preserved.
 *
 * The plaintext password is only hashed, never logged or returned.
 *
 * @param {import('pg').Pool} pool
 * @param {{ password: string, logger?: { info?: Function } }} args
 * @returns {Promise<{ status: 'created' | 'reconciled' }>}
 */
export async function provisionSystemAdmin(pool, { password, logger } = {}) {
  if (typeof password !== 'string' || !password) {
    throw new Error('provisionSystemAdmin requires a non-empty password');
  }
  const log = logger || console;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const existing = await client.query(
      `SELECT id FROM users WHERE LOWER(username) = LOWER($1) FOR UPDATE`,
      [SYSTEM_ADMIN_EMAIL]
    );

    if (existing.rowCount) {
      await client.query(
        'UPDATE users SET is_system_admin = TRUE, role = $2::app_user_role WHERE id = $1',
        [existing.rows[0].id, DEFAULT_ADMIN_ROLE]
      );
      await client.query('COMMIT');
      log.info?.('[system-admin] existing account reconciled as protected system administrator (password/profile preserved)');
      return { status: 'reconciled' };
    }

    const hash = await bcrypt.hash(password, 12);
    await client.query(
      `INSERT INTO users
         (username, password_hash, first_name, last_name, role, status, must_change_password, is_system_admin)
       VALUES
         ($1, $2, 'System', 'Administrator', $3::app_user_role, 'active'::app_user_status, TRUE, TRUE)`,
      [SYSTEM_ADMIN_EMAIL, hash, DEFAULT_ADMIN_ROLE]
    );
    await client.query('COMMIT');
    log.info?.('[system-admin] protected system administrator account created');
    return { status: 'created' };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
