import bcrypt from 'bcrypt';

export const DEFAULT_ADMIN_EMAIL = 'admin@talonhound.local';
export const DEFAULT_ADMIN_PASSWORD = 'admin';
export const DEFAULT_ADMIN_ROLE = 'admin';

/** Advisory lock key shared for default-admin bootstrap (race-safe across restarts). */
export const DEFAULT_ADMIN_BOOTSTRAP_LOCK_KEY = 'talonhound:default-admin-bootstrap';

/**
 * Ensure the clean-install default local admin exists exactly once.
 *
 * Runs only when:
 *   - system_settings.default_admin_bootstrapped is false, AND
 *   - the users table is empty
 *
 * After a successful attempt (insert or skip-because-users-exist), marks
 * default_admin_bootstrapped = true so later restarts never recreate the account
 * even if the users table becomes empty again.
 *
 * @param {import('pg').Pool} pool
 * @param {{ logger?: { info?: Function, warn?: Function } }} [opts]
 * @returns {Promise<{ status: 'created' | 'skipped_already_bootstrapped' | 'skipped_users_exist' | 'skipped_lock' }>}
 */
export async function ensureDefaultAdminBootstrap(pool, opts = {}) {
  const log = opts.logger || console;
  const client = await pool.connect();
  let lockHeld = false;

  try {
    const lock = await client.query(
      'SELECT pg_try_advisory_lock(hashtext($1)) AS acquired',
      [DEFAULT_ADMIN_BOOTSTRAP_LOCK_KEY]
    );
    lockHeld = Boolean(lock.rows[0]?.acquired);
    if (!lockHeld) {
      return { status: 'skipped_lock' };
    }

    await client.query('BEGIN');

    await client.query(`
      INSERT INTO system_settings (id)
      VALUES (1)
      ON CONFLICT (id) DO NOTHING
    `);

    const flagRes = await client.query(
      'SELECT default_admin_bootstrapped FROM system_settings WHERE id = 1 FOR UPDATE'
    );
    if (flagRes.rows[0]?.default_admin_bootstrapped) {
      await client.query('COMMIT');
      return { status: 'skipped_already_bootstrapped' };
    }

    const countRes = await client.query('SELECT COUNT(*)::int AS n FROM users');
    const userCount = Number(countRes.rows[0]?.n || 0);

    if (userCount > 0) {
      await client.query(
        `UPDATE system_settings
         SET default_admin_bootstrapped = TRUE,
             updated_at = NOW()
         WHERE id = 1`
      );
      await client.query('COMMIT');
      log.info?.('[users] default admin bootstrap skipped (users already exist)');
      return { status: 'skipped_users_exist' };
    }

    const hash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 12);
    await client.query(
      `INSERT INTO users (username, password_hash, first_name, last_name, role, must_change_password)
       VALUES ($1, $2, 'Local', 'Admin', $3::app_user_role, TRUE)`,
      [DEFAULT_ADMIN_EMAIL, hash, DEFAULT_ADMIN_ROLE]
    );

    await client.query(
      `UPDATE system_settings
       SET default_admin_bootstrapped = TRUE,
           updated_at = NOW()
       WHERE id = 1`
    );
    await client.query('COMMIT');
    log.info?.('[users] default local admin created for clean install');
    return { status: 'created' };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    log.warn?.('[users] default admin bootstrap failed:', err?.message || err);
    throw err;
  } finally {
    if (lockHeld) {
      await client
        .query('SELECT pg_advisory_unlock(hashtext($1))', [DEFAULT_ADMIN_BOOTSTRAP_LOCK_KEY])
        .catch(() => {});
    }
    client.release();
  }
}
