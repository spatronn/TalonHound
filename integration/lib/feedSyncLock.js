/**
 * Per-feed synchronization exclusion via a PostgreSQL session advisory lock.
 *
 * This is the atomic, cross-process guard that makes same-feed overlap
 * impossible even when several worker slots (or several worker containers) pick
 * up jobs for the same feed at the same time. It reuses TalonHound's established
 * advisory-lock pattern (see importer.js pg_try_advisory_lock, feedPublisherService)
 * rather than a second locking system.
 *
 * Why an advisory *session* lock (not a row lock / transaction):
 *  - pg_try_advisory_lock is non-blocking: it returns immediately, so a busy
 *    feed never blocks a worker slot waiting.
 *  - It is held on a dedicated connection for the life of the sync but does NOT
 *    hold a transaction open — no idle-in-transaction, no vacuum/xid pressure —
 *    so it is safe to hold across the feed's HTTP download + ingestion.
 *  - It is released automatically by PostgreSQL if the connection/process dies,
 *    so a crashed worker leaves no permanent phantom lock.
 */

const LOCK_NAMESPACE = 'talonhound:feed-sync:';

/**
 * Try to acquire the per-feed exclusion lock.
 *
 * @param {import('pg').Pool} pool
 * @param {string} identity  Exclusion identity (see feedSyncLockIdentity).
 * @returns {Promise<{ acquired: boolean, release: () => Promise<void> }>}
 *   When acquired, `release()` unlocks and returns the connection to the pool.
 *   When not acquired, `release()` is a no-op (connection already returned).
 */
export async function acquireFeedSyncLock(pool, identity) {
  const lockName = `${LOCK_NAMESPACE}${identity}`;
  const client = await pool.connect();
  try {
    const { rows } = await client.query('SELECT pg_try_advisory_lock(hashtext($1)) AS ok', [lockName]);
    if (rows[0]?.ok === true) {
      let released = false;
      return {
        acquired: true,
        async release() {
          if (released) return;
          released = true;
          try {
            await client.query('SELECT pg_advisory_unlock(hashtext($1))', [lockName]);
          } catch {
            // Connection may already be gone; PostgreSQL frees the lock on close.
          } finally {
            client.release();
          }
        }
      };
    }
    client.release();
    return { acquired: false, async release() {} };
  } catch (err) {
    // Discard a possibly-broken connection and let the job fail/retry so its
    // queue slot is freed rather than leaked.
    client.release(err instanceof Error ? err : new Error(String(err)));
    throw err;
  }
}
