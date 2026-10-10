/**
 * Session advisory lock for Threat Library Create IOCs.
 * Prevents concurrent bulk creation on the same report (double-submit / retry).
 * Held on a dedicated pooled connection for the duration of the confirm path.
 */

const LOCK_PREFIX = 'threat-library:create-iocs:';

/**
 * @param {import('pg').Pool} pool
 * @param {number|string} reportId
 * @returns {Promise<{ acquired: boolean, release: () => Promise<void> }>}
 */
export async function acquireCreateIocsLock(pool, reportId) {
  if (!pool || typeof pool.connect !== 'function') {
    // Unit-test fakes without connect(): treat as acquired (single-threaded).
    return { acquired: true, async release() {} };
  }
  const key = `${LOCK_PREFIX}${Number(reportId)}`;
  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      'SELECT pg_try_advisory_lock(hashtext($1)) AS ok',
      [key]
    );
    if (rows[0]?.ok === true) {
      let released = false;
      return {
        acquired: true,
        async release() {
          if (released) return;
          released = true;
          try {
            await client.query(
              'SELECT pg_advisory_unlock(hashtext($1))',
              [key]
            );
          } catch {
            /* lock freed when the connection closes */
          } finally {
            client.release();
          }
        }
      };
    }
    client.release();
    return { acquired: false, async release() {} };
  } catch (err) {
    client.release(err instanceof Error ? err : new Error(String(err)));
    throw err;
  }
}

export function createIocsInProgressError() {
  return {
    ok: false,
    status: 409,
    code: 'create_iocs_in_progress',
    error: 'IOC creation is already in progress for this report. Wait for it to finish before starting another.'
  };
}
