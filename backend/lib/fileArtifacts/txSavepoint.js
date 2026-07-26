/**
 * Transaction savepoint helpers for File Artifact attach / provider backfill.
 * Prevents 25P02 chains when a statement fails inside an open transaction.
 */

/**
 * Run fn under a SAVEPOINT when the client is inside an open transaction.
 * Falls back to bare fn when SAVEPOINT is unavailable (autocommit / pool.query),
 * so dual-write callers can share one helper for both TX and non-TX paths.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} client
 * @param {string} name
 * @param {() => Promise<any>} fn
 */
export async function withSavepoint(client, name, fn) {
  const sp = String(name || 'fa_sp').replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 60) || 'fa_sp';
  try {
    await client.query(`SAVEPOINT ${sp}`);
  } catch (err) {
    // 25P01: no_active_sql_transaction — e.g. pool.query autocommit
    if (err?.code === '25P01' || /no transaction/i.test(String(err?.message || ''))) {
      return fn();
    }
    throw err;
  }
  try {
    const result = await fn();
    await client.query(`RELEASE SAVEPOINT ${sp}`);
    return result;
  } catch (err) {
    await client.query(`ROLLBACK TO SAVEPOINT ${sp}`).catch(() => {});
    throw err;
  }
}

/**
 * Controlled (non-fatal for provider loops) DB / domain outcomes.
 * @param {any} err
 */
export function isControlledFileArtifactDbError(err) {
  if (!err) return false;
  if (err.code === '23505') return true;
  if (err.reason === 'conflict' || err.reason === 'unique_violation' || err.reason === 'invalid_hash') {
    return true;
  }
  const msg = String(err.message || '');
  if (msg.includes('uq_file_artifact_hashes') || msg.includes('uq_file_artifact_ioc_links')) {
    return true;
  }
  return false;
}

/**
 * @param {any} err
 * @param {object} [extra]
 */
export function formatProviderError(err, extra = {}) {
  return {
    ...extra,
    code: err?.code || null,
    reason: err?.reason || null,
    message: err?.message || String(err),
    constraint: err?.constraint || null,
    detail: err?.detail || null,
    table: err?.table || null,
    column: err?.column || null,
    sqlState: err?.code || null
  };
}
