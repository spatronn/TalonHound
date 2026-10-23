/**
 * Atomic ownership fencing for Threat Library pipeline writes.
 *
 * A check-then-write ownership test leaves a window in which a stale worker
 * (stalled past the heartbeat window, its job taken over) commits writes
 * after losing the job. The fenced database handle closes that window: every
 * write runs in a transaction that first locks the job row
 * (`SELECT … FOR UPDATE`) and confirms `owner_token` and `status = 'running'`.
 * A takeover (`claimJobOwnership`) and crash recovery both UPDATE that row,
 * so they serialize against an in-flight fenced write: either the write
 * commits before the takeover, or it sees the new owner and rolls back with
 * `job_ownership_lost`. No stale write can commit after a takeover.
 *
 *  - `query(sql)`: reads pass through; INSERT / UPDATE / DELETE / MERGE / WITH
 *    run as their own fenced transaction.
 *  - `connect()`: a client whose BEGIN takes the fence (and whose writes
 *    outside a BEGIN are fenced statements), so helpers that manage their
 *    own transaction (reconcileReportCandidates) are fenced as a whole.
 *  - `transaction(fn)`: one fenced transaction around several writes.
 *
 * The fence lock is held only for the duration of a write transaction. The
 * worker's heartbeat (raw pool) waits for it at most that long.
 */

import { AI_FAILURE_CODES, aiFailure } from './ai/timeouts.js';

const FENCE_SQL = `SELECT 1 FROM threat_library_jobs
  WHERE id = $1 AND owner_token = $2::uuid AND status = 'running'
  FOR UPDATE`;

const WRITE_RE = /^\s*(INSERT|UPDATE|DELETE|MERGE|WITH)\b/i;
const BEGIN_RE = /^\s*(BEGIN|START\s+TRANSACTION)\b/i;
const END_RE = /^\s*(COMMIT|END|ROLLBACK)\s*;?\s*$/i;

function sqlText(sql) {
  return String(sql && typeof sql === 'object' ? sql.text : sql);
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ jobId: number, ownerToken: string }} fence
 */
export function createFencedDb(pool, fence) {
  const lockFence = async (client) => {
    const owned = await client.query(FENCE_SQL, [fence.jobId, fence.ownerToken]);
    if (!owned.rowCount) throw aiFailure(AI_FAILURE_CODES.JOB_OWNERSHIP_LOST);
  };

  async function inFencedTransaction(client, fn) {
    await client.query('BEGIN');
    try {
      await lockFence(client);
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    }
  }

  async function withClient(fn) {
    const client = await pool.connect();
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }

  function wrapClient(client) {
    let inTxn = false;
    return {
      async query(sql, params) {
        const text = sqlText(sql);
        if (BEGIN_RE.test(text)) {
          const res = await client.query(sql, params);
          inTxn = true;
          try {
            await lockFence(client);
          } catch (err) {
            try { await client.query('ROLLBACK'); } catch { /* ignore */ }
            inTxn = false;
            throw err;
          }
          return res;
        }
        if (END_RE.test(text)) {
          inTxn = false;
          return client.query(sql, params);
        }
        if (!inTxn && WRITE_RE.test(text)) {
          return inFencedTransaction(client, (c) => c.query(sql, params));
        }
        return client.query(sql, params);
      },
      release: (...args) => client.release(...args)
    };
  }

  return {
    fenced: true,
    query(sql, params) {
      if (!WRITE_RE.test(sqlText(sql))) return pool.query(sql, params);
      return withClient((client) => inFencedTransaction(client, (c) => c.query(sql, params)));
    },
    async connect() {
      return wrapClient(await pool.connect());
    },
    /** One fenced transaction; `fn` receives the raw transaction client. */
    transaction(fn) {
      return withClient((client) => inFencedTransaction(client, fn));
    },
    /** Confirms ownership without writing (early stop before AI work). */
    async assertOwned() {
      const owned = await pool.query(
        `SELECT 1 FROM threat_library_jobs WHERE id = $1 AND owner_token = $2::uuid AND status = 'running'`,
        [fence.jobId, fence.ownerToken]
      );
      if (!owned.rowCount) throw aiFailure(AI_FAILURE_CODES.JOB_OWNERSHIP_LOST);
    }
  };
}
