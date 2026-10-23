/**
 * Threat Library job ownership: one live worker per job (migration 049).
 *
 * BullMQ can deliver a job twice (stalled-lock re-delivery after a crash or a
 * long event-loop stall) and crash recovery can re-dispatch a job whose old
 * BullMQ entry is still "active". Ownership is therefore fenced in
 * PostgreSQL, not in BullMQ:
 *  - claim: a delivery takes the job only when it is unowned, already its
 *    own, or the current owner's heartbeat is stale;
 *  - heartbeat: the owner refreshes heartbeat_at; a heartbeat that finds the
 *    row owned by someone else reports ownership loss, and the run stops
 *    without writing report state;
 *  - recovery treats a running job as interrupted only when its owner's
 *    heartbeat is stale, so a live owner is never displaced.
 */

import { createServiceLogger } from '../appLogger.js';

const log = createServiceLogger('threat-library-job-ownership');

export const JOB_HEARTBEAT_MS = 15_000;
/** 8 missed heartbeats: well past any GC / event-loop pause, short next to an analysis. */
export const JOB_OWNER_STALE_MS = 120_000;

/**
 * @param {import('pg').Pool} pool
 * @param {{ jobId: number, ownerToken: string, bullmqJobId?: string|null, staleMs?: number }} input
 * @returns {Promise<object|null>} the job row when claimed, null when another live owner holds it
 */
export async function claimJobOwnership(pool, { jobId, ownerToken, bullmqJobId = null, staleMs = JOB_OWNER_STALE_MS }) {
  const { rows } = await pool.query(
    `UPDATE threat_library_jobs
     SET owner_token = $2::uuid,
         heartbeat_at = NOW(),
         status = 'running',
         stage = 'starting',
         bullmq_job_id = COALESCE($3, bullmq_job_id),
         started_at = COALESCE(started_at, NOW())
     WHERE id = $1
       AND status = ANY(ARRAY['queued','running'])
       AND (
         owner_token IS NULL
         OR owner_token = $2::uuid
         OR COALESCE(heartbeat_at, started_at, created_at) < NOW() - ($4::int * INTERVAL '1 millisecond')
       )
     RETURNING *`,
    [jobId, ownerToken, bullmqJobId, staleMs]
  );
  return rows[0] || null;
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ jobId: number, ownerToken: string, onLost: (reason: string) => void, intervalMs?: number, staleMs?: number }} input
 */
export function startJobHeartbeat(pool, { jobId, ownerToken, onLost, intervalMs = JOB_HEARTBEAT_MS, staleMs = JOB_OWNER_STALE_MS }) {
  let stopped = false;
  let lost = false;
  let lastConfirmedAt = Date.now();
  const fireLost = (reason) => {
    if (lost || stopped) return;
    lost = true;
    log.warn('job ownership lost', { jobId, reason });
    try { onLost(reason); } catch { /* ignore */ }
  };
  const timer = setInterval(async () => {
    if (stopped || lost) return;
    try {
      const res = await pool.query(
        `UPDATE threat_library_jobs SET heartbeat_at = NOW()
         WHERE id = $1 AND owner_token = $2::uuid AND status = 'running'`,
        [jobId, ownerToken]
      );
      if (stopped) return;
      if (!res.rowCount) fireLost('owner_changed_or_job_ended');
      else lastConfirmedAt = Date.now();
    } catch (err) {
      // Stop before a recovery pass could consider this owner stale.
      if (Date.now() - lastConfirmedAt > staleMs - 2 * intervalMs) fireLost('heartbeat_unconfirmed');
      else log.warn('job heartbeat failed; retrying', { jobId, error: err?.message });
    }
  }, intervalMs);
  if (typeof timer.unref === 'function') timer.unref();
  return {
    get lost() {
      return lost;
    },
    stop() {
      stopped = true;
      clearInterval(timer);
    }
  };
}

/**
 * Hand an interrupted job back to the queue (graceful worker shutdown).
 * Only the current owner can do it; dispatch claims it again with its
 * completed checkpoints intact.
 * @param {import('pg').Pool} pool
 * @param {{ jobId: number, ownerToken: string, reason: string }} input
 */
export async function requeueOwnedJob(pool, { jobId, ownerToken, reason }) {
  const { rows } = await pool.query(
    `UPDATE threat_library_jobs
     SET status = 'queued', stage = 'queued', bullmq_job_id = NULL,
         owner_token = NULL, heartbeat_at = NULL, error_message = $3
     WHERE id = $1 AND owner_token = $2::uuid AND status = 'running'
     RETURNING *`,
    [jobId, ownerToken, reason]
  );
  return rows[0] || null;
}
