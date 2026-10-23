/**
 * Shared AI inference-capacity scheduler (cross-process, FIFO, lease based).
 *
 * Why: the local Ollama host runs one request at a time. Without a shared
 * gate, two report analyses send requests together and the second waits
 * inside Ollama, where that wait was counted as first-token latency and
 * failed healthy requests with first_token_timeout. The gate moves the wait
 * into TalonHound, where it is measured, bounded and reported separately.
 *
 * Design (migration 049, threat_library_ai_capacity_leases):
 *  - one row per waiting / holding request, keyed by provider endpoint;
 *  - claims run in short transactions serialized per endpoint by
 *    pg_advisory_xact_lock(namespace, hashtext(endpoint)); a hash collision
 *    only serializes two endpoints' claim checks, rows are still filtered by
 *    resource_key, so it can never merge their capacity;
 *  - strict FIFO by row id, no barging: a request is granted only when
 *    holders + earlier waiters < capacity. Each report has at most one
 *    outstanding request (chunks run in order), so FIFO is round-robin
 *    between reports and no report can monopolize the provider;
 *  - rows carry an expiry: holders heartbeat, waiters refresh on every poll.
 *    A crashed process stops refreshing and its rows expire (waiters 15s,
 *    holders 60s) — no manual cleanup, no leaked slots;
 *  - no PostgreSQL connection is held while waiting or during inference:
 *    every poll / heartbeat borrows a pool connection for one transaction.
 *
 * A holder that cannot confirm its lease (row gone, or the database was
 * unreachable for most of the lease) reports the lease as lost so the caller
 * aborts the request: two holders never believe they own the same slot.
 *
 * Quarantine: aborting a request does not prove the provider stopped working
 * on it (a lost FIN, a provider that ignores the disconnect). The holder then
 * quarantines its slot instead of releasing it: the row stays `holding`
 * (capacity stays occupied, durably — it survives the holder's process) until
 * a probe served promptly inside that slot proves the provider is idle, or
 * the request's worst-case execution bound passes. Probes are claim-guarded
 * (verify_after) and run by the holder or by any waiter, so a quarantine
 * never depends on the process that created it.
 *
 * Fail-closed (local providers, `failClosed`): time never frees capacity.
 *  - A holding lease that expires (holder crashed, database outage, network
 *    partition) is converted into a quarantine under the endpoint lock, not
 *    deleted: whoever reaches the database first after recovery finds the
 *    slot quarantined, never free.
 *  - A quarantine past its worst-case bound stays: waiters then fail fast with
 *    `ai_capacity_quarantined` (explicit, bounded) instead of waiting, while
 *    probes continue (waiters, the worker safety net). Recovery is a
 *    successful probe or an audited administrator release
 *    (`releaseQuarantined`).
 * Hosted providers (failClosed false) keep plain lease expiry.
 */

import crypto from 'node:crypto';
import os from 'node:os';
import { EventEmitter } from 'node:events';
import { AI_FAILURE_CODES, aiFailure } from './timeouts.js';
import { createServiceLogger } from '../../appLogger.js';

const log = createServiceLogger('threat-library-ai-scheduler');

export const INFERENCE_LOCK_NAMESPACE = 'threat-library.ai_capacity';

export const SCHEDULER_DEFAULTS = Object.freeze({
  pollMs: 500,
  waitLeaseMs: 15_000,
  holdLeaseMs: 60_000,
  heartbeatMs: 15_000,
  /** Minimum spacing between idle probes of one quarantined slot. */
  verifyIntervalMs: 10_000,
  /** Throttle for onWaiting callbacks when the queue position is unchanged. */
  waitingNotifyMs: 5_000
});

// Same-process waiters re-check immediately when a slot is released here;
// other processes notice on their next poll.
const localReleases = new EventEmitter();
localReleases.setMaxListeners(0);

const ownerLabel = `${os.hostname()}:${process.pid}`;

function sleepUntilWake(ms, resourceKey, signal) {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      localReleases.removeListener(resourceKey, finish);
      signal?.removeEventListener?.('abort', finish);
      resolve();
    };
    const timer = setTimeout(finish, Math.max(0, ms));
    localReleases.once(resourceKey, finish);
    signal?.addEventListener?.('abort', finish, { once: true });
  });
}

function capacityError(code, detail, extra = {}) {
  const err = aiFailure(code, detail);
  Object.assign(err, extra);
  return err;
}

/**
 * @param {import('pg').Pool} pool
 * @param {Partial<typeof SCHEDULER_DEFAULTS>} [options]
 */
export function createInferenceScheduler(pool, options = {}) {
  const cfg = { ...SCHEDULER_DEFAULTS, ...options };

  async function inTransaction(fn) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    } finally {
      client.release();
    }
  }

  async function insertWaiter(token, { resourceKey, purpose, reportId, failClosed, maxExecutionMs }) {
    const { rows } = await pool.query(
      `INSERT INTO threat_library_ai_capacity_leases
         (resource_key, token, state, purpose, owner, report_id, lease_expires_at, fail_closed, max_execution_ms)
       VALUES ($1, $2::uuid, 'waiting', $3, $4, $5, NOW() + ($6::int * INTERVAL '1 millisecond'), $7, $8)
       RETURNING id`,
      [resourceKey, token, purpose || null, ownerLabel, reportId ?? null, cfg.waitLeaseMs, failClosed === true, maxExecutionMs ?? null]
    );
    return Number(rows[0].id);
  }

  /**
   * One claim attempt. Returns the queue view, and whether the slot was granted.
   */
  async function tryClaim(token, resourceKey, capacity, meta) {
    return inTransaction(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))', [
        INFERENCE_LOCK_NAMESPACE,
        resourceKey
      ]);
      // Waiters that stopped polling hold no capacity: drop them.
      await client.query(
        `DELETE FROM threat_library_ai_capacity_leases
         WHERE resource_key = $1 AND state = 'waiting' AND lease_expires_at < NOW()`,
        [resourceKey]
      );
      // A holder that stopped renewing (crash, database outage, partition) may
      // have left a request running on the provider. Fail-closed: quarantine
      // it (probe before reuse) rather than free it.
      const converted = await client.query(
        `UPDATE threat_library_ai_capacity_leases
         SET quarantined_at = NOW(), verify_after = NOW(), purpose = 'quarantine:lease_expired',
             lease_expires_at = GREATEST(
               NOW(),
               COALESCE(acquired_at, created_at) + (COALESCE(max_execution_ms, 0) * INTERVAL '1 millisecond')
             )
         WHERE resource_key = $1 AND state = 'holding' AND quarantined_at IS NULL
           AND lease_expires_at < NOW() AND fail_closed
         RETURNING owner, report_id`,
        [resourceKey]
      );
      if (converted.rowCount) {
        log.warn('expired AI capacity lease quarantined (provider termination unverified)', {
          resource: resourceKey,
          holders: converted.rows.map((r) => ({ owner: r.owner, reportId: r.report_id }))
        });
      }
      const purged = await client.query(
        `DELETE FROM threat_library_ai_capacity_leases
         WHERE resource_key = $1 AND state = 'holding' AND quarantined_at IS NULL
           AND lease_expires_at < NOW() AND NOT fail_closed
         RETURNING owner, purpose`,
        [resourceKey]
      );
      if (purged.rowCount) {
        log.warn('expired AI capacity leases reclaimed', {
          resource: resourceKey,
          reclaimed: purged.rows.map((r) => ({ owner: r.owner, purpose: r.purpose }))
        });
      }
      let mine = await client.query(
        `UPDATE threat_library_ai_capacity_leases
         SET lease_expires_at = NOW() + ($2::int * INTERVAL '1 millisecond')
         WHERE token = $1::uuid AND state = 'waiting'
         RETURNING id`,
        [token, cfg.waitLeaseMs]
      );
      let requeued = false;
      if (!mine.rowCount) {
        // Our waiting row expired (the database or this process stalled
        // longer than the waiter lease): rejoin at the tail rather than jump.
        mine = await client.query(
          `INSERT INTO threat_library_ai_capacity_leases
             (resource_key, token, state, purpose, owner, report_id, lease_expires_at, fail_closed, max_execution_ms)
           VALUES ($1, $2::uuid, 'waiting', $3, $4, $5, NOW() + ($6::int * INTERVAL '1 millisecond'), $7, $8)
           RETURNING id`,
          [resourceKey, token, meta.purpose || null, ownerLabel, meta.reportId ?? null, cfg.waitLeaseMs, meta.failClosed === true, meta.maxExecutionMs ?? null]
        );
        requeued = true;
      }
      const myId = Number(mine.rows[0].id);
      const { rows } = await client.query(
        `SELECT
           COUNT(*) FILTER (WHERE state = 'holding')::int AS holding,
           COUNT(*) FILTER (WHERE state = 'holding' AND quarantined_at IS NOT NULL)::int AS quarantined,
           COUNT(*) FILTER (WHERE state = 'holding' AND quarantined_at IS NOT NULL AND lease_expires_at < NOW())::int AS unverified,
           COUNT(*) FILTER (WHERE state = 'waiting' AND id < $2)::int AS ahead,
           COUNT(*) FILTER (WHERE state = 'waiting')::int AS waiting
         FROM threat_library_ai_capacity_leases
         WHERE resource_key = $1`,
        [resourceKey, myId]
      );
      const view = rows[0];
      if (view.holding + view.ahead < capacity) {
        await client.query(
          `UPDATE threat_library_ai_capacity_leases
           SET state = 'holding', acquired_at = NOW(),
               lease_expires_at = NOW() + ($2::int * INTERVAL '1 millisecond')
           WHERE token = $1::uuid`,
          [token, cfg.holdLeaseMs]
        );
        return { acquired: true, holding: view.holding + 1, quarantined: view.quarantined, unverified: view.unverified, ahead: 0, waiting: view.waiting - 1, requeued };
      }
      return { acquired: false, holding: view.holding, quarantined: view.quarantined, unverified: view.unverified, ahead: view.ahead, waiting: view.waiting, requeued };
    });
  }

  async function deleteLease(token) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await pool.query('DELETE FROM threat_library_ai_capacity_leases WHERE token = $1::uuid', [token]);
        return true;
      } catch (err) {
        if (attempt === 0) await new Promise((r) => setTimeout(r, 250));
        else log.warn('AI capacity lease delete failed; it will expire', { error: err?.message });
      }
    }
    return false;
  }

  function startHolding(token, resourceKey, info) {
    let released = false;
    let lost = false;
    let quarantined = false;
    let lastConfirmedAt = Date.now();
    const lostCallbacks = new Set();
    const markLost = (reason) => {
      if (lost || released) return;
      lost = true;
      log.warn('AI capacity lease lost', { resource: resourceKey, reason, purpose: info.purpose, reportId: info.reportId ?? null });
      for (const cb of lostCallbacks) {
        try { cb(capacityError(AI_FAILURE_CODES.AI_CAPACITY_LEASE_LOST, undefined, { lease_lost_reason: reason })); } catch { /* ignore */ }
      }
    };
    // The row expires for other processes at (last confirmed renewal +
    // holdLeaseMs). Give the slot up two heartbeats before that, whether the
    // renewal failed or is still hanging (pool exhausted, network stall), so
    // two holders never overlap.
    const lossDeadlineMs = Math.max(cfg.heartbeatMs, cfg.holdLeaseMs - 2 * cfg.heartbeatMs);
    let renewing = false;
    const timer = setInterval(async () => {
      if (released || lost || quarantined) return;
      if (Date.now() - lastConfirmedAt >= lossDeadlineMs) {
        markLost('heartbeat_unconfirmed');
        return;
      }
      if (renewing) return; // never stack renewals behind a slow query
      renewing = true;
      try {
        const res = await pool.query(
          `UPDATE threat_library_ai_capacity_leases
           SET lease_expires_at = NOW() + ($2::int * INTERVAL '1 millisecond')
           WHERE token = $1::uuid AND state = 'holding' AND quarantined_at IS NULL`,
          [token, cfg.holdLeaseMs]
        );
        if (released || lost) return;
        if (!res.rowCount) markLost('lease_row_missing');
        else lastConfirmedAt = Date.now();
      } catch (err) {
        log.warn('AI capacity heartbeat failed; retrying', { error: err?.message });
      } finally {
        renewing = false;
      }
    }, cfg.heartbeatMs);
    if (typeof timer.unref === 'function') timer.unref();

    return {
      token,
      resourceKey,
      ...info,
      get lost() {
        return lost;
      },
      onLost(cb) {
        lostCallbacks.add(cb);
        return () => lostCallbacks.delete(cb);
      },
      get quarantined() {
        return quarantined;
      },
      /**
       * Keep the slot occupied after an abort whose provider-side termination
       * is unproven: durable `holding` row until verified idle or `holdMs`.
       * If the row was lost meanwhile it is re-created (conservatively
       * occupying capacity again rather than letting a request overlap).
       * @param {{ holdMs: number, reason?: string }} q
       */
      async quarantine(q) {
        if (released || quarantined) return;
        quarantined = true;
        clearInterval(timer);
        const holdMs = Math.max(1, Math.trunc(Number(q?.holdMs) || 0));
        try {
          const res = await pool.query(
            `UPDATE threat_library_ai_capacity_leases
             SET quarantined_at = NOW(), verify_after = NOW(), purpose = 'quarantine',
                 lease_expires_at = NOW() + ($2::int * INTERVAL '1 millisecond')
             WHERE token = $1::uuid`,
            [token, holdMs]
          );
          if (!res.rowCount) {
            await pool.query(
              `INSERT INTO threat_library_ai_capacity_leases
                 (resource_key, token, state, purpose, owner, report_id, lease_expires_at, acquired_at, quarantined_at, verify_after, fail_closed)
               VALUES ($1, $2::uuid, 'holding', 'quarantine', $3, $4, NOW() + ($5::int * INTERVAL '1 millisecond'), NOW(), NOW(), NOW(), true)
               ON CONFLICT (token) DO NOTHING`,
              [resourceKey, token, ownerLabel, info.reportId ?? null, holdMs]
            );
          }
          log.warn('inference slot quarantined until the provider is verified idle', {
            resource: resourceKey,
            reason: q?.reason || null,
            hold_ms: holdMs,
            reportId: info.reportId ?? null
          });
        } catch (err) {
          // The previous lease row (if any) still expires on its own schedule.
          log.warn('inference slot quarantine could not be recorded', { resource: resourceKey, error: err?.message });
        }
      },
      async release() {
        if (released) return;
        released = true;
        clearInterval(timer);
        await deleteLease(token);
        localReleases.emit(resourceKey);
      }
    };
  }

  /**
   * Probe one due quarantined slot of `resourceKey` (claim-guarded across
   * processes via verify_after). `verifyIdle` must resolve true only when a
   * provider request was served promptly — i.e. the provider has capacity.
   * @returns {Promise<'released'|'still_busy'|'none'>}
   */
  async function verifyQuarantine(resourceKey, verifyIdle) {
    let token = null;
    try {
      const { rows } = await pool.query(
        `UPDATE threat_library_ai_capacity_leases
         SET verify_after = NOW() + ($2::int * INTERVAL '1 millisecond')
         WHERE id = (
           SELECT id FROM threat_library_ai_capacity_leases
           WHERE resource_key = $1 AND state = 'holding' AND quarantined_at IS NOT NULL
             AND verify_after <= NOW()
           ORDER BY id LIMIT 1
           FOR UPDATE SKIP LOCKED
         )
         RETURNING token`,
        [resourceKey, cfg.verifyIntervalMs]
      );
      token = rows[0]?.token || null;
    } catch (err) {
      log.warn('quarantine verification claim failed', { resource: resourceKey, error: err?.message });
      return 'none';
    }
    if (!token) return 'none';
    let idle = false;
    try {
      idle = (await verifyIdle()) === true;
    } catch {
      idle = false;
    }
    if (!idle) return 'still_busy';
    await pool.query(
      `DELETE FROM threat_library_ai_capacity_leases WHERE token = $1::uuid AND quarantined_at IS NOT NULL`,
      [token]
    ).catch(() => {});
    log.info('quarantined inference slot released: provider verified idle', { resource: resourceKey });
    localReleases.emit(resourceKey);
    return 'released';
  }

  /**
   * Wait (bounded) for an inference slot.
   * @param {{
   *   resourceKey: string,
   *   capacity: number,
   *   maxWaitMs: number,
   *   signal?: AbortSignal,
   *   purpose?: string,
   *   reportId?: number|null,
   *   onWaiting?: (view: { position: number, holding: number, waiting: number, waited_ms: number }) => void,
   *   verifyIdle?: () => Promise<boolean>,
   *   failClosed?: boolean,
   *   maxExecutionMs?: number
   * }} req
   */
  async function acquire(req) {
    const capacity = Math.max(1, Math.trunc(Number(req.capacity) || 1));
    const maxWaitMs = Math.max(0, Number(req.maxWaitMs) || 0);
    const resourceKey = String(req.resourceKey);
    const token = crypto.randomUUID();
    const startedAt = Date.now();
    const waited = () => Date.now() - startedAt;

    if (req.signal?.aborted) throw req.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED);
    try {
      await insertWaiter(token, req);
    } catch (err) {
      throw capacityError(AI_FAILURE_CODES.AI_CAPACITY_UNAVAILABLE, `AI capacity scheduler unavailable: ${err?.message || err}`);
    }

    let lastNotifyAt = 0;
    let lastPosition = null;
    let firstDbErrorAt = null;
    let maxPosition = 0;
    try {
      while (true) {
        if (req.signal?.aborted) throw req.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED);
        let view = null;
        try {
          view = await tryClaim(token, resourceKey, capacity, req);
          firstDbErrorAt = null;
        } catch (err) {
          firstDbErrorAt = firstDbErrorAt || Date.now();
          if (Date.now() - firstDbErrorAt > cfg.waitLeaseMs) {
            throw capacityError(AI_FAILURE_CODES.AI_CAPACITY_UNAVAILABLE, `AI capacity scheduler unavailable: ${err?.message || err}`);
          }
        }
        if (view?.acquired) {
          const waitMs = waited();
          if (waitMs >= 1000 || maxPosition > 0) {
            log.info('AI capacity acquired', {
              resource: resourceKey,
              purpose: req.purpose || null,
              reportId: req.reportId ?? null,
              wait_ms: waitMs,
              max_position: maxPosition,
              capacity
            });
          }
          return startHolding(token, resourceKey, {
            waitMs,
            maxPosition,
            holdersAtAcquire: view.holding,
            waitingAtAcquire: view.waiting,
            capacity,
            purpose: req.purpose || null,
            reportId: req.reportId ?? null
          });
        }
        if (view && view.quarantined > 0 && view.ahead === 0 && typeof req.verifyIdle === 'function') {
          // Head of the queue behind a quarantined slot: probe the provider.
          // The probe can outlast the waiter lease: keep our row alive meanwhile.
          const keepAlive = setInterval(() => {
            pool.query(
              `UPDATE threat_library_ai_capacity_leases
               SET lease_expires_at = NOW() + ($2::int * INTERVAL '1 millisecond')
               WHERE token = $1::uuid AND state = 'waiting'`,
              [token, cfg.waitLeaseMs]
            ).catch(() => {});
          }, Math.max(50, Math.floor(cfg.waitLeaseMs / 3)));
          let outcome;
          try {
            outcome = await verifyQuarantine(resourceKey, req.verifyIdle);
          } finally {
            clearInterval(keepAlive);
          }
          if (outcome === 'released') continue;
        }
        if (view && view.unverified > 0 && view.holding >= capacity) {
          // No free slot and a quarantine outlived its worst-case bound
          // unverified: an explicit, bounded state — never a silent reuse.
          throw capacityError(
            AI_FAILURE_CODES.AI_CAPACITY_QUARANTINED,
            'AI capacity is held: the provider has not confirmed that an abandoned request finished. It is released when a probe succeeds or an administrator releases it.'
          );
        }
        if (view) {
          const position = view.ahead + 1;
          maxPosition = Math.max(maxPosition, position);
          const now = Date.now();
          if (req.onWaiting && (position !== lastPosition || now - lastNotifyAt >= cfg.waitingNotifyMs)) {
            lastPosition = position;
            lastNotifyAt = now;
            try {
              await req.onWaiting({ position, holding: view.holding, waiting: view.waiting, waited_ms: waited() });
            } catch { /* progress is best-effort */ }
          }
        }
        const remaining = maxWaitMs - waited();
        if (remaining <= 0) {
          throw capacityError(AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT, undefined, {
            timing: { slot_wait_ms: waited(), slot_max_position: maxPosition }
          });
        }
        await sleepUntilWake(Math.min(cfg.pollMs, remaining), resourceKey, req.signal);
      }
    } catch (err) {
      await deleteLease(token);
      if (err && typeof err === 'object') {
        err.timing = { ...(err.timing || {}), slot_wait_ms: waited(), slot_max_position: maxPosition };
      }
      throw err;
    }
  }

  /**
   * Current queue view for one endpoint (diagnostics; expired rows excluded).
   * @param {string} resourceKey
   */
  async function snapshot(resourceKey) {
    const { rows } = await pool.query(
      `SELECT
         COUNT(*) FILTER (WHERE state = 'holding')::int AS holding,
         COUNT(*) FILTER (WHERE state = 'waiting')::int AS waiting,
         COUNT(*) FILTER (WHERE state = 'holding' AND quarantined_at IS NOT NULL)::int AS quarantined,
         COUNT(*) FILTER (WHERE state = 'holding' AND quarantined_at IS NOT NULL AND lease_expires_at < NOW())::int AS unverified,
         MIN(quarantined_at) FILTER (WHERE state = 'holding' AND quarantined_at IS NOT NULL) AS oldest_quarantined_at,
         COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at) FILTER (WHERE state = 'waiting'))) * 1000, 0)::bigint AS oldest_wait_ms
       FROM threat_library_ai_capacity_leases
       WHERE resource_key = $1 AND (lease_expires_at >= NOW() OR quarantined_at IS NOT NULL)`,
      [resourceKey]
    );
    return {
      holding: rows[0]?.holding || 0,
      waiting: rows[0]?.waiting || 0,
      quarantined: rows[0]?.quarantined || 0,
      unverified: rows[0]?.unverified || 0,
      oldest_quarantined_at: rows[0]?.oldest_quarantined_at || null,
      oldest_wait_ms: Number(rows[0]?.oldest_wait_ms || 0)
    };
  }

  /**
   * Administrator recovery: free every quarantined slot of `resourceKey`
   * (after confirming the provider is idle, e.g. restarted). Audited by the
   * caller. Returns the number of slots released.
   * @param {string} resourceKey
   */
  async function releaseQuarantined(resourceKey) {
    const { rowCount } = await pool.query(
      `DELETE FROM threat_library_ai_capacity_leases
       WHERE resource_key = $1 AND state = 'holding' AND quarantined_at IS NOT NULL`,
      [resourceKey]
    );
    if (rowCount) {
      log.warn('quarantined AI capacity released by an administrator', { resource: resourceKey, released: rowCount });
      localReleases.emit(resourceKey);
    }
    return rowCount;
  }

  return { acquire, snapshot, verifyQuarantine, releaseQuarantined, config: cfg };
}

const schedulersByPool = new WeakMap();

/**
 * One scheduler per process and pool (backend probe, worker analyses).
 * @param {import('pg').Pool} pool
 */
export function getInferenceScheduler(pool) {
  let scheduler = schedulersByPool.get(pool);
  if (!scheduler) {
    scheduler = createInferenceScheduler(pool);
    schedulersByPool.set(pool, scheduler);
  }
  return scheduler;
}
