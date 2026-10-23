/**
 * In-memory FIFO semaphore with the inferenceScheduler contract (acquire,
 * lease.release / lease.quarantine, verifyQuarantine), for unit tests that
 * exercise client.js / analyze.js without PostgreSQL. The real cross-process
 * scheduler is covered by inferenceScheduler.integration.test.js.
 */

import { AI_FAILURE_CODES, aiFailure } from '../lib/threatLibrary/ai/timeouts.js';

export function createMemoryInferenceScheduler(options = {}) {
  const verifyEveryMs = options.verifyEveryMs ?? 25;
  let holding = 0;
  const waiters = [];
  const events = [];
  const quarantines = new Set();
  let maxHolding = 0;
  let capacityHint = 1;

  const grantNext = () => {
    while (waiters.length && holding < capacityHint) {
      const w = waiters.shift();
      holding += 1;
      maxHolding = Math.max(maxHolding, holding);
      w.grant();
    }
  };

  const freeSlot = (type, extra = {}) => {
    holding -= 1;
    events.push({ type, at: Date.now(), ...extra });
    grantNext();
  };

  async function verifyQuarantine(_resourceKey, verifyIdle) {
    const q = [...quarantines].find((x) => !x.verifying);
    if (!q) return 'none';
    q.verifying = true;
    let idle = false;
    try {
      idle = (await verifyIdle()) === true;
    } catch {
      idle = false;
    }
    q.verifying = false;
    if (!idle || !quarantines.has(q)) return 'still_busy';
    q.end('quarantine_verified');
    return 'released';
  }

  async function acquire(req) {
    capacityHint = Math.max(1, req.capacity || 1);
    const startedAt = Date.now();
    let maxPosition = 0;
    if (req.signal?.aborted) throw req.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED);
    await new Promise((resolve, reject) => {
      let verifier = null;
      const cleanup = () => {
        clearTimeout(timer);
        if (verifier) clearInterval(verifier);
        req.signal?.removeEventListener('abort', onAbort);
      };
      const w = {
        grant: () => {
          cleanup();
          resolve();
        }
      };
      const fail = (w.fail = (err) => {
        const idx = waiters.indexOf(w);
        if (idx >= 0) waiters.splice(idx, 1);
        cleanup();
        err.timing = { slot_wait_ms: Date.now() - startedAt, slot_max_position: maxPosition };
        reject(err);
      });
      const timer = setTimeout(() => fail(aiFailure(AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT)), Math.max(0, req.maxWaitMs ?? 60_000));
      const onAbort = () => fail(req.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
      req.signal?.addEventListener('abort', onAbort, { once: true });
      if (holding >= capacityHint && [...quarantines].some((q) => q.unverified)) {
        cleanup();
        const err = aiFailure(AI_FAILURE_CODES.AI_CAPACITY_QUARANTINED);
        err.timing = { slot_wait_ms: 0, slot_max_position: 0 };
        reject(err);
        return;
      }
      waiters.push(w);
      maxPosition = waiters.length;
      grantNext();
      if (waiters.includes(w)) {
        req.onWaiting?.({ position: waiters.indexOf(w) + 1, holding, waiting: waiters.length, waited_ms: 0 });
        if (typeof req.verifyIdle === 'function') {
          // Head-of-queue waiters probe quarantined slots, like the PG scheduler.
          verifier = setInterval(() => {
            if (waiters[0] === w && quarantines.size) verifyQuarantine(req.resourceKey, req.verifyIdle).catch(() => {});
          }, verifyEveryMs);
        }
      } else {
        maxPosition = 0;
      }
    });
    const waitMs = Date.now() - startedAt;
    events.push({ type: 'acquire', purpose: req.purpose || null, reportId: req.reportId ?? null, at: Date.now(), waitMs });
    let released = false;
    let quarantined = false;
    return {
      waitMs,
      maxPosition,
      holdersAtAcquire: holding,
      capacity: capacityHint,
      onLost: () => () => {},
      get quarantined() {
        return quarantined;
      },
      async quarantine({ holdMs, reason } = {}) {
        if (released || quarantined) return;
        quarantined = true;
        const q = { verifying: false };
        q.end = (type) => {
          if (!quarantines.has(q)) return;
          quarantines.delete(q);
          clearTimeout(q.expiry);
          released = true;
          freeSlot(type, { reason });
        };
        // Fail-closed: the bound does not free the slot, it marks it unverified.
        q.expiry = setTimeout(() => {
          q.unverified = true;
          events.push({ type: 'quarantine_unverified', at: Date.now() });
          // Like the PG scheduler's per-poll check: queued waiters fail fast.
          if (holding >= capacityHint) {
            for (const w of [...waiters]) w.fail?.(aiFailure(AI_FAILURE_CODES.AI_CAPACITY_QUARANTINED));
          }
        }, Math.max(0, holdMs ?? 0));
        quarantines.add(q);
        events.push({ type: 'quarantine', at: Date.now(), holdMs, reason });
      },
      async release() {
        if (released || quarantined) return;
        released = true;
        freeSlot('release', { purpose: req.purpose || null, reportId: req.reportId ?? null });
      }
    };
  }

  /** Administrator release (audited by the caller). */
  async function releaseQuarantined() {
    const all = [...quarantines];
    for (const q of all) q.end('quarantine_released_by_admin');
    return all.length;
  }

  return {
    acquire,
    verifyQuarantine,
    releaseQuarantined,
    events,
    stats: () => ({ holding, waiting: waiters.length, maxHolding, quarantined: quarantines.size })
  };
}
