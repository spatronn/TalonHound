/**
 * In-memory FIFO semaphore with the inferenceScheduler.acquire contract, for
 * unit tests that exercise client.js / analyze.js without PostgreSQL. The
 * real cross-process scheduler is covered by inferenceScheduler.integration.test.js.
 */

import { AI_FAILURE_CODES, aiFailure } from '../lib/threatLibrary/ai/timeouts.js';

export function createMemoryInferenceScheduler() {
  let holding = 0;
  const waiters = [];
  const events = [];
  let maxHolding = 0;

  const grantNext = (capacity) => {
    while (waiters.length && holding < capacity) {
      const w = waiters.shift();
      holding += 1;
      maxHolding = Math.max(maxHolding, holding);
      w.grant();
    }
  };

  async function acquire(req) {
    const capacity = Math.max(1, req.capacity || 1);
    const startedAt = Date.now();
    let maxPosition = 0;
    if (req.signal?.aborted) throw req.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED);
    await new Promise((resolve, reject) => {
      const w = {
        grant: () => {
          cleanup();
          resolve();
        }
      };
      const fail = (err) => {
        const idx = waiters.indexOf(w);
        if (idx >= 0) waiters.splice(idx, 1);
        cleanup();
        err.timing = { slot_wait_ms: Date.now() - startedAt, slot_max_position: maxPosition };
        reject(err);
      };
      const timer = setTimeout(() => fail(aiFailure(AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT)), Math.max(0, req.maxWaitMs ?? 60_000));
      const onAbort = () => fail(req.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
      req.signal?.addEventListener('abort', onAbort, { once: true });
      const cleanup = () => {
        clearTimeout(timer);
        req.signal?.removeEventListener('abort', onAbort);
      };
      waiters.push(w);
      maxPosition = waiters.length;
      grantNext(capacity);
      if (waiters.includes(w)) {
        req.onWaiting?.({ position: waiters.indexOf(w) + 1, holding, waiting: waiters.length, waited_ms: 0 });
      } else {
        maxPosition = 0;
      }
    });
    const waitMs = Date.now() - startedAt;
    events.push({ type: 'acquire', purpose: req.purpose || null, reportId: req.reportId ?? null, at: Date.now(), waitMs });
    let released = false;
    return {
      waitMs,
      maxPosition,
      holdersAtAcquire: holding,
      capacity,
      onLost: () => () => {},
      async release() {
        if (released) return;
        released = true;
        holding -= 1;
        events.push({ type: 'release', purpose: req.purpose || null, reportId: req.reportId ?? null, at: Date.now() });
        grantNext(capacity);
      }
    };
  }

  return {
    acquire,
    events,
    stats: () => ({ holding, waiting: waiters.length, maxHolding })
  };
}
