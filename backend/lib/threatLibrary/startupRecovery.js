/**
 * Threat Library worker startup recovery.
 *
 * On start the worker must (1) fail BullMQ jobs a previous worker process left
 * `active`, (2) re-queue interrupted / stale-claimed analysis jobs and (3)
 * dispatch queued analyses. It used to try this once, when Redis became ready,
 * and swallow any error — after a Docker restart PostgreSQL was often not up
 * yet, so recovery silently never ran. It now retries with capped exponential
 * backoff and full jitter until it succeeds or the worker shuts down, and
 * publishes its state for System → Health.
 *
 * Every step is idempotent (conditional UPDATEs, ownership-fenced claims), so a
 * retry after a partial attempt, or a concurrent safety-net pass, cannot run a
 * job twice or exceed the analysis concurrency limit.
 */

import { JOB_OWNER_STALE_MS } from './jobOwnership.js';
import { recoverInterruptedAnalysisJobs } from './analysisConcurrency.js';

export const STARTUP_RECOVERY_STATE_KEY = 'talonhound:worker-state:threat_library_startup_recovery';
export const STARTUP_RECOVERY_STATE_TTL_SECONDS = 24 * 60 * 60;

/** Jobs a previous process started are older than this process by at least this much. */
const PREVIOUS_PROCESS_MARGIN_MS = 2000;

/**
 * Full-jitter exponential backoff: uniform in [0, min(maxMs, baseMs * 2^(attempt-1))].
 * A small floor keeps a tight loop impossible.
 */
export function computeBackoffMs(attempt, { baseMs = 1000, maxMs = 30_000, random = Math.random } = {}) {
  const n = Math.max(1, Math.trunc(attempt));
  const ceiling = Math.min(maxMs, baseMs * 2 ** Math.min(n - 1, 30));
  return Math.max(100, Math.round(random() * ceiling));
}

/**
 * BullMQ jobs left `active` by a previous worker process. Their lock (held up to
 * lockDuration, 2 h) belongs to a dead process, so they must be failed with the
 * force token '0' — the job's own token is unknown here and a token mismatch is
 * rejected by BullMQ. A job whose database row still has a live owner
 * heartbeat is left alone (it may belong to another running worker).
 *
 * @returns {Promise<{ moved: object[], skippedLiveOwner: number }>}
 */
export async function failStaleActiveJobs({ queue, pool, workerStartedAt, log, ownerStaleMs = JOB_OWNER_STALE_MS }) {
  const active = await queue.getJobs(['active']);
  const stale = active.filter((job) => job?.processedOn && job.processedOn < workerStartedAt - PREVIOUS_PROCESS_MARGIN_MS);
  const moved = [];
  let skippedLiveOwner = 0;
  for (const job of stale) {
    const { rows } = await pool.query(
      `SELECT 1 FROM threat_library_jobs
        WHERE bullmq_job_id = $1
          AND status = 'running'
          AND owner_token IS NOT NULL
          AND COALESCE(heartbeat_at, started_at, created_at) >= NOW() - ($2::int * INTERVAL '1 millisecond')
        LIMIT 1`,
      [String(job.id), ownerStaleMs]
    );
    if (rows.length) {
      skippedLiveOwner += 1;
      continue;
    }
    try {
      await job.moveToFailed(new Error('worker_restarted'), '0', false);
    } catch (err) {
      // Finished or removed meanwhile: nothing left to recover.
      if (!(await queue.getJob(job.id))) continue;
      throw err;
    }
    moved.push({ bullmqJobId: job.id, reportId: job.data?.reportId || null });
    log?.info?.('stale analysis recovered', { bullmqJobId: job.id, reportId: job.data?.reportId || null, reason: 'worker_restarted' });
  }
  return { moved, skippedLiveOwner };
}

/**
 * One startup recovery attempt: fail the previous process's BullMQ `active`
 * jobs, re-queue interrupted / stale-claimed jobs, dispatch queued analyses.
 * Throws on any failure so the caller retries the whole (idempotent) sequence.
 *
 * @param {{ queue: object, pool: object, workerStartedAt: number, log?: object, dispatch: () => Promise<object> }} input
 */
export async function performStartupRecovery({ queue, pool, workerStartedAt, log, dispatch }) {
  const stale = await failStaleActiveJobs({ queue, pool, workerStartedAt, log });
  const recovered = await recoverInterruptedAnalysisJobs(pool, {
    getJobState: async (id) => {
      const job = await queue.getJob(id);
      return job ? job.getState() : null;
    }
  });
  const dispatched = await dispatch();
  const summary = {
    staleActive: stale.moved.length,
    staleActiveLiveOwner: stale.skippedLiveOwner,
    recovered: recovered.length,
    claimed: dispatched.claimed.length,
    occupied: dispatched.occupied,
    limit: dispatched.limit
  };
  log?.info?.('scheduler recovered', summary);
  return summary;
}

/**
 * Retry `attempt` until it resolves or `stop()` is called.
 *
 * @param {{
 *   attempt: () => Promise<object>,
 *   log: { info: Function, warn: Function, error: Function },
 *   onState?: (state: object) => Promise<void>|void,
 *   baseMs?: number, maxMs?: number, escalateAfter?: number,
 *   random?: () => number,
 *   sleep?: (ms: number, signal: AbortSignal) => Promise<void>,
 *   now?: () => number
 * }} opts
 */
export function createStartupRecovery({
  attempt,
  log,
  onState = () => {},
  baseMs = 1000,
  maxMs = 30_000,
  escalateAfter = 8,
  random = Math.random,
  sleep = abortableSleep,
  now = Date.now
}) {
  const controller = new AbortController();
  let running = null;
  let state = { state: 'pending', attempts: 0, last_error: null, started_at: null, completed_at: null };

  const publish = async (patch) => {
    state = { ...state, ...patch, updated_at: new Date(now()).toISOString() };
    try {
      await onState(state);
    } catch {
      /* state publication is best effort; logs carry the same information */
    }
  };

  async function loop() {
    await publish({ state: 'running', started_at: new Date(now()).toISOString() });
    while (!controller.signal.aborted) {
      const n = state.attempts + 1;
      try {
        const result = await attempt();
        await publish({ state: 'completed', attempts: n, last_error: null, completed_at: new Date(now()).toISOString() });
        log.info('startup recovery completed', { attempts: n, ...result });
        return state;
      } catch (err) {
        if (controller.signal.aborted) break;
        const delayMs = computeBackoffMs(n, { baseMs, maxMs, random });
        const fields = { attempt: n, error: err?.message, code: err?.code, retryInMs: delayMs };
        await publish({ state: 'retrying', attempts: n, last_error: String(err?.message || err).slice(0, 300) });
        if (n === escalateAfter || (n > escalateAfter && n % escalateAfter === 0)) {
          log.error('startup recovery still failing; queued and interrupted analyses are not being recovered', fields);
        } else {
          log.warn('startup recovery failed; retrying', fields);
        }
        try {
          await sleep(delayMs, controller.signal);
        } catch {
          break;
        }
      }
    }
    await publish({ state: 'cancelled' });
    return state;
  }

  return {
    /** Idempotent: a second call returns the run already in progress. */
    start() {
      if (!running) running = loop();
      return running;
    },
    stop() {
      controller.abort();
      return running || Promise.resolve(state);
    },
    status() {
      return state;
    }
  };
}

export function abortableSleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('aborted'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener?.('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error('aborted'));
    };
    signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

/**
 * System → Health row for the worker's startup recovery, from the state key.
 * The worker refreshes `alive_at` every safety-net tick (30 s); an old value
 * means the worker process is gone, whatever its last recovery state was.
 * @param {object|null} recovery parsed STARTUP_RECOVERY_STATE_KEY value
 */
export function startupRecoveryHealthEntry(recovery, { now = Date.now(), staleMs = 120_000 } = {}) {
  const base = { key: 'threat_library_worker', name: 'Threat Library worker' };
  if (!recovery) return { ...base, status: 'unknown', reason: 'recovery_state_missing' };
  const aliveAt = Date.parse(recovery.alive_at || recovery.updated_at || '');
  if (Number.isFinite(aliveAt) && now - aliveAt > staleMs) {
    return { ...base, status: 'unhealthy', reason: 'heartbeat_stale', last_seen_at: new Date(aliveAt).toISOString() };
  }
  if (recovery.state === 'completed') {
    return { ...base, status: 'healthy', reason: 'startup_recovery_completed', last_seen_at: recovery.completed_at || null };
  }
  if (recovery.state === 'retrying') {
    return {
      ...base,
      status: 'degraded',
      reason: 'startup_recovery_retrying',
      evidence: `Startup recovery retrying (attempt ${recovery.attempts}): ${recovery.last_error || 'unknown error'}`,
      last_seen_at: recovery.updated_at || null
    };
  }
  return { ...base, status: 'unknown', reason: `startup_recovery_${recovery.state || 'unknown'}`, last_seen_at: recovery.updated_at || null };
}
