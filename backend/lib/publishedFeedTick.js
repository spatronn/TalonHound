import {
  regenerateAllEnabledFeeds,
  cleanupPublishedFeedLegacyArtifacts,
  resolvePublishedFeedTickMs
} from './feedPublisherService.js';
import { createServiceLogger } from './appLogger.js';

const tickLog = createServiceLogger('published-feeds');

/** Default overall tick budget — slightly above the per-generation statement timeout default. */
export const PUBLISHED_FEED_TICK_TIMEOUT_MS_DEFAULT = 35 * 60 * 1000;

let tickInProgress = false;
let lastTickStartedAt = null;
let lastTickCompletedAt = null;

export function resolvePublishedFeedTickTimeoutMs(
  envValue = process.env.PUBLISHED_FEED_TICK_TIMEOUT_MS
) {
  if (envValue == null || envValue === '') return PUBLISHED_FEED_TICK_TIMEOUT_MS_DEFAULT;
  const n = Number(envValue);
  if (!Number.isFinite(n) || n <= 0) return PUBLISHED_FEED_TICK_TIMEOUT_MS_DEFAULT;
  // Floor at one poll interval so a misconfigured tiny value cannot thrash.
  return Math.max(n, resolvePublishedFeedTickMs());
}

export function getPublishedFeedTickState() {
  return {
    inProgress: tickInProgress,
    lastTickStartedAt,
    lastTickCompletedAt
  };
}

/** Test-only: reset module guard/heartbeat state between cases. */
export function resetPublishedFeedTickStateForTests() {
  tickInProgress = false;
  lastTickStartedAt = null;
  lastTickCompletedAt = null;
}

function abortPromise(signal) {
  return new Promise((_, reject) => {
    if (signal.aborted) {
      reject(signal.reason || Object.assign(new Error('aborted'), { code: 'PUBLISHED_FEED_TICK_TIMEOUT' }));
      return;
    }
    signal.addEventListener(
      'abort',
      () => {
        reject(
          signal.reason
            || Object.assign(new Error('published feed tick timed out'), {
              code: 'PUBLISHED_FEED_TICK_TIMEOUT'
            })
        );
      },
      { once: true }
    );
  });
}

/**
 * Bounded Published Feed scheduler tick.
 *
 * Acquires an in-process guard, runs regenerate (+ optional cleanup) under an overall
 * deadline, then always clears the guard so the next poll can start. A timed-out tick
 * aborts via AbortSignal (cooperative) and clears the process flag; in-flight per-feed
 * generation that ignores the signal may still finish under advisory locks /
 * statement_timeout, but it will not permanently freeze future ticks.
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 */
export async function runPublishedFeedSchedulerTick(pool, options = {}) {
  if (tickInProgress) {
    return { skipped: true, reason: 'in_progress' };
  }

  tickInProgress = true;
  lastTickStartedAt = Date.now();
  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? Math.max(1, options.timeoutMs)
    : resolvePublishedFeedTickTimeoutMs();

  const regenerate = options.regenerateAllEnabledFeeds || regenerateAllEnabledFeeds;
  const cleanupLegacy = options.cleanupPublishedFeedLegacyArtifacts
    || cleanupPublishedFeedLegacyArtifacts;
  const cleanupChunks = options.cleanupPublishedFeedChunkGenerations || null;
  const skipCleanup = Boolean(options.skipCleanup);

  const timeoutErr = Object.assign(new Error('published feed tick timed out'), {
    code: 'PUBLISHED_FEED_TICK_TIMEOUT'
  });
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(timeoutErr), timeoutMs);
  // Do not unref the deadline timer — an unref'd timer will not keep the event
  // loop alive, which breaks unit tests and can skip the deadline in idle processes.

  try {
    const work = (async () => {
      const regenerateResult = await regenerate(pool, { ...options, signal: ac.signal });
      if (ac.signal.aborted) throw ac.signal.reason || timeoutErr;
      if (!skipCleanup) {
        if (typeof cleanupChunks === 'function') {
          await cleanupChunks(pool);
        }
        await cleanupLegacy(pool);
      }
      return regenerateResult;
    })();
    // If the deadline wins while regenerate ignores AbortSignal, swallow late
    // settlement so it cannot become an unhandledRejection.
    work.catch(() => {});

    const regenerateResult = await Promise.race([work, abortPromise(ac.signal)]);

    lastTickCompletedAt = Date.now();
    return { ok: true, skipped: false, regenerateResult };
  } catch (err) {
    lastTickCompletedAt = Date.now();
    const timedOut = err?.code === 'PUBLISHED_FEED_TICK_TIMEOUT' || ac.signal.aborted;
    if (timedOut) {
      tickLog.error('published feed tick timed out', {
        timeout_ms: timeoutMs,
        error: String(err?.message || err)
      });
    } else {
      tickLog.error('published feed tick failed', {
        error: String(err?.message || err)
      });
    }
    return {
      ok: false,
      skipped: false,
      timedOut,
      error: String(err?.message || err)
    };
  } finally {
    clearTimeout(timer);
    tickInProgress = false;
  }
}
