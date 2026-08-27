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

function rejectAfter(timeoutMs, message, code) {
  return new Promise((_, reject) => {
    const timer = setTimeout(() => {
      const err = new Error(message);
      err.code = code;
      reject(err);
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
  });
}

/**
 * Bounded Published Feed scheduler tick.
 *
 * Acquires an in-process guard, runs regenerate (+ optional cleanup) under an overall
 * deadline, then always clears the guard so the next poll can start. A timed-out tick
 * does not cancel in-flight per-feed generation (advisory locks still serialize those);
 * it only unblocks the process flag.
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {number} [options.timeoutMs]
 * @param {typeof regenerateAllEnabledFeeds} [options.regenerateAllEnabledFeeds]
 * @param {Function} [options.cleanupPublishedFeedChunkGenerations]
 * @param {typeof cleanupPublishedFeedLegacyArtifacts} [options.cleanupPublishedFeedLegacyArtifacts]
 * @param {boolean} [options.skipCleanup]
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

  try {
    const work = (async () => {
      const regenerateResult = await regenerate(pool, options);
      if (!skipCleanup) {
        if (typeof cleanupChunks === 'function') {
          await cleanupChunks(pool);
        }
        await cleanupLegacy(pool);
      }
      return regenerateResult;
    })();
    // If the overall deadline wins, in-flight work may still finish later; swallow
    // late rejection so a timed-out tick does not surface as unhandled.
    work.catch(() => {});

    const regenerateResult = await Promise.race([
      work,
      rejectAfter(timeoutMs, 'published feed tick timed out', 'PUBLISHED_FEED_TICK_TIMEOUT')
    ]);

    lastTickCompletedAt = Date.now();
    return { ok: true, skipped: false, regenerateResult };
  } catch (err) {
    lastTickCompletedAt = Date.now();
    const timedOut = err?.code === 'PUBLISHED_FEED_TICK_TIMEOUT';
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
    tickInProgress = false;
  }
}
