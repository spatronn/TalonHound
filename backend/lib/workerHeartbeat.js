/**
 * Redis-backed liveness heartbeats for long-running workers that are not
 * BullMQ queue consumers (integration scheduler, IOC expiration worker).
 */

export const HEARTBEAT_KEYS = Object.freeze({
  integration_scheduler: 'talonhound:worker-heartbeat:integration_scheduler',
  ioc_expiration_worker: 'talonhound:worker-heartbeat:ioc_expiration_worker'
});

/** Age above which a heartbeat is considered unhealthy (default 2 minutes). */
export const WORKER_HEARTBEAT_STALE_MS_DEFAULT = 120_000;

/** Redis key TTL — long enough that a stalled worker expires, short enough to self-heal. */
export const WORKER_HEARTBEAT_TTL_SECONDS_DEFAULT = 300;

export function resolveWorkerHeartbeatStaleMs(
  envValue = process.env.WORKER_HEARTBEAT_STALE_MS
) {
  if (envValue == null || envValue === '') return WORKER_HEARTBEAT_STALE_MS_DEFAULT;
  const n = Number(envValue);
  if (!Number.isFinite(n) || n <= 0) return WORKER_HEARTBEAT_STALE_MS_DEFAULT;
  return Math.trunc(n);
}

/**
 * @param {import('ioredis').default} redis
 * @param {string} key
 * @param {{ ttlSeconds?: number, now?: number }} [options]
 */
export async function touchWorkerHeartbeat(redis, key, {
  ttlSeconds = WORKER_HEARTBEAT_TTL_SECONDS_DEFAULT,
  now = Date.now()
} = {}) {
  const ttl = Math.max(1, Math.trunc(ttlSeconds));
  await redis.set(String(key), String(now), 'EX', ttl);
  return { key: String(key), lastSeen: now, ttlSeconds: ttl };
}

/**
 * @param {import('ioredis').default} redis
 * @param {string} key
 * @param {{ now?: number, staleMs?: number }} [options]
 * @returns {Promise<{ lastSeen: number|null, ageMs: number|null, status: 'healthy'|'unhealthy'|'unknown' }>}
 */
export async function readWorkerHeartbeat(redis, key, {
  now = Date.now(),
  staleMs = resolveWorkerHeartbeatStaleMs()
} = {}) {
  if (!redis || typeof redis.get !== 'function') {
    return { lastSeen: null, ageMs: null, status: 'unknown' };
  }
  let raw;
  try {
    raw = await redis.get(String(key));
  } catch {
    return { lastSeen: null, ageMs: null, status: 'unknown' };
  }
  if (raw == null || raw === '') {
    return { lastSeen: null, ageMs: null, status: 'unknown' };
  }
  const lastSeen = Number(raw);
  if (!Number.isFinite(lastSeen)) {
    return { lastSeen: null, ageMs: null, status: 'unknown' };
  }
  const ageMs = Math.max(0, now - lastSeen);
  const threshold = Math.max(1, Number(staleMs) || WORKER_HEARTBEAT_STALE_MS_DEFAULT);
  return {
    lastSeen,
    ageMs,
    status: ageMs <= threshold ? 'healthy' : 'unhealthy'
  };
}

/**
 * Shape a heartbeat read into the /api/system/health worker entry format.
 */
export function workerHeartbeatHealthEntry(key, name, heartbeat) {
  const status = heartbeat?.status || 'unknown';
  let reason = 'heartbeat_missing';
  if (status === 'healthy') reason = 'heartbeat_fresh';
  else if (status === 'unhealthy') reason = 'heartbeat_stale';
  return {
    key,
    name,
    status,
    reason,
    last_seen_at: heartbeat?.lastSeen ? new Date(heartbeat.lastSeen).toISOString() : null,
    age_ms: heartbeat?.ageMs ?? null
  };
}
