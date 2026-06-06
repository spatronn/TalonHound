import { pingClickhouse } from './clickhouse.js';

/**
 * @param {import('pg').Pool} pool
 * @param {import('ioredis').default} redis
 * @param {{ useClickhouse?: boolean }} opts
 */
export async function runReadinessChecks(pool, redis, opts = {}) {
  const useClickhouse = opts.useClickhouse !== false;
  const checks = {
    postgres: 'unknown',
    redis: 'unknown',
    clickhouse: useClickhouse ? 'unknown' : 'skipped'
  };

  try {
    await pool.query('SELECT 1');
    checks.postgres = 'ok';
  } catch (err) {
    checks.postgres = 'error';
    return { ok: false, checks, error: err?.message || 'postgres unavailable' };
  }

  try {
    const pong = await redis.ping();
    checks.redis = String(pong || '').toUpperCase() === 'PONG' ? 'ok' : 'error';
    if (checks.redis !== 'ok') {
      return { ok: false, checks, error: 'redis ping failed' };
    }
  } catch (err) {
    checks.redis = 'error';
    return { ok: false, checks, error: err?.message || 'redis unavailable' };
  }

  if (useClickhouse) {
    try {
      await pingClickhouse();
      checks.clickhouse = 'ok';
    } catch (err) {
      checks.clickhouse = 'error';
      return { ok: false, checks, error: err?.message || 'clickhouse unavailable' };
    }
  }

  return { ok: true, checks };
}

export function buildHealthPayload(status, checks = {}) {
  return {
    status,
    timestamp: new Date().toISOString(),
    checks
  };
}
