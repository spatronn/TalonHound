/**
 * @param {import('pg').Pool} pool
 * @param {import('ioredis').default} redis
 */
export async function runReadinessChecks(pool, redis) {
  const checks = {
    postgres: 'unknown',
    redis: 'unknown'
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

  return { ok: true, checks };
}

export function buildHealthPayload(status, checks = {}) {
  return {
    status,
    timestamp: new Date().toISOString(),
    checks
  };
}
