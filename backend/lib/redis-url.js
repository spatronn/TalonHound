import './ensure-redis-password.js';

/** Build BullMQ/ioredis URL with encoded password. Prefer REDIS_HOST/REDIS_PORT/REDIS_PASSWORD; REDIS_URL overrides if set. */
export function getRedisUrl() {
  const legacy = process.env.REDIS_URL?.trim();
  if (legacy) return legacy;

  const host = process.env.REDIS_HOST || 'redis';
  const port = String(process.env.REDIS_PORT || '6379');
  const pass = process.env.REDIS_PASSWORD;
  return `redis://:${encodeURIComponent(pass)}@${host}:${port}`;
}
