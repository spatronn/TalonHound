/**
 * Fail closed unless REDIS_PASSWORD or REDIS_URL is set.
 * Never assigns a repository-known default password.
 */
export function validateRedisPasswordEnv(env = process.env) {
  const hasLegacyUrl = Boolean(env.REDIS_URL?.trim());
  if (!hasLegacyUrl && !env.REDIS_PASSWORD) {
    throw new Error('REDIS_PASSWORD is required (or set REDIS_URL with credentials)');
  }
}

validateRedisPasswordEnv();
