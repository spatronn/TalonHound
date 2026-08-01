/**
 * Hard fail unless disposable test DB is explicitly allowed.
 * Prevents accidental prod/shared DB use.
 */

const SAFE_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

export function assertFileArtifactDbTestAllowed(env = process.env) {
  if (String(env.ALLOW_FILE_ARTIFACT_DB_TESTS || '') !== '1') {
    throw new Error('Refusing DB tests: set ALLOW_FILE_ARTIFACT_DB_TESTS=1');
  }
  if (String(env.NODE_ENV || '').toLowerCase() === 'production') {
    throw new Error('Refusing DB tests: NODE_ENV=production');
  }
  const host = String(env.DB_HOST || '').trim().toLowerCase();
  if (!SAFE_HOSTS.has(host)) {
    throw new Error(`Refusing DB tests: DB_HOST must be localhost/127.0.0.1 (got ${host || '(empty)'})`);
  }
  const name = String(env.DB_NAME || '').trim().toLowerCase();
  if (!name.includes('_test')) {
    throw new Error(`Refusing DB tests: DB_NAME must contain "_test" (got ${name || '(empty)'})`);
  }
  // Block known prod hostnames if ever passed as DB_HOST somehow
  if (host.includes('talonhound') && !host.includes('test')) {
    throw new Error('Refusing DB tests: production-like hostname');
  }
  return {
    host,
    port: Number(env.DB_PORT || 55432),
    user: env.DB_USER || 'talonhound',
    password: env.DB_PASSWORD || 'test',
    database: env.DB_NAME
  };
}
