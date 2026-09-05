/**
 * MCP server configuration. Prefer env overrides; secure defaults otherwise.
 */

function intEnv(env, name, fallback, { min = 1, max = 1_000_000 } = {}) {
  const raw = env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function boolEnv(env, name, fallback = true) {
  const raw = env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const v = String(raw).trim().toLowerCase();
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  return fallback;
}

export const MCP_DEFAULTS = Object.freeze({
  ENABLED: true,
  BULK_LOOKUP_MAX: 100,
  IMPORT_MAX: 100,
  SEARCH_PAGE_MAX: 50,
  VALUE_MAX_CHARS: 2048,
  RATE_LIMIT_PER_MIN: 120,
  RATE_LIMIT_IMPORT_PER_MIN: 30,
  RATE_LIMIT_SEARCH_PER_MIN: 60,
  RATE_LIMIT_BULK_PER_MIN: 60
});

export function isMcpEnabled(env = process.env) {
  return boolEnv(env, 'MCP_ENABLED', MCP_DEFAULTS.ENABLED);
}

export function getMcpConfig(env = process.env) {
  return Object.freeze({
    enabled: isMcpEnabled(env),
    bulkLookupMax: intEnv(env, 'MCP_BULK_LOOKUP_MAX', MCP_DEFAULTS.BULK_LOOKUP_MAX, { min: 1, max: 500 }),
    importMax: intEnv(env, 'MCP_IMPORT_MAX', MCP_DEFAULTS.IMPORT_MAX, { min: 1, max: 500 }),
    searchPageMax: intEnv(env, 'MCP_SEARCH_PAGE_MAX', MCP_DEFAULTS.SEARCH_PAGE_MAX, { min: 1, max: 100 }),
    valueMaxChars: intEnv(env, 'MCP_VALUE_MAX_CHARS', MCP_DEFAULTS.VALUE_MAX_CHARS, { min: 64, max: 8192 }),
    rateLimitPerMin: intEnv(env, 'MCP_RATE_LIMIT_PER_MIN', MCP_DEFAULTS.RATE_LIMIT_PER_MIN, { min: 10, max: 10_000 }),
    rateLimitImportPerMin: intEnv(
      env,
      'MCP_RATE_LIMIT_IMPORT_PER_MIN',
      MCP_DEFAULTS.RATE_LIMIT_IMPORT_PER_MIN,
      { min: 1, max: 1000 }
    ),
    rateLimitSearchPerMin: intEnv(
      env,
      'MCP_RATE_LIMIT_SEARCH_PER_MIN',
      MCP_DEFAULTS.RATE_LIMIT_SEARCH_PER_MIN,
      { min: 1, max: 1000 }
    ),
    rateLimitBulkPerMin: intEnv(
      env,
      'MCP_RATE_LIMIT_BULK_PER_MIN',
      MCP_DEFAULTS.RATE_LIMIT_BULK_PER_MIN,
      { min: 1, max: 1000 }
    )
  });
}
