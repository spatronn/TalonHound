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
  RATE_LIMIT_BULK_PER_MIN: 60,
  // Enrichment action tools (external, possibly paid provider calls).
  ENRICH_BULK_MAX: 25,
  ENRICH_MAX_OPERATIONS: 100,
  ENRICH_MAX_ACTIVE_JOBS: 5,
  ENRICH_WAIT_MAX_SECONDS: 20,
  RATE_LIMIT_ENRICH_PER_MIN: 10,
  RATE_LIMIT_BULK_ENRICH_PER_MIN: 2,
  // Analyst tag tools (add_ioc_tags / remove_ioc_tags / list_tags).
  TAG_WRITE_MAX: 10,
  TAG_LIST_MAX: 100,
  RATE_LIMIT_TAG_WRITE_PER_MIN: 30
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
    ),
    // Hard ceilings: env can lower these but never lift them past the max.
    enrichBulkMax: intEnv(env, 'MCP_ENRICH_BULK_MAX', MCP_DEFAULTS.ENRICH_BULK_MAX, { min: 1, max: 50 }),
    enrichMaxOperations: intEnv(env, 'MCP_ENRICH_MAX_OPERATIONS', MCP_DEFAULTS.ENRICH_MAX_OPERATIONS, { min: 1, max: 250 }),
    enrichMaxActiveJobs: intEnv(env, 'MCP_ENRICH_MAX_ACTIVE_JOBS', MCP_DEFAULTS.ENRICH_MAX_ACTIVE_JOBS, { min: 1, max: 20 }),
    enrichWaitMaxSeconds: intEnv(env, 'MCP_ENRICH_WAIT_MAX_SECONDS', MCP_DEFAULTS.ENRICH_WAIT_MAX_SECONDS, { min: 1, max: 25 }),
    rateLimitEnrichPerMin: intEnv(env, 'MCP_RATE_LIMIT_ENRICH_PER_MIN', MCP_DEFAULTS.RATE_LIMIT_ENRICH_PER_MIN, { min: 1, max: 120 }),
    rateLimitBulkEnrichPerMin: intEnv(env, 'MCP_RATE_LIMIT_BULK_ENRICH_PER_MIN', MCP_DEFAULTS.RATE_LIMIT_BULK_ENRICH_PER_MIN, { min: 1, max: 30 }),
    tagWriteMax: intEnv(env, 'MCP_TAG_WRITE_MAX', MCP_DEFAULTS.TAG_WRITE_MAX, { min: 1, max: 25 }),
    tagListMax: intEnv(env, 'MCP_TAG_LIST_MAX', MCP_DEFAULTS.TAG_LIST_MAX, { min: 1, max: 200 }),
    rateLimitTagWritePerMin: intEnv(env, 'MCP_RATE_LIMIT_TAG_WRITE_PER_MIN', MCP_DEFAULTS.RATE_LIMIT_TAG_WRITE_PER_MIN, { min: 1, max: 300 })
  });
}
