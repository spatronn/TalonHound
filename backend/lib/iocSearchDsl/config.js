// Central, env-driven limits and knobs for the IOC Search DSL.
//
// Every guard the parser enforces is sourced here so operators can tune them via
// environment without code changes. Values are clamped to sane bounds so a typo in
// the environment cannot disable a safety limit entirely.

function intFromEnv(name, fallback, { min, max } = {}) {
  const raw = Number(process.env[name]);
  let value = Number.isFinite(raw) ? Math.trunc(raw) : fallback;
  if (typeof min === 'number') value = Math.max(value, min);
  if (typeof max === 'number') value = Math.min(value, max);
  return value;
}

export function getSearchLimits() {
  return {
    maxQueryLength: intFromEnv('IOC_SEARCH_MAX_QUERY_LENGTH', 4000, { min: 16, max: 100_000 }),
    maxConditions: intFromEnv('IOC_SEARCH_MAX_CONDITIONS', 30, { min: 1, max: 500 }),
    maxParenthesesDepth: intFromEnv('IOC_SEARCH_MAX_PARENTHESES_DEPTH', 8, { min: 1, max: 64 }),
    maxInItems: intFromEnv('IOC_SEARCH_MAX_IN_ITEMS', 100, { min: 1, max: 1000 })
  };
}

export function getPreviewLimit() {
  return intFromEnv('IOC_SEARCH_PREVIEW_LIMIT', 2000, { min: 1, max: 100_000 });
}

export function getQueryTimeoutMs() {
  return intFromEnv('IOC_SEARCH_QUERY_TIMEOUT_MS', 5000, { min: 100, max: 120_000 });
}

// Deep-search classifier knobs. The classifier decides — from the normalized AST, never
// raw user text — whether a query is index-friendly enough to run interactively or must
// be routed to an asynchronous Deep Search. Every threshold lives here so operators can
// tune it without touching the classifier logic.
//
//   trigramMinLength : shortest value for which the observable/source trigram GIN index
//                      can still serve a `%value%` / `value%` / `%value` pattern. Below
//                      this a wildcard search degrades to a scan (Postgres pg_trgm needs
//                      a full 3-gram; default 3).
//   maxOrBranches    : an OR group wider than this is treated as a broad scan even when
//                      each branch is individually indexable.
export function getClassifierConfig() {
  return {
    trigramMinLength: intFromEnv('IOC_SEARCH_TRIGRAM_MIN_LENGTH', 3, { min: 1, max: 16 }),
    maxOrBranches: intFromEnv('IOC_SEARCH_MAX_INTERACTIVE_OR_BRANCHES', 4, { min: 1, max: 64 })
  };
}

// Timezone used to interpret bare date/datetime literals in the DSL. Bound explicitly
// into every date comparison via `($value::timestamp AT TIME ZONE $tz)` so the result
// is deterministic and never depends on the database session TimeZone. Default UTC.
export function getSearchTimezone() {
  const tz = String(process.env.IOC_SEARCH_TIMEZONE || '').trim();
  return tz || 'UTC';
}
