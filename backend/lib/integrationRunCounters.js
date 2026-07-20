// Single source of truth for integration run counter semantics.
//
// WHY THIS EXISTS
// ---------------
// Several importers write run counters (usomImportStore, import-metrics,
// integrationQueueJobState, customThreatFeedImport...). Historically each decided for
// itself what "duplicate" meant, so the API could return values that were not comparable
// across feeds. Every read path must go through resolveRunCounters() so a run row is
// interpreted identically no matter which importer produced it.
//
// CANONICAL vs DEPRECATED
// -----------------------
// records_unchanged is canonical: a row seen again with an identical canonical content
// fingerprint, for which no physical UPDATE was issued.
//
// records_duplicate is DEPRECATED and retained only for backward compatibility with
// existing API clients. Two kinds of rows carry it:
//   * rows written by the migration-121-aware USOM path, where it mirrors
//     records_unchanged exactly;
//   * legacy rows (and importers not yet migrated) that only ever populated
//     records_duplicate.
// The `records_unchanged ?? records_duplicate ?? 0` fallback below resolves both without
// needing to backfill or to migrate every importer in this change set.
//
// New consumers MUST read `unchanged`. Do not add new writers of records_duplicate.

/** @param {unknown} value */
function metricInt(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : 0;
}

/**
 * Resolve the unchanged counter for a run row, tolerating legacy rows.
 * Semantics: records_unchanged ?? records_duplicate ?? 0
 * @param {object|null} row
 */
export function resolveUnchangedCount(row) {
  if (!row) return 0;
  if (row.records_unchanged != null) return metricInt(row.records_unchanged);
  if (row.records_duplicate != null) return metricInt(row.records_duplicate);
  return 0;
}

/**
 * Normalize a run row into the counter set the API exposes.
 *
 * `duplicate` is emitted as an alias of `unchanged` so old clients keep working while
 * never disagreeing with the canonical field.
 * @param {object|null} row
 */
export function resolveRunCounters(row) {
  const unchanged = resolveUnchangedCount(row);
  return {
    processed: metricInt(row?.records_processed),
    inserted: metricInt(row?.records_inserted),
    updated: metricInt(row?.records_updated),
    unchanged,
    reactivated: metricInt(row?.records_reactivated),
    removed: metricInt(row?.records_removed),
    // DEPRECATED alias — always equals `unchanged`.
    duplicate: unchanged,
    skipped: metricInt(row?.records_skipped),
    suppressed: metricInt(row?.records_suppressed),
    failed: metricInt(row?.records_failed)
  };
}

/**
 * Counter columns every run-selecting query should project so resolveRunCounters() has
 * what it needs. Kept here so a new column cannot be added to one query and forgotten
 * in another.
 */
export const RUN_COUNTER_COLUMNS = Object.freeze([
  'records_processed',
  'records_inserted',
  'records_updated',
  'records_unchanged',
  'records_reactivated',
  'records_removed',
  'records_duplicate',
  'records_skipped',
  'records_suppressed',
  'records_failed'
]);
