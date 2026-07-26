// IOC List table "Timestamp" column — platform first-import time.
// Never use last_changed_in_source / last_seen_in_feed for this column.
export const IOC_LIST_TIMESTAMP_PRESENTATION = Object.freeze({
  label: 'Timestamp',
  apiField: 'imported_at',
  fallbackApiFields: Object.freeze(['created_at']),
  description: 'When this IOC was first added to TalonHound. Stable across re-syncs.'
});

/** Resolve list Timestamp value from an IOC list row (no client-side source fallback). */
export function resolveIocListTimestamp(row = {}) {
  return row.imported_at || row.created_at || null;
}
