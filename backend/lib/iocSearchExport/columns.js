// Export column registry. Each column has a stable key (persisted in selected_columns),
// a CSV header label, and a formatter that reads from an assembled export record.
//
// NOTE: no `updated_at` or `last_seen` column. ioc_items has no truthful item-level
// updated_at, and ioc_items.last_seen_at carries feed-heterogeneous/technical semantics
// that the analyst presentation layer deliberately does not surface. Timestamp columns
// use analyst-visible source semantics only:
//   first_seen_in_source   = MIN(first_seen_in_feed) across memberships, else item first_seen_at
//   last_changed_in_source = MAX(COALESCE(last_changed_in_source, first_seen_in_feed)); never last_seen_in_feed
import { csvTimestamp } from './csv.js';

export const EXPORT_COLUMNS = Object.freeze({
  ioc: { header: 'IOC', format: (r) => r.observable },
  ioc_type: { header: 'IOC Type', format: (r) => r.observable_type },
  status: { header: 'Status', format: (r) => r.status || 'active' },
  source: { header: 'Source', format: (r) => r.source_name },
  confidence: { header: 'Confidence', format: (r) => r.confidence },
  tags: { header: 'Tags', format: (r) => (r.tags || []).join('|') },
  classifications: { header: 'Classifications', format: (r) => (r.classifications || []).join('|') },
  threat_actor: { header: 'Threat actor', format: (r) => r.threat_actor_name || '' },
  first_seen_in_source: { header: 'First seen in source', format: (r) => csvTimestamp(r.first_seen_in_source) },
  last_changed_in_source: { header: 'Last changed in source', format: (r) => csvTimestamp(r.last_changed_in_source) },
  created_at: { header: 'Created at', format: (r) => csvTimestamp(r.created_at) }
});

export const EXPORT_COLUMN_KEYS = Object.freeze(Object.keys(EXPORT_COLUMNS));

export const DEFAULT_EXPORT_COLUMNS = Object.freeze([
  'ioc',
  'ioc_type',
  'status',
  'source',
  'confidence',
  'tags',
  'classifications',
  'first_seen_in_source',
  'last_changed_in_source'
]);

// Validate & normalize a requested column list. Returns the sanitized list (in the
// requested order) or the default list when none/invalid are provided.
export function sanitizeColumns(requested) {
  if (!Array.isArray(requested) || requested.length === 0) {
    return [...DEFAULT_EXPORT_COLUMNS];
  }
  const seen = new Set();
  const out = [];
  for (const key of requested) {
    const k = String(key || '').trim();
    if (EXPORT_COLUMNS[k] && !seen.has(k)) {
      seen.add(k);
      out.push(k);
    }
  }
  return out.length ? out : [...DEFAULT_EXPORT_COLUMNS];
}

export function headerRow(columns) {
  return columns.map((k) => EXPORT_COLUMNS[k].header);
}

export function formatRecord(record, columns) {
  return columns.map((k) => EXPORT_COLUMNS[k].format(record));
}
