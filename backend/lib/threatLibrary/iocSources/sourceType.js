/**
 * Classify the format of an Additional IOC Source URL for inspection.
 *
 * Source rows are created by:
 * - selective auto-discovery (`discover.js` / `runDiscovery.js`) — `discovered`
 *   only; never fetch/attach/extract
 * - the explicit Add Source URL action (`store.createManualIocSource`)
 */

import { IOC_SOURCE_TYPES } from './constants.js';

/**
 * A parse format as a persisted `source_type`: the column is constrained to
 * IOC_SOURCE_TYPES (migration 050), while the parser also reports `ndjson` /
 * `asciidoc`. Unknown values become 'unknown' rather than failing the write.
 * @param {string|null|undefined} format
 */
export function persistableSourceType(format) {
  if (format == null || format === '') return null;
  const f = String(format).toLowerCase();
  if (IOC_SOURCE_TYPES.includes(f)) return f;
  if (f === 'ndjson' || f === 'jsonl') return 'json';
  if (f === 'asciidoc' || f === 'adoc') return 'markdown';
  return 'unknown';
}

export function guessTypeFromUrl(url) {
  const u = String(url || '').toLowerCase();
  // GitHub blob/tree URLs are source packs even when the path ends in .txt/.csv.
  if (u.includes('github.com/')) {
    if (/\/blob\//.test(u)) return 'github_file';
    if (/\/tree\//.test(u) || /\/ioc\b/.test(u)) return 'github_dir';
  }
  if (u.includes('raw.githubusercontent.com/')) return 'github_file';
  if (/\.pdf(\?|$)/i.test(u)) return 'pdf';
  if (/\.csv(\?|$)/i.test(u)) return 'csv';
  if (/\.stix\.?json(\?|$)/i.test(u) || /stix[^/]*\.json(\?|$)/i.test(u)) return 'stix_json';
  if (/\.json(\?|$)/i.test(u)) return 'json';
  if (/\.stix\.?xml(\?|$)/i.test(u) || /stix[^/]*\.xml(\?|$)/i.test(u) || /\.stix(\?|$)/i.test(u)) return 'stix_xml';
  if (/\.xml(\?|$)/i.test(u)) return 'xml';
  if (/\.(txt|md|ioc|ya?ml)(\?|$)/i.test(u)) return 'txt';
  if (/\.(html?|htm)(\?|$)/i.test(u)) return 'html';
  return 'unknown';
}
