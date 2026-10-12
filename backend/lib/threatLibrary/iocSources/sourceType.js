/**
 * Additional IOC Sources are manual-only: an analyst adds a source URL to a
 * report. Nothing scans report content for candidate source links, and no
 * workflow creates threat_report_ioc_sources rows except the explicit
 * Add Source URL action (store.createManualIocSource).
 *
 * This module only classifies the format of a source URL for inspection.
 */

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
  if (/\.json(\?|$)/i.test(u)) return 'json';
  if (/\.(txt|md|ioc|ya?ml)(\?|$)/i.test(u)) return 'txt';
  if (/\.(html?|htm)(\?|$)/i.test(u)) return 'html';
  return 'unknown';
}
