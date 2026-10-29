/**
 * Active Sources Overview columns — timestamps live in IOC Timestamps cards only.
 */
export const ACTIVE_SOURCES_COLUMNS = Object.freeze([
  'Source',
  'Reported as',
  'Type',
  'Status',
  'Policy expires',
  'Effective expires',
  'Override',
  'Actions'
]);

/**
 * Publisher-asserted observable for an Active/Historical source row.
 * Verified file-identity aliases keep the hash the source published.
 * @param {object|null|undefined} src
 */
export function reportedAsLabel(src) {
  const type = String(src?.publisher_observable_type || '').trim();
  const value = String(src?.publisher_observable || '').trim();
  if (!type || !value) return '—';
  const short = value.length > 20 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
  const via = src?.relationship === 'verified_file_identity' ? ' · file identity' : '';
  return `${type} ${short}${via}`;
}

/**
 * Summary strip under Active Sources — Type + Sources only.
 * @param {object|null} summary
 */
export function buildIocSummaryStripItems(summary) {
  if (!summary) return [];
  return [
    { label: 'Type', value: summary.observable_type || '—' },
    {
      label: 'Sources',
      value: `${summary.active_source_count ?? 0} / ${summary.total_source_membership_count ?? summary.source_count ?? summary.active_source_count ?? 0} total`
    }
  ];
}
