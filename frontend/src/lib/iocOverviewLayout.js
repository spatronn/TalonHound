/**
 * Active Sources Overview columns — timestamps live in IOC Timestamps cards only.
 */
export const ACTIVE_SOURCES_COLUMNS = Object.freeze([
  'Source',
  'Type',
  'Status',
  'Policy expires',
  'Effective expires',
  'Override',
  'Actions'
]);

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
