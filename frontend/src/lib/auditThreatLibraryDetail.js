// Pure helpers for rendering Threat Library audit events in the Audit Log.
//
// Actor / entity / status come from the audit row columns; the operation
// summary comes from metadata written by the backend after the operation
// committed (never reconstructed client-side).

export const THREAT_LIBRARY_ACTION_PREFIX = 'threat_library.';
export const THREAT_LIBRARY_CREATE_IOCS_ACTION = 'threat_library.iocs.created';

/** Actor column text. Legacy rows with no actor keep rendering "—". */
export function auditActorLabel(row) {
  return row?.actor_username || row?.actor_email || '—';
}

export function isThreatLibraryAuditRow(row) {
  return String(row?.action || '').startsWith(THREAT_LIBRARY_ACTION_PREFIX);
}

function num(value) {
  return value == null || value === '' || Number.isNaN(Number(value)) ? null : Number(value);
}

function formatTypeDistribution(types) {
  if (!types || typeof types !== 'object') return null;
  const parts = Object.entries(types)
    .filter(([, n]) => Number(n) > 0)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([type, n]) => `${type}: ${n}`);
  return parts.length ? parts.join(' · ') : null;
}

export function formatAuditStatusLabel(status) {
  const s = String(status || '').toLowerCase();
  if (s === 'partial') return 'Partial';
  if (s === 'failed') return 'Failed';
  return 'Success';
}

/**
 * Label/value rows for the detail view of a Threat Library event.
 * Returns [] for non-Threat-Library rows so callers can render nothing.
 * @param {object} row - public audit row (metadata already parsed)
 * @returns {Array<[string, string]>}
 */
export function threatLibraryDetailRows(row) {
  if (!isThreatLibraryAuditRow(row)) return [];
  const m = row?.metadata && typeof row.metadata === 'object' ? row.metadata : {};
  const action = String(row.action || '');
  const rows = [];
  const push = (label, value) => {
    if (value == null || value === '' || value === '—') return;
    rows.push([label, String(value)]);
  };

  push('Report', m.report_title || row.entity_display);
  push('Report ID', m.report_public_id || row.entity_id);
  if (m.tlp) push('TLP', `TLP:${String(m.tlp).toUpperCase().replace('_STRICT', '+STRICT')}`);
  if (m.source_type) push('Source type', m.source_type);
  push('Initiated by', m.initiated_by || auditActorLabel(row));
  if (m.executed_by && m.executed_by !== 'backend') push('Executed by', m.executed_by);
  push('Result', m.result);

  if (action === THREAT_LIBRARY_CREATE_IOCS_ACTION) {
    push('Selected', num(m.selected));
    push('Eligible', num(m.eligible));
    push('Created', num(m.created));
    push('Already existing', num(m.already_existing));
    push('Not approved', num(m.not_approved));
    push('Unsupported', num(m.unsupported));
    push('Not applicable', num(m.not_applicable));
    push('Failed', num(m.failed));
    push('Candidate types', formatTypeDistribution(m.candidate_types));
    push('Operation ID', m.operation_id);
    push('Error', m.error_code);
  } else if (action.startsWith('threat_library.candidates.')) {
    push('Selected', num(m.selected));
    push('Changed', num(m.changed));
    push('Already in state', num(m.already_in_state));
    push('Target state', m.target_state);
    push('Candidate types', formatTypeDistribution(m.candidate_types));
  } else if (action === 'threat_library.report.finalized') {
    push('Total candidates', num(m.total_candidates));
    push('Approved', num(m.approved));
    push('Context only', num(m.context_only));
    push('Ignored', num(m.ignored));
    push('IOCs created', num(m.created));
    push('Already existing', num(m.already_existing));
    push('Unsupported', num(m.unsupported));
    push('Failed', num(m.failed));
  } else if (action.startsWith('threat_library.report.imported') || action === 'threat_library.report.import_failed') {
    push('File', m.file_name);
    push('SHA-256', m.sha256);
    push('Source URL', m.source_url);
    push('Host', m.host);
    push('Job', m.job_public_id);
    push('Error', m.error_code);
  } else if (action.startsWith('threat_library.report.analysis')) {
    push('Job', m.job_public_id);
    push('Candidates', num(m.candidates_total));
    push('New', num(m.candidates_new));
    push('Existing', num(m.candidates_existing));
    push('Context only', num(m.candidates_context_only));
    push('Error', m.error_code);
  } else if (action === 'threat_library.report.source_url.updated') {
    push('Old URL', m.old_source_url ?? row?.before_data?.source_url);
    push('New URL', m.new_source_url ?? row?.after_data?.source_url);
  } else if (action === 'threat_library.thib.exported') {
    push('Indicators', num(m.indicator_count));
    push('Entities', num(m.entity_count));
    push('TLP:RED confirmed', m.confirm_red === true ? 'yes' : null);
  }
  return rows;
}

/**
 * Per-candidate outcome sample for Create IOCs plus an explicit note when
 * the backend omitted rows (bounded sample).
 * @returns {{ rows: object[], note: string|null }}
 */
export function threatLibraryOutcomeSample(row) {
  const m = row?.metadata && typeof row.metadata === 'object' ? row.metadata : {};
  const rows = Array.isArray(m.results) ? m.results : [];
  const total = num(m.results_total) ?? rows.length;
  const shown = num(m.results_shown) ?? rows.length;
  const omitted = num(m.results_omitted) ?? Math.max(0, total - shown);
  const note = omitted > 0
    ? `Showing ${shown} of ${total} outcomes · ${omitted} omitted from the audit detail`
    : null;
  return { rows, note };
}
