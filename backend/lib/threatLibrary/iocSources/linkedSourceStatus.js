/**
 * Read-time status of a report's linked IOC Sources (tl-ioc-source-scope-v1).
 *
 * A publisher that keeps its indicators in an external pack has an incomplete
 * Union until that pack is extracted. The stored extraction-quality record is
 * computed before discovery and never sees the source lifecycle, so the gap is
 * overlaid when a report is read (UI detail, MCP): it never changes membership.
 */

const PENDING = new Set(['discovered', 'inspecting', 'inspected', 'attached', 'extracting']);
const UNRESOLVED = new Set(['unsupported', 'failed', 'blocked', 'stale']);

export const LINKED_SOURCE_NOT_INGESTED_CODE = 'linked_ioc_source_not_ingested';

/**
 * @param {Array<{ lifecycle_status: string }>} rows threat_report_ioc_sources rows
 */
export function summarizeLinkedIocSources(rows) {
  const out = { declared: 0, extracted: 0, pending: 0, unresolved: 0, dismissed: 0 };
  for (const r of Array.isArray(rows) ? rows : []) {
    const s = String(r?.lifecycle_status || '');
    if (s === 'dismissed') {
      out.dismissed += 1;
      continue;
    }
    out.declared += 1;
    if (s === 'extracted') out.extracted += 1;
    else if (PENDING.has(s)) out.pending += 1;
    else if (UNRESOLVED.has(s)) out.unresolved += 1;
  }
  return out;
}

/**
 * Overlay the linked-source gap onto a stored quality record (copy).
 * @param {object|null} quality stored extraction quality
 * @param {ReturnType<typeof summarizeLinkedIocSources>|null} summary
 */
export function withLinkedSourceQuality(quality, summary) {
  if (!quality || typeof quality !== 'object' || !summary) return quality;
  const open = summary.pending + summary.unresolved;
  if (!open) return quality;
  const warnings = Array.isArray(quality.warnings) ? quality.warnings.filter((w) => w?.code !== LINKED_SOURCE_NOT_INGESTED_CODE) : [];
  warnings.push({
    code: LINKED_SOURCE_NOT_INGESTED_CODE,
    severity: 'warning',
    section: null,
    evidence: [],
    block_ids: [],
    candidates: [],
    candidate_count: 0,
    explanation: `${open} publisher-declared IOC Source(s) are not extracted (${summary.pending} pending, ${summary.unresolved} unresolved): Linked and Union Indicators are incomplete until the analyst inspects and extracts them.`
  });
  const counts = { high: 0, warning: 0, info: 0, ...(quality.counts || {}) };
  counts.warning = warnings.filter((w) => w.severity === 'warning').length;
  return {
    ...quality,
    status: quality.status === 'high' ? 'high' : 'warning',
    counts,
    warnings,
    warnings_total: warnings.length
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 */
export async function loadLinkedIocSourceSummary(pool, reportId) {
  const { rows } = await pool.query('SELECT lifecycle_status FROM threat_report_ioc_sources WHERE report_id = $1', [reportId]);
  return summarizeLinkedIocSources(rows);
}
