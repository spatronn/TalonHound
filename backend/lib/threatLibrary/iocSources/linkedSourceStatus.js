/**
 * Read-time status of a report's linked IOC Sources (tl-ioc-source-scope-v1).
 *
 * A publisher that keeps its indicators in an external pack has an incomplete
 * Union until that pack is extracted. The stored extraction-quality record is
 * computed before discovery and never sees the source lifecycle, so the gap is
 * overlaid when a report is read (UI detail, MCP): it never changes membership.
 */

import { LINKED_SOURCE_PENDING_STATUSES, LINKED_SOURCE_UNRESOLVED_STATUSES } from '../finalizeGuard.js';

// One definition of pending / unresolved, shared with the finalize guard.
const PENDING = new Set(LINKED_SOURCE_PENDING_STATUSES);
const UNRESOLVED = new Set(LINKED_SOURCE_UNRESOLVED_STATUSES);

export const LINKED_SOURCE_NOT_INGESTED_CODE = 'linked_ioc_source_not_ingested';
/** The publisher announces an IOC package but no IOC Source was discovered or attached (tl-quality-v10). */
export const IOC_PACKAGE_NOT_DISCOVERED_CODE = 'ioc_package_not_discovered';
/** Persisted candidates lack the extraction provenance a first analysis writes (tl-quality-v10). */
export const EXTRACTION_PROVENANCE_INCOMPLETE_CODE = 'extraction_provenance_incomplete';
/** Candidates exist but no extraction-quality record was stored (tl-quality-v10). */
export const EXTRACTION_QUALITY_MISSING_CODE = 'extraction_quality_missing';
/**
 * A linked IOC Source whose files belong to other reports (their metadata rows
 * link other articles) or whose campaign folder could not be corroborated:
 * the published link does not lead to this report's inventory
 * (tl-ioc-source-scope-v3).
 */
export const LINKED_SOURCE_SCOPE_MISMATCH_CODE = 'linked_ioc_source_scope_mismatch';
const READ_TIME_CODES = new Set([
  LINKED_SOURCE_NOT_INGESTED_CODE,
  LINKED_SOURCE_SCOPE_MISMATCH_CODE,
  IOC_PACKAGE_NOT_DISCOVERED_CODE,
  EXTRACTION_PROVENANCE_INCOMPLETE_CODE,
  EXTRACTION_QUALITY_MISSING_CODE
]);

/**
 * @param {Array<{ lifecycle_status: string }>} rows threat_report_ioc_sources rows
 */
export function summarizeLinkedIocSources(rows) {
  const out = { declared: 0, extracted: 0, pending: 0, unresolved: 0, dismissed: 0, scope_mismatch: 0 };
  for (const r of Array.isArray(rows) ? rows : []) {
    const s = String(r?.lifecycle_status || '');
    if (s === 'dismissed') {
      out.dismissed += 1;
      continue;
    }
    if (r?.error_code === 'campaign_scope_unresolved' || r?.other_report_files > 0) out.scope_mismatch += 1;
    out.declared += 1;
    if (s === 'extracted') out.extracted += 1;
    else if (PENDING.has(s)) out.pending += 1;
    else if (UNRESOLVED.has(s)) out.unresolved += 1;
  }
  return out;
}

/**
 * Overlay read-time gaps onto a stored quality record (copy): un-ingested
 * linked IOC Sources, an announced IOC package with no IOC Source, persisted
 * candidates without extraction provenance, and a missing quality record. The
 * stored record is computed before discovery and never sees these; nothing
 * here changes membership.
 * @param {object|null} quality stored extraction quality
 * @param {(ReturnType<typeof summarizeLinkedIocSources> & { candidate_provenance?: { rows: number, missing: number } })|null} summary
 */
export function withLinkedSourceQuality(quality, summary) {
  if (!summary) return quality;
  const provenance = summary.candidate_provenance || null;
  const add = [];
  if (!quality || typeof quality !== 'object') {
    if (!provenance || !(provenance.rows > 0)) return quality;
    quality = { status: 'clean', mode: null, counts: { high: 0, warning: 0, info: 0 }, warnings: [], warnings_total: 0 };
    add.push({
      code: EXTRACTION_QUALITY_MISSING_CODE,
      severity: 'warning',
      explanation: `${provenance.rows} candidate(s) exist but no extraction-quality record was stored for this report; ` +
        'quality checks did not run on the persisted set (a Refresh extraction recomputes it).'
    });
  }
  const open = summary.pending + summary.unresolved;
  if (open) {
    add.push({
      code: LINKED_SOURCE_NOT_INGESTED_CODE,
      severity: 'warning',
      explanation: `${open} publisher-declared IOC Source(s) are not extracted (${summary.pending} pending, ${summary.unresolved} unresolved): Linked and Union Indicators are incomplete until the analyst inspects and extracts them.`
    });
  }
  if (summary.scope_mismatch > 0) {
    add.push({
      code: LINKED_SOURCE_SCOPE_MISMATCH_CODE,
      severity: 'warning',
      explanation: `${summary.scope_mismatch} linked IOC Source(s) lead to inventories of other reports (or no campaign folder for this report could be corroborated): verify the publisher link before extracting or dismissing.`
    });
  }
  const announced = (quality.warnings || []).some((w) => w?.code === 'ioc_package_announced');
  if (announced && summary.declared === 0 && summary.dismissed === 0) {
    add.push({
      code: IOC_PACKAGE_NOT_DISCOVERED_CODE,
      severity: 'warning',
      explanation: 'The publisher announces a downloadable IOC package but no IOC Source is attached to this report: add it ' +
        'as a linked IOC Source (Union Indicators may be incomplete).'
    });
  }
  if (provenance && provenance.missing > 0) {
    add.push({
      code: EXTRACTION_PROVENANCE_INCOMPLETE_CODE,
      severity: 'warning',
      explanation: `${provenance.missing} of ${provenance.rows} persisted candidate(s) carry no scope-engine / section-tree / ` +
        'type-resolver provenance (stored by an older or reused-candidate path); a Refresh extraction re-derives it.'
    });
  }
  if (!add.length) return quality;
  const warnings = Array.isArray(quality.warnings) ? quality.warnings.filter((w) => !READ_TIME_CODES.has(w?.code)) : [];
  for (const w of add) warnings.push({ section: null, evidence: [], block_ids: [], candidates: [], candidate_count: 0, ...w });
  const counts = { high: 0, warning: 0, info: 0 };
  for (const w of warnings) counts[w.severity] = (counts[w.severity] || 0) + 1;
  return {
    ...quality,
    status: counts.high ? 'high' : counts.warning ? 'warning' : counts.info ? 'info' : 'clean',
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
  const { rows } = await pool.query(
    `SELECT lifecycle_status, error_code,
            COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(preview->'scope'->'other_report_files') = 'array'
                                             THEN preview->'scope'->'other_report_files' END), 0)::int AS other_report_files
       FROM threat_report_ioc_sources WHERE report_id = $1`,
    [reportId]
  );
  const summary = summarizeLinkedIocSources(rows);
  try {
    const r = await pool.query(
      `SELECT count(*)::int AS rows,
              count(*) FILTER (WHERE evidence->>'scope_engine' IS NULL OR evidence->'type_resolution' IS NULL
                                 OR evidence->'type_resolution' = 'null'::jsonb)::int AS missing
         FROM threat_report_candidates
        WHERE report_id = $1 AND has_original_document_occurrence`,
      [reportId]
    );
    const row = r?.rows?.[0];
    if (row && Number.isFinite(Number(row.rows))) {
      summary.candidate_provenance = { rows: Number(row.rows), missing: Number(row.missing) || 0 };
    }
  } catch {
    // Provenance overlay is best-effort read-time diagnostics.
  }
  return summary;
}
