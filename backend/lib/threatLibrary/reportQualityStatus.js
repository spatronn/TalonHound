/**
 * What is known about a report, one dimension at a time. `finalized` says an analyst
 * closed the report; it does not say the extraction was perfect, and these axes keep
 * the two apart.
 *
 * The finalize obligations apply to reports with a first-pass extraction run: reports
 * imported through the current pipeline. Earlier reports keep their finalized state
 * and read as historical, with coverage "not recorded" rather than assumed.
 */

import { isPendingActionableCandidate, previewCreateIocPromotion } from './promotion.js';
import { contractFingerprint, extractionContractBundle } from './contractBundle.js';
import { packageCoverage } from './iocSources/discoveryLedger.js';
import { isNeedsReviewCandidate } from './indicatorMembership.js';
import { storedExtractionQuality } from './extractionQuality.js';

export const FINALIZE_OBLIGATION_CODES = Object.freeze({
  EXTRACTION_NOT_RECORDED: 'extraction_run_not_recorded',
  SOURCE_REGIONS_UNACCOUNTED: 'source_regions_unaccounted',
  DISCOVERY_INCOMPLETE: 'ioc_source_discovery_incomplete',
  DISMISSAL_WITHOUT_EVIDENCE: 'ioc_source_dismissed_without_evidence',
  APPROVED_NOT_LINKED: 'approved_indicators_not_linked',
  CRITICAL_EXTRACTION_FAILURE: 'critical_extraction_failure'
});

/**
 * Quality checks that mean Indicators were lost, not that something looks unusual.
 * Across the existing library these fire on about one report in 700, so they stop a
 * finalize without stopping ordinary work.
 */
export const CRITICAL_QUALITY_CODES = Object.freeze(['explicit_table_rows_dropped', 'appendix_without_hash_indicators', 'reserved_indicator']);

const CRITICAL = new Set(CRITICAL_QUALITY_CODES);

/**
 * @typedef {{
 *   firstPassRun: object|null,
 *   latestRun: { operational_status: string, contract_fingerprint?: string }|null,
 *   significantRegions: Array<{ region_kind: string, locator?: string|null, observable_count: number }>,
 *   latestDiscovery: { status: string }|null,
 *   sources: Array<{ lifecycle_status: string, public_id?: string, dismissal_reason?: string|null, canonical_url?: string }>,
 *   candidates: object[],
 *   quality: object|null
 * }} ObligationSnapshot
 */

/**
 * Unmet finalize obligations (pure). Pending review and open linked sources have
 * their own blockers in finalizeGuard.js and are not repeated here.
 * @param {ObligationSnapshot} s
 * @returns {{ applies: boolean, unmet: Array<{ code: string, message: string, detail?: object }> }}
 */
export function evaluateFinalizeObligations(s) {
  if (!s.firstPassRun) return { applies: false, unmet: [] };
  const unmet = [];
  if (!s.latestRun) {
    unmet.push({ code: FINALIZE_OBLIGATION_CODES.EXTRACTION_NOT_RECORDED, message: 'No completed extraction run is recorded for this report.' });
  }
  const regions = (s.significantRegions || []).filter((r) => r.observable_count > 0);
  if (regions.length) {
    const n = regions.reduce((sum, r) => sum + r.observable_count, 0);
    unmet.push({
      code: FINALIZE_OBLIGATION_CODES.SOURCE_REGIONS_UNACCOUNTED,
      message: `${regions.length} source region${regions.length === 1 ? '' : 's'} with ${n} observable-shaped value${n === 1 ? '' : 's'} did not reach the document.`,
      detail: { regions: regions.slice(0, 10).map((r) => ({ region_kind: r.region_kind, locator: r.locator || null, observable_count: r.observable_count })) }
    });
  }
  if (!s.latestDiscovery || s.latestDiscovery.status === 'failed' || s.latestDiscovery.status === 'partial') {
    unmet.push({
      code: FINALIZE_OBLIGATION_CODES.DISCOVERY_INCOMPLETE,
      message: 'IOC Source discovery did not finish for this report, so a publisher package may be missing.',
      detail: { discovery_status: s.latestDiscovery?.status || 'not_recorded' }
    });
  }
  const undocumented = (s.sources || []).filter((x) => x.lifecycle_status === 'dismissed' && !String(x.dismissal_reason || '').trim());
  if (undocumented.length) {
    unmet.push({
      code: FINALIZE_OBLIGATION_CODES.DISMISSAL_WITHOUT_EVIDENCE,
      message: `${undocumented.length} dismissed IOC Source${undocumented.length === 1 ? ' has' : 's have'} no stated reason.`,
      detail: { sources: undocumented.slice(0, 10).map((x) => ({ public_id: x.public_id, url: x.canonical_url })) }
    });
  }
  const eligible = previewCreateIocPromotion(s.candidates || []).summary.eligible;
  if (eligible > 0) {
    unmet.push({
      code: FINALIZE_OBLIGATION_CODES.APPROVED_NOT_LINKED,
      message: `${eligible} approved Indicator${eligible === 1 ? ' is' : 's are'} not linked to an IOC: run Create IOCs first.`,
      detail: { eligible }
    });
  }
  const critical = (s.quality?.warnings || []).filter((w) => CRITICAL.has(w?.code));
  if (critical.length) {
    unmet.push({
      code: FINALIZE_OBLIGATION_CODES.CRITICAL_EXTRACTION_FAILURE,
      message: `Extraction reported ${critical.length === 1 ? 'a critical failure' : `${critical.length} critical failures`}: ${critical.map((w) => w.code).join(', ')}.`,
      detail: { codes: critical.map((w) => w.code) }
    });
  }
  return { applies: true, unmet };
}

/**
 * The independent status dimensions of a report (pure).
 * @param {ObligationSnapshot & { report?: object, exceptions?: object[], currentFingerprint?: string }} s
 */
export function reportStatusAxes(s) {
  const historical = !s.firstPassRun;
  const candidates = s.candidates || [];
  const pending = candidates.filter((c) => isPendingActionableCandidate(c)).length;
  const uncertain = candidates.filter((c) => isNeedsReviewCandidate(c) && (c.review_status || 'pending') === 'pending').length;
  const linkable = previewCreateIocPromotion(candidates).summary.eligible;
  const regions = (s.significantRegions || []).filter((r) => r.observable_count > 0);
  const critical = (s.quality?.warnings || []).filter((w) => CRITICAL.has(w?.code)).map((w) => w.code);
  const fingerprint = s.currentFingerprint ?? contractFingerprint(extractionContractBundle());
  let freshness = 'not_recorded';
  if (s.latestRun?.contract_fingerprint) freshness = s.latestRun.contract_fingerprint === fingerprint ? 'current' : 'older_contract';
  let documentCoverage = 'not_recorded';
  if (s.latestRun && s.latestRun.run_type !== 'legacy_baseline') documentCoverage = regions.length ? 'regions_unaccounted' : 'accounted';
  return {
    generation: historical ? 'historical' : 'first_pass_recorded',
    finalized: Boolean(s.report?.finalized_at),
    operational_execution: { status: s.latestRun?.operational_status && s.latestRun.run_type !== 'legacy_baseline' ? s.latestRun.operational_status : 'not_recorded', critical_failures: critical },
    document_coverage: { status: documentCoverage, regions_unaccounted: regions.length },
    package_discovery: packageCoverage({ latestRun: s.latestDiscovery || null, sources: s.sources || [] }),
    classification_uncertainty: { status: uncertain ? 'open' : 'none', needs_review: uncertain },
    analyst_review: { status: pending ? 'open' : 'complete', pending },
    ioc_linking: { status: linkable ? 'open' : 'complete', not_linked: linkable },
    contract_freshness: { status: freshness },
    exceptions: (s.exceptions || []).map((e) => ({ obligation_code: e.obligation_code, reason: e.reason, created_at: e.created_at }))
  };
}

/**
 * Read what the obligations and axes need. `db` may be a client holding the report
 * lock; the candidates and sources are passed in when the caller already read them.
 * @param {{ query: Function }} db
 * @param {object} report
 * @param {{ candidates?: object[], sources?: object[] }} [known]
 * @returns {Promise<ObligationSnapshot & { report: object, exceptions: object[] }>}
 */
export async function loadObligationSnapshot(db, report, known = {}) {
  const reportId = report.id;
  const runs = await db.query(
    `SELECT id, run_type, is_first_pass, operational_status, contract_fingerprint
       FROM threat_report_extraction_runs WHERE report_id = $1 ORDER BY id DESC`,
    [reportId]
  );
  const runRows = runs?.rows || [];
  const latestRun = runRows[0] || null;
  const firstPassRun = runRows.find((r) => r.is_first_pass) || null;
  const realRun = runRows.find((r) => r.run_type !== 'legacy_baseline') || null;
  const regions = realRun
    ? await db.query(
      `SELECT region_kind, locator, observable_count FROM threat_report_dropped_regions
        WHERE run_id = $1 AND significant ORDER BY observable_count DESC LIMIT 50`,
      [realRun.id]
    )
    : { rows: [] };
  const discovery = await db.query(
    `SELECT status FROM threat_report_source_discovery_runs WHERE report_id = $1 ORDER BY id DESC LIMIT 1`,
    [reportId]
  );
  const sources = known.sources || (await db.query(
    `SELECT public_id, lifecycle_status, dismissal_reason, canonical_url, error_code,
            preview->'scope'->'skipped_files' AS skipped_files
       FROM threat_report_ioc_sources WHERE report_id = $1 ORDER BY id`,
    [reportId]
  )).rows.map((r) => ({ ...r, skipped_files: Array.isArray(r.skipped_files) ? r.skipped_files : [] }));
  const candidates = known.candidates || (await db.query(`SELECT * FROM threat_report_candidates WHERE report_id = $1`, [reportId])).rows;
  const exceptions = await db.query(
    `SELECT obligation_code, reason, created_at FROM threat_report_finalize_exceptions WHERE report_id = $1 ORDER BY id`,
    [reportId]
  );
  return {
    report,
    firstPassRun,
    latestRun: realRun || latestRun,
    significantRegions: regions?.rows || [],
    latestDiscovery: discovery?.rows?.[0] || null,
    sources,
    candidates,
    quality: storedExtractionQuality(report),
    exceptions: exceptions?.rows || []
  };
}

/**
 * Obligations an administrator's exception has to cover: those without one on record.
 * @param {Array<{ code: string }>} unmet
 * @param {Array<{ obligation_code: string }>} exceptions
 */
export function uncoveredObligations(unmet, exceptions = []) {
  const covered = new Set(exceptions.map((e) => e.obligation_code));
  return unmet.filter((o) => !covered.has(o.code));
}
