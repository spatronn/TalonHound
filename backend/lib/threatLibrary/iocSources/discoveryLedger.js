/**
 * Source-discovery ledger: what discovery examined for a report and how each
 * linked source was resolved. Append-only. Recording never decides membership and
 * never attaches, approves or extracts anything.
 */

import { canonicalizeReportUrl } from '../importIdentity.js';
import { LINKED_SOURCE_PENDING_STATUSES, LINKED_SOURCE_UNRESOLVED_STATUSES } from '../finalizeGuard.js';
import { guessTypeFromUrl } from './sourceType.js';

export const SOURCE_DISCOVERY_VERSION = 'tl-source-discovery-v1';

/** References stored per run; the rest are counted, never silently dropped. */
export const MAX_RECORDED_REFERENCES = 300;

const PENDING = new Set(LINKED_SOURCE_PENDING_STATUSES);
const UNRESOLVED = new Set(LINKED_SOURCE_UNRESOLVED_STATUSES);

/** Rejections that are page furniture rather than a reference to anything. */
const NOISE_REJECTIONS = new Set(['unparseable_url', 'unsupported_scheme', 'lookup_or_social_service', 'per_indicator_link']);

/**
 * Whether a rejected link is worth a ledger row: a reference a reader could take
 * for a package, not navigation.
 * @param {{ rejected?: string, matchedCues?: string[] }} scored
 */
export function isRelevantRejection(scored) {
  if (NOISE_REJECTIONS.has(scored?.rejected)) return false;
  if (scored?.rejected === 'same_site_navigation') return (scored.matchedCues || []).length > 0;
  return true;
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

/**
 * Merge the accepted and rejected sightings of one pass into one row per URL. An
 * accepted sighting wins over a rejected one (the same link can sit in a better
 * and a worse context).
 * @param {{ accepted: object[], rejected: object[], reportUrl?: string|null }} input
 * @returns {{ rows: object[], notRecorded: number, examined: number }}
 */
export function buildReferenceRows({ accepted = [], rejected = [], reportUrl = null }) {
  const publisherHost = hostOf(reportUrl);
  const byCanon = new Map();
  for (const a of accepted) {
    const key = a.canonical_url;
    const prev = byCanon.get(key);
    if (prev && (prev.score || 0) >= (a.score || 0)) continue;
    const ev = a.discovery_evidence || {};
    byCanon.set(key, {
      url: a.original_url || key,
      canonical_url: key,
      discovery_method: a.reference_method || 'document_link',
      publisher_host: publisherHost,
      source_type: a.source_type || guessTypeFromUrl(key),
      link_text: ev.link_text || null,
      heading_text: ev.heading_text || null,
      surrounding_text: ev.surrounding_text || null,
      score: a.score || 0,
      matched_cues: ev.matched_cues || [],
      decision: 'accepted',
      rejection_reason: null
    });
  }
  for (const r of rejected) {
    const canonical = canonicalizeReportUrl(r.href) || r.href;
    const prev = byCanon.get(canonical);
    if (prev && prev.decision === 'accepted') continue;
    if (prev && (prev.score || 0) >= (r.score || 0)) continue;
    byCanon.set(canonical, {
      url: r.href,
      canonical_url: canonical,
      discovery_method: r.reference_method || 'document_link',
      publisher_host: publisherHost,
      source_type: guessTypeFromUrl(canonical),
      link_text: String(r.linkText || '').slice(0, 240) || null,
      heading_text: r.headingText ? String(r.headingText).slice(0, 200) : null,
      surrounding_text: String(r.surrounding || '').slice(0, 400) || null,
      score: r.score || 0,
      matched_cues: (r.matchedCues || []).slice(0, 16),
      decision: 'rejected',
      rejection_reason: r.rejected || 'below_score_threshold'
    });
  }
  const all = [...byCanon.values()];
  // Every accepted row is kept; rejected rows fill what remains of the cap, best evidence first.
  const acceptedRows = all.filter((x) => x.decision === 'accepted');
  const rejectedRows = all.filter((x) => x.decision === 'rejected').sort((a, b) => b.score - a.score || b.matched_cues.length - a.matched_cues.length);
  const room = Math.max(0, MAX_RECORDED_REFERENCES - acceptedRows.length);
  const rows = [...acceptedRows, ...rejectedRows.slice(0, room)];
  return { rows, notRecorded: all.length - rows.length, examined: all.length };
}

/**
 * @param {{ query: Function }} pool
 * @param {number} reportId
 * @param {{ status: string, rows?: object[], notRecorded?: number, examined?: number, sourcesInserted?: number, errorDetail?: string|null }} run
 */
export async function recordDiscoveryRun(pool, reportId, run) {
  const rows = run.rows || [];
  const accepted = rows.filter((r) => r.decision === 'accepted').length;
  const { rows: inserted } = await pool.query(
    `INSERT INTO threat_report_source_discovery_runs (
       report_id, discovery_version, status, references_examined, references_accepted,
       references_rejected, references_not_recorded, sources_inserted, error_detail
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, public_id`,
    [
      reportId, SOURCE_DISCOVERY_VERSION, run.status, run.examined ?? rows.length, accepted, rows.length - accepted,
      run.notRecorded || 0, run.sourcesInserted || 0, run.errorDetail ? String(run.errorDetail).slice(0, 500) : null
    ]
  );
  const runId = inserted[0].id;
  if (rows.length) {
    await pool.query(
      `INSERT INTO threat_report_source_references (
         discovery_run_id, report_id, url, canonical_url, discovery_method, publisher_host, source_type,
         link_text, heading_text, surrounding_text, score, matched_cues, decision, rejection_reason, source_public_id
       )
       SELECT $1, $2, x.url, x.canonical_url, x.discovery_method, x.publisher_host, x.source_type,
              x.link_text, x.heading_text, x.surrounding_text, COALESCE(x.score, 0), COALESCE(x.matched_cues, '[]'::jsonb),
              x.decision, x.rejection_reason,
              (SELECT s.public_id FROM threat_report_ioc_sources s WHERE s.report_id = $2 AND s.canonical_url = x.canonical_url)
         FROM jsonb_to_recordset($3::jsonb) AS x(
           url text, canonical_url text, discovery_method text, publisher_host text, source_type text,
           link_text text, heading_text text, surrounding_text text, score int, matched_cues jsonb,
           decision text, rejection_reason text
         )`,
      [runId, reportId, JSON.stringify(rows)]
    );
  }
  return inserted[0];
}

/**
 * Append the resolution outcome of a linked source, read from its stored row.
 * @param {{ query: Function }} pool
 * @param {number} sourceId
 * @param {'inspection'|'extraction'|'dismissal'} eventType
 * @param {{ detail?: string|null, actorPublicId?: string|null }} [extra]
 */
export async function recordResolutionEvent(pool, sourceId, eventType, extra = {}) {
  const { rows } = await pool.query(`SELECT * FROM threat_report_ioc_sources WHERE id = $1`, [sourceId]);
  const s = rows[0];
  if (!s) return null;
  const { rows: files } = await pool.query(
    `SELECT path, content_sha, size_bytes, selected, parse_status, error_detail
       FROM threat_report_ioc_source_files WHERE source_id = $1 ORDER BY id LIMIT 500`,
    [sourceId]
  );
  const scope = s.preview && typeof s.preview === 'object' ? s.preview.scope || {} : {};
  await pool.query(
    `INSERT INTO threat_report_source_resolution_events (
       report_id, source_public_id, url, event_type, outcome, error_code, detail,
       content_hash, repo_revision, evidence, files, actor_public_id
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12)`,
    [
      s.report_id, s.public_id, s.canonical_url || s.original_url, eventType, s.lifecycle_status, s.error_code || null,
      extra.detail || s.error_detail || null, s.content_hash || null, s.repo_revision || null,
      JSON.stringify(scope), JSON.stringify(files), extra.actorPublicId || null
    ]
  );
  return true;
}

/**
 * Run a resolution step and append its outcome. A ledger failure is logged and
 * never changes the outcome of the step itself.
 */
export async function withResolutionEvent(pool, source, eventType, step, logger = console) {
  const result = await step();
  try {
    await recordResolutionEvent(pool, source.id, eventType);
  } catch (err) {
    logger?.warn?.('source resolution event not recorded', { source: source.public_id, error: String(err?.message || err).slice(0, 200) });
  }
  return result;
}

/** Skipped entries that mean part of a pack was not read. */
const COVERAGE_GAP_REASONS = new Set(['too_large', 'file_limit']);

/**
 * The report's package coverage (pure). Never "complete" while a declared source
 * is open, and never "none" for a report discovery has not examined.
 * @param {{
 *   latestRun?: { status: string }|null,
 *   sources?: Array<{ lifecycle_status: string, skipped_files?: Array<{ reason: string }> }>,
 *   announced?: boolean
 * }} input
 */
export function packageCoverage({ latestRun = null, sources = [], announced = false }) {
  const live = sources.filter((s) => s.lifecycle_status !== 'dismissed');
  const counts = {
    declared: live.length,
    extracted: live.filter((s) => s.lifecycle_status === 'extracted').length,
    pending: live.filter((s) => PENDING.has(s.lifecycle_status)).length,
    unresolved: live.filter((s) => UNRESOLVED.has(s.lifecycle_status)).length,
    dismissed: sources.length - live.length
  };
  const gaps = live
    .filter((s) => s.lifecycle_status === 'extracted')
    .flatMap((s) => (s.skipped_files || []).filter((f) => COVERAGE_GAP_REASONS.has(f.reason)));
  let status;
  if (counts.unresolved) status = 'unresolved';
  else if (counts.pending) status = 'pending';
  else if (!latestRun && !sources.length) status = 'not_recorded';
  else if (latestRun && (latestRun.status === 'failed' || latestRun.status === 'partial')) status = 'discovery_incomplete';
  else if (gaps.length) status = 'partial';
  else if (counts.extracted) status = 'complete';
  else if (counts.dismissed) status = 'dismissed';
  else if (announced) status = 'announced_not_found';
  else status = 'no_package_declared';
  return { status, discovery_status: latestRun?.status || 'not_recorded', ...counts, files_not_read: gaps.length };
}

/**
 * Discovery runs, references and resolution events of a report, newest run first.
 * @param {{ query: Function }} pool
 * @param {number} reportId
 */
export async function loadSourceDiscoveryLedger(pool, reportId) {
  const [runs, refs, events] = await Promise.all([
    pool.query(
      `SELECT id, public_id, discovery_version, status, references_examined, references_accepted, references_rejected,
              references_not_recorded, sources_inserted, error_detail, created_at
         FROM threat_report_source_discovery_runs WHERE report_id = $1 ORDER BY id DESC LIMIT 20`,
      [reportId]
    ),
    pool.query(
      `SELECT discovery_run_id, url, canonical_url, discovery_method, publisher_host, source_type, link_text, heading_text,
              surrounding_text, score, matched_cues, decision, rejection_reason, source_public_id
         FROM threat_report_source_references
        WHERE discovery_run_id = (SELECT max(id) FROM threat_report_source_discovery_runs WHERE report_id = $1)
        ORDER BY decision, score DESC, id`,
      [reportId]
    ),
    pool.query(
      `SELECT source_public_id, url, event_type, outcome, error_code, detail, content_hash, repo_revision, evidence, files,
              actor_public_id, created_at
         FROM threat_report_source_resolution_events WHERE report_id = $1 ORDER BY id DESC LIMIT 100`,
      [reportId]
    )
  ]);
  return {
    runs: runs.rows.map(({ id, ...r }) => r),
    references: refs.rows.map(({ discovery_run_id, ...r }) => r),
    events: events.rows
  };
}
