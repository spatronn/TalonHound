/**
 * Immutable extraction run ledger (migration 052).
 *
 * A run is what one completed extraction produced, by exact identity. Runs are
 * append-only; the database refuses updates and direct deletes. First pass =
 * the first completed `analyze` / `retry` result of a report that had no earlier
 * run. A report imported before the ledger holds a `legacy_baseline` run instead
 * and never gains a first-pass record.
 */

import crypto from 'node:crypto';
import { contractFingerprint, extractionContractBundle } from './contractBundle.js';
import { THREAT_LIBRARY_JOB_MODES } from './jobModes.js';
import { isLinkedSourceIndicatorMember, isReportIndicatorMember } from './indicatorMembership.js';
import { buildObservableDispositions } from './observableDispositions.js';

export const EXTRACTION_RUN_TYPES = Object.freeze({
  INITIAL: 'initial',
  RETRY: 'retry',
  REFRESH: 'refresh',
  RERUN_AI: 'rerun_ai',
  LEGACY_BASELINE: 'legacy_baseline'
});

const RUN_TYPE_BY_JOB = Object.freeze({
  [THREAT_LIBRARY_JOB_MODES.ANALYZE]: EXTRACTION_RUN_TYPES.INITIAL,
  [THREAT_LIBRARY_JOB_MODES.RETRY]: EXTRACTION_RUN_TYPES.RETRY,
  [THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION]: EXTRACTION_RUN_TYPES.REFRESH,
  [THREAT_LIBRARY_JOB_MODES.RERUN_AI]: EXTRACTION_RUN_TYPES.RERUN_AI
});

const FIRST_PASS_RUN_TYPES = new Set([EXTRACTION_RUN_TYPES.INITIAL, EXTRACTION_RUN_TYPES.RETRY]);

/** Insert batch size for the ledger child tables. */
const INSERT_CHUNK = 500;

export function runTypeForJob(jobType) {
  return RUN_TYPE_BY_JOB[jobType] || EXTRACTION_RUN_TYPES.INITIAL;
}

/**
 * Stable content hash of a document's blocks (ids, types, text, table cells).
 * Annotations added by later contracts on `meta` do not move it.
 * @param {object|null|undefined} document
 */
export function documentContentHash(document) {
  const blocks = Array.isArray(document?.blocks) ? document.blocks : null;
  if (!blocks) return null;
  const h = crypto.createHash('sha256');
  for (const b of blocks) {
    h.update(`${b.id}\0${b.type}\0${b.text || ''}\0`);
    if (b.table) h.update(JSON.stringify({ headers: b.table.headers || null, rows: b.table.rows || [] }));
  }
  return h.digest('hex');
}

/**
 * The per-identity snapshot of one run (pure).
 * @param {object[]} candidates persisted rows (with evidence)
 */
export function buildRunCandidateRows(candidates) {
  return (candidates || []).map((c) => {
    const ev = c?.evidence && typeof c.evidence === 'object' ? c.evidence : {};
    const decision = c?.membership_decision || ev.membership_decision || null;
    return {
      candidate_type: c.candidate_type,
      normalized_value: c.normalized_value,
      original_value: c.original_value ? String(c.original_value).slice(0, 500) : null,
      is_member: isReportIndicatorMember(c),
      is_linked_member: isLinkedSourceIndicatorMember(c),
      membership_outcome: decision?.outcome || null,
      reason_code: decision?.reason_code || c.policy_decision || ev.policy_decision || null,
      rule_id: decision?.rule_id || null,
      assessment: c.assessment || null,
      role: c.role || null,
      source_assertion: c.source_assertion || ev.source_assertion || null,
      review_status: c.review_status || null,
      matched_ioc_id: c.matched_ioc_id ?? null,
      has_original_document_occurrence: c.has_original_document_occurrence !== false,
      decision: decision || {
        policy_decision: c.policy_decision || ev.policy_decision || null,
        decision_source: c.decision_source || ev.decision_source || null
      }
    };
  });
}

/** Bounded, non-duplicating diagnostics stored with a run (no document content). */
export function compactRunDiagnostics(diagnostics) {
  const d = diagnostics && typeof diagnostics === 'object' ? diagnostics : {};
  const q = d.quality && typeof d.quality === 'object' ? d.quality : null;
  const t = d.explicit_tables && typeof d.explicit_tables === 'object' ? d.explicit_tables : null;
  return {
    extraction_version: d.extraction_version || null,
    scope_engine: d.scope_engine
      ? {
          engine: d.scope_engine.engine || null,
          has_authoritative_scope: d.scope_engine.has_authoritative_scope === true,
          fallback: d.scope_engine.fallback === true || undefined
        }
      : null,
    quality: q
      ? {
          status: q.status || null,
          counts: q.counts || null,
          codes: [...new Set((q.warnings || []).map((w) => w.code))].slice(0, 40)
        }
      : null,
    explicit_tables: t
      ? { rows_seen: t.rows_seen ?? 0, rows_valid: t.rows_valid ?? 0, rows_rejected: t.rows_rejected ?? 0, inconsistent: t.inconsistent === true }
      : null
  };
}

async function insertInChunks(db, table, columns, rows, jsonColumns = new Set()) {
  for (let i = 0; i < rows.length; i += INSERT_CHUNK) {
    const chunk = rows.slice(i, i + INSERT_CHUNK);
    const params = [];
    const tuples = chunk.map((row) => {
      const slots = columns.map((col) => {
        params.push(jsonColumns.has(col) ? JSON.stringify(row[col] ?? null) : row[col] ?? null);
        return `$${params.length}${jsonColumns.has(col) ? '::jsonb' : ''}`;
      });
      return `(${slots.join(',')})`;
    });
    await db.query(`INSERT INTO ${table} (${columns.join(',')}) VALUES ${tuples.join(',')}`, params);
  }
}

/**
 * Record one completed extraction, in the caller's transaction. Idempotent per
 * (report, job, run type): a repeated completion of the same job writes nothing.
 *
 * @param {{ query: Function }} db
 * @param {{
 *   report: { id: number },
 *   jobId?: number|null,
 *   jobType?: string,
 *   runType?: string,
 *   document?: object|null,
 *   candidates: object[],
 *   tokenLog?: object[],
 *   blocks?: object[],
 *   diagnostics?: object|null,
 *   aiProvenance?: object|null,
 *   operationalStatus?: 'completed'|'degraded',
 *   sourceSha256?: string|null,
 *   startedAt?: number|Date|null
 * }} input
 * @returns {Promise<{ run_id: number|null, recorded: boolean, is_first_pass: boolean }>}
 */
export async function recordExtractionRun(db, input) {
  const runType = input.runType || runTypeForJob(input.jobType);
  const bundle = extractionContractBundle();
  const fingerprint = contractFingerprint(bundle);
  const documentHash = documentContentHash(input.document);
  const idempotencyKey = input.jobId != null ? `job:${input.jobId}:${runType}` : `doc:${runType}:${fingerprint}:${documentHash || 'none'}`;

  const { rows: earlier } = await db.query(
    'SELECT 1 FROM threat_report_extraction_runs WHERE report_id = $1 LIMIT 1',
    [input.report.id]
  );
  const isFirstPass = earlier.length === 0 && FIRST_PASS_RUN_TYPES.has(runType);

  const candidateRows = buildRunCandidateRows(input.candidates);
  const dispositions = buildObservableDispositions({
    candidates: input.candidates,
    tokenLog: input.tokenLog || [],
    blocks: input.blocks || []
  });
  const dropped = Array.isArray(input.document?.meta?.source_accounting?.dropped_regions)
    ? input.document.meta.source_accounting.dropped_regions
    : [];
  const counts = {
    candidates: candidateRows.length,
    members: candidateRows.filter((c) => c.is_member).length,
    linked_members: candidateRows.filter((c) => c.is_linked_member).length,
    needs_review: candidateRows.filter((c) => c.membership_outcome === 'needs_review').length,
    dispositions: dispositions.counts,
    dispositions_truncated: dispositions.truncated,
    dropped_regions: dropped.length,
    dropped_significant_observables: dropped.filter((r) => r.significant).reduce((n, r) => n + (r.observable_count || 0), 0)
  };

  const { rows: inserted } = await db.query(
    `INSERT INTO threat_report_extraction_runs (
       report_id, job_id, run_type, is_first_pass, operational_status, contract_bundle, contract_fingerprint,
       document_hash, source_sha256, ai_provenance, counts, diagnostics, idempotency_key, started_at
     ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14)
     ON CONFLICT (report_id, idempotency_key) DO NOTHING
     RETURNING id`,
    [
      input.report.id,
      input.jobId ?? null,
      runType,
      isFirstPass,
      input.operationalStatus || 'completed',
      JSON.stringify(bundle),
      fingerprint,
      documentHash,
      input.sourceSha256 || null,
      JSON.stringify(input.aiProvenance || {}),
      JSON.stringify(counts),
      JSON.stringify(compactRunDiagnostics(input.diagnostics)),
      idempotencyKey,
      input.startedAt ? new Date(input.startedAt) : null
    ]
  );
  if (!inserted.length) return { run_id: null, recorded: false, is_first_pass: false };
  const runId = inserted[0].id;

  await insertInChunks(
    db,
    'threat_report_extraction_run_candidates',
    ['run_id', 'candidate_type', 'normalized_value', 'original_value', 'is_member', 'is_linked_member', 'membership_outcome',
      'reason_code', 'rule_id', 'assessment', 'role', 'source_assertion', 'review_status', 'matched_ioc_id',
      'has_original_document_occurrence', 'decision'],
    candidateRows.map((r) => ({ ...r, run_id: runId })),
    new Set(['decision'])
  );
  await insertInChunks(
    db,
    'threat_report_observable_dispositions',
    ['run_id', 'source_kind', 'observable_type', 'raw_value', 'normalized_value', 'disposition', 'reason_code', 'rule_id',
      'block_id', 'section_path', 'table_index', 'row_index', 'column_index', 'char_start', 'char_end', 'excerpt'],
    dispositions.rows.map((r) => ({ ...r, run_id: runId })),
    new Set(['section_path'])
  );
  await insertInChunks(
    db,
    'threat_report_dropped_regions',
    ['run_id', 'region_kind', 'reason', 'locator', 'text_chars', 'observable_count', 'observable_types', 'sample_observables', 'significant'],
    dropped.map((r) => ({
      run_id: runId,
      region_kind: String(r.region_kind || 'unknown').slice(0, 80),
      reason: String(r.reason || 'unknown').slice(0, 120),
      locator: r.locator ? String(r.locator).slice(0, 300) : null,
      text_chars: Number(r.text_chars) || 0,
      observable_count: Number(r.observable_count) || 0,
      observable_types: r.observable_types || {},
      sample_observables: Array.isArray(r.sample_observables) ? r.sample_observables.slice(0, 20) : [],
      significant: r.significant === true
    })),
    new Set(['observable_types', 'sample_observables'])
  );
  return { run_id: runId, recorded: true, is_first_pass: isFirstPass };
}

/**
 * Label a report's current state as its earliest available baseline. Never a
 * first-pass record: the true first-pass identities of these reports are gone.
 * Idempotent per report.
 * @param {{ query: Function }} db
 * @param {{ report: object, candidates: object[] }} input
 */
export async function recordLegacyBaseline(db, { report, candidates }) {
  return recordExtractionRun(db, {
    report,
    runType: EXTRACTION_RUN_TYPES.LEGACY_BASELINE,
    jobId: null,
    document: null,
    candidates,
    diagnostics: { extraction_version: report.analysis_progress?.candidate_extraction_version || null },
    aiProvenance: {},
    startedAt: null
  });
}

/** @param {{ query: Function }} db @param {number} reportId */
export async function listExtractionRuns(db, reportId) {
  const { rows } = await db.query(
    `SELECT public_id, job_id, run_type, is_first_pass, operational_status, contract_fingerprint, contract_bundle,
            document_hash, ai_provenance, counts, diagnostics, started_at, completed_at
       FROM threat_report_extraction_runs WHERE report_id = $1 ORDER BY id`,
    [reportId]
  );
  return rows;
}

/**
 * Exact-identity comparison of a report's reference run with its current review
 * set. Reference = the first-pass run when one exists, else the legacy baseline
 * (labelled as such: it is not a first pass).
 * @param {{ query: Function }} db
 * @param {number} reportId
 */
export async function compareReferenceRunToCurrent(db, reportId) {
  const { rows: runs } = await db.query(
    `SELECT id, public_id, run_type, is_first_pass, contract_fingerprint, completed_at
       FROM threat_report_extraction_runs
      WHERE report_id = $1
      ORDER BY is_first_pass DESC, id ASC
      LIMIT 1`,
    [reportId]
  );
  if (!runs.length) return { reference: null, available: false };
  const reference = runs[0];
  const { rows: diff } = await db.query(
    `SELECT COALESCE(r.candidate_type, c.candidate_type) AS candidate_type,
            COALESCE(r.normalized_value, c.normalized_value) AS normalized_value,
            COALESCE(r.is_member, FALSE) AS reference_member,
            r.review_status AS reference_review_status,
            r.candidate_type IS NOT NULL AS in_reference,
            c.id IS NOT NULL AS in_current,
            c.review_status AS current_review_status,
            c.has_original_document_occurrence AS current_in_document
       FROM (SELECT * FROM threat_report_extraction_run_candidates WHERE run_id = $1) r
       FULL OUTER JOIN (SELECT * FROM threat_report_candidates WHERE report_id = $2) c
         ON c.candidate_type = r.candidate_type AND c.normalized_value = r.normalized_value`,
    [reference.id, reportId]
  );
  const approved = new Set(['approved', 'created_ioc']);
  const isApproved = (row) => approved.has(String(row.current_review_status || ''));
  const out = { reference: { ...reference, id: undefined }, available: true, kept: 0, added_after_reference: [], lost_from_reference: [], not_approved: [] };
  for (const row of diff) {
    const id = { candidate_type: row.candidate_type, normalized_value: row.normalized_value };
    if (row.reference_member && isApproved(row)) out.kept += 1;
    else if (row.reference_member && row.in_current) out.not_approved.push(id);
    else if (row.reference_member) out.lost_from_reference.push(id);
    else if (isApproved(row)) out.added_after_reference.push({ ...id, from_linked_source: row.current_in_document === false });
  }
  return out;
}
