/**
 * Threat Library persistence helpers.
 */

import crypto from 'node:crypto';
import { normalizeTlp, normalizeEntityName, IOC_SOURCE_NAME } from './constants.js';
import { deleteReportArtifacts } from './artifactStore.js';

export async function getAiSettings(pool) {
  const { rows } = await pool.query(`SELECT * FROM threat_library_ai_settings WHERE id = 1`);
  return rows[0] || null;
}

export async function updateAiSettings(pool, patch, userPublicId) {
  const current = await getAiSettings(pool);
  const enabled = patch.enabled != null ? Boolean(patch.enabled) : current?.enabled === true;
  const provider = patch.provider != null ? String(patch.provider) : current?.provider || 'openai_compatible';
  const baseUrl = patch.base_url !== undefined ? (patch.base_url ? String(patch.base_url).trim() : null) : current?.base_url;
  const model = patch.model !== undefined ? (patch.model ? String(patch.model).trim() : null) : current?.model;
  const maxInput = patch.max_input_chars != null ? Number(patch.max_input_chars) : current?.max_input_chars || 120000;
  const privacyAck = patch.privacy_ack === true;
  const hasKeyPatch = Object.prototype.hasOwnProperty.call(patch, 'api_key');
  const nextKey = hasKeyPatch
    ? (patch.api_key === '' || patch.api_key == null ? null : String(patch.api_key))
    : null;

  // Prefer explicit multi-timeout fields; legacy timeout_ms updates inactivity.
  const connectionTimeoutMs =
    patch.connection_timeout_ms != null ? Number(patch.connection_timeout_ms) : current?.connection_timeout_ms;
  const firstTokenTimeoutMs =
    patch.first_token_timeout_ms != null ? Number(patch.first_token_timeout_ms) : current?.first_token_timeout_ms;
  let inactivityTimeoutMs =
    patch.inactivity_timeout_ms != null ? Number(patch.inactivity_timeout_ms) : current?.inactivity_timeout_ms;
  const totalTimeoutMs =
    patch.total_analysis_timeout_ms != null
      ? Number(patch.total_analysis_timeout_ms)
      : current?.total_analysis_timeout_ms;
  if (patch.timeout_ms != null && patch.inactivity_timeout_ms == null) {
    inactivityTimeoutMs = Number(patch.timeout_ms);
  }
  const legacyTimeoutMs = inactivityTimeoutMs ?? current?.timeout_ms ?? 60000;

  const { rows } = await pool.query(
    `UPDATE threat_library_ai_settings SET
       enabled = $1,
       provider = $2,
       base_url = $3,
       model = $4,
       timeout_ms = $5,
       max_input_chars = $6,
       api_key = CASE WHEN $7 THEN $8 ELSE api_key END,
       privacy_ack_at = CASE WHEN $9 THEN NOW() ELSE privacy_ack_at END,
       privacy_ack_by = CASE WHEN $9 THEN $10::uuid ELSE privacy_ack_by END,
       connection_timeout_ms = COALESCE($11, connection_timeout_ms),
       first_token_timeout_ms = COALESCE($12, first_token_timeout_ms),
       inactivity_timeout_ms = COALESCE($13, inactivity_timeout_ms),
       total_analysis_timeout_ms = COALESCE($14, total_analysis_timeout_ms),
       updated_at = NOW(),
       updated_by = $10::uuid
     WHERE id = 1
     RETURNING *`,
    [
      enabled,
      provider,
      baseUrl,
      model,
      legacyTimeoutMs,
      maxInput,
      hasKeyPatch,
      nextKey,
      privacyAck,
      userPublicId || null,
      Number.isFinite(connectionTimeoutMs) ? connectionTimeoutMs : null,
      Number.isFinite(firstTokenTimeoutMs) ? firstTokenTimeoutMs : null,
      Number.isFinite(inactivityTimeoutMs) ? inactivityTimeoutMs : null,
      Number.isFinite(totalTimeoutMs) ? totalTimeoutMs : null
    ]
  );
  return rows[0];
}

export async function clearAiApiKey(pool, userPublicId) {
  const { rows } = await pool.query(
    `UPDATE threat_library_ai_settings SET api_key = NULL, updated_at = NOW(), updated_by = $1::uuid
     WHERE id = 1 RETURNING *`,
    [userPublicId || null]
  );
  return rows[0];
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} fields
 */
export async function createThreatReport(pool, fields) {
  const { rows } = await pool.query(
    `INSERT INTO threat_reports (
       title, source_type, source_name, source_url, source_file_name, source_sha256,
       published_at, language, tlp, confidence, report_type, summary,
       import_status, analysis_status, portable_id, bundle_id, created_by
     ) VALUES (
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::uuid
     ) RETURNING *`,
    [
      fields.title || 'Untitled report',
      fields.source_type,
      fields.source_name || null,
      fields.source_url || null,
      fields.source_file_name || null,
      fields.source_sha256 || null,
      fields.published_at || null,
      fields.language || null,
      normalizeTlp(fields.tlp || 'clear'),
      fields.confidence ?? null,
      fields.report_type || null,
      fields.summary || null,
      fields.import_status || 'processing',
      fields.analysis_status || 'pending',
      fields.portable_id || `report--${crypto.randomUUID()}`,
      fields.bundle_id || null,
      fields.created_by || null
    ]
  );
  return rows[0];
}

export async function getReportByPublicId(pool, publicId) {
  const { rows } = await pool.query(
    `SELECT * FROM threat_reports WHERE public_id = $1::uuid AND deleted_at IS NULL`,
    [publicId]
  );
  return rows[0] || null;
}

export async function getReportById(pool, id) {
  const { rows } = await pool.query(
    `SELECT * FROM threat_reports WHERE id = $1 AND deleted_at IS NULL`,
    [id]
  );
  return rows[0] || null;
}

export async function listThreatReports(pool, { limit = 50, offset = 0 } = {}) {
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const off = Math.max(Number(offset) || 0, 0);
  const { rows } = await pool.query(
    `SELECT r.*,
       (SELECT COUNT(*)::int FROM threat_report_candidates c WHERE c.report_id = r.id) AS indicator_count,
       (SELECT COUNT(*)::int FROM threat_report_candidates c WHERE c.report_id = r.id AND c.matched_ioc_id IS NOT NULL) AS matched_count,
       (SELECT COUNT(*)::int FROM threat_report_entities e WHERE e.report_id = r.id) AS entity_count
     FROM threat_reports r
     WHERE r.deleted_at IS NULL
     ORDER BY r.created_at DESC
     LIMIT $1 OFFSET $2`,
    [lim, off]
  );
  const { rows: countRows } = await pool.query(
    `SELECT COUNT(*)::int AS total FROM threat_reports WHERE deleted_at IS NULL`
  );
  return { items: rows, total: countRows[0]?.total || 0 };
}

export async function updateReportStatus(pool, reportId, patch) {
  const { rows } = await pool.query(
    `UPDATE threat_reports SET
       title = COALESCE($2, title),
       language = COALESCE($3, language),
       tlp = COALESCE($4, tlp),
       confidence = COALESCE($5, confidence),
       report_type = COALESCE($6, report_type),
       summary = COALESCE($7, summary),
       import_status = COALESCE($8, import_status),
       analysis_status = COALESCE($9, analysis_status),
       failure_stage = CASE WHEN $22 THEN NULL ELSE COALESCE($10, failure_stage) END,
       failure_reason = CASE WHEN $22 THEN NULL ELSE COALESCE($11, failure_reason) END,
       candidate_summary = COALESCE($12, candidate_summary),
       canonical_document = COALESCE($13, canonical_document),
       ai_result = COALESCE($14, ai_result),
       published_at = COALESCE($15, published_at),
       source_name = COALESCE($16, source_name),
       analysis_progress = COALESCE($18, analysis_progress),
       failure_code = CASE WHEN $22 THEN NULL ELSE COALESCE($19, failure_code) END,
       analysis_run_id = COALESCE($20::uuid, analysis_run_id),
       cancel_requested_at = CASE
         WHEN $21 = true THEN NOW()
         WHEN $21 = false THEN NULL
         ELSE cancel_requested_at
       END,
       failure_details = CASE
         WHEN $22 THEN '{}'::jsonb
         WHEN $23::jsonb IS NOT NULL THEN $23::jsonb
         ELSE failure_details
       END,
       updated_at = NOW(),
       finalized_at = CASE WHEN $17 THEN NOW() ELSE finalized_at END
     WHERE id = $1
     RETURNING *`,
    [
      reportId,
      patch.title ?? null,
      patch.language ?? null,
      patch.tlp ? normalizeTlp(patch.tlp) : null,
      patch.confidence ?? null,
      patch.report_type ?? null,
      patch.summary ?? null,
      patch.import_status ?? null,
      patch.analysis_status ?? null,
      patch.failure_stage ?? null,
      patch.failure_reason ?? null,
      patch.candidate_summary ?? null,
      patch.canonical_document ?? null,
      patch.ai_result ?? null,
      patch.published_at ?? null,
      patch.source_name ?? null,
      patch.finalize === true,
      patch.analysis_progress ?? null,
      patch.failure_code ?? null,
      patch.analysis_run_id ?? null,
      patch.clear_cancel === true ? false : patch.request_cancel === true ? true : null,
      patch.clear_failure === true,
      patch.failure_details != null ? JSON.stringify(patch.failure_details) : null
    ]
  );
  return rows[0];
}

export async function requestAnalysisCancel(pool, reportId) {
  const { rows } = await pool.query(
    `UPDATE threat_reports
     SET cancel_requested_at = NOW(), updated_at = NOW()
     WHERE id = $1 AND deleted_at IS NULL
     RETURNING *`,
    [reportId]
  );
  return rows[0] || null;
}

export async function isAnalysisCancelRequested(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT cancel_requested_at FROM threat_reports WHERE id = $1`,
    [reportId]
  );
  return Boolean(rows[0]?.cancel_requested_at);
}

export async function ensureAnalysisRun(pool, reportId, { forceNew = false } = {}) {
  const report = await getReportById(pool, reportId);
  if (!report) return null;
  if (!forceNew && report.analysis_run_id) return report.analysis_run_id;
  const runId = crypto.randomUUID();
  await pool.query(
    `UPDATE threat_reports SET analysis_run_id = $2::uuid, cancel_requested_at = NULL, updated_at = NOW() WHERE id = $1`,
    [reportId, runId]
  );
  return runId;
}

export async function loadCompletedChunkResult(pool, reportId, analysisRunId, chunkKey) {
  const { rows } = await pool.query(
    `SELECT result, schema_version FROM threat_library_analysis_chunks
     WHERE report_id = $1 AND analysis_run_id = $2::uuid AND chunk_key = $3 AND status = 'completed'
     LIMIT 1`,
    [reportId, analysisRunId, chunkKey]
  );
  const row = rows[0];
  if (!row?.result) return null;
  return { ok: true, value: row.result, schema_version: row.schema_version || null };
}

export async function saveAnalysisChunkResult(pool, reportId, analysisRunId, chunk, result, meta = {}) {
  await pool.query(
    `INSERT INTO threat_library_analysis_chunks (
       report_id, analysis_run_id, chunk_index, chunk_key, status, block_ids, result,
       schema_version, rejected_items, attempt_count, started_at, completed_at, updated_at
     ) VALUES (
       $1, $2::uuid, $3, $4, 'completed', $5::jsonb, $6::jsonb,
       $7, $8::jsonb, 1, NOW(), NOW(), NOW()
     )
     ON CONFLICT (report_id, analysis_run_id, chunk_key) DO UPDATE SET
       status = 'completed',
       result = EXCLUDED.result,
       block_ids = EXCLUDED.block_ids,
       schema_version = EXCLUDED.schema_version,
       rejected_items = EXCLUDED.rejected_items,
       validation_details = '[]'::jsonb,
       raw_output_sample = NULL,
       error_code = NULL,
       error_message = NULL,
       attempt_count = threat_library_analysis_chunks.attempt_count + 1,
       completed_at = NOW(),
       updated_at = NOW()`,
    [
      reportId,
      analysisRunId,
      chunk.chunk_index,
      chunk.chunk_key,
      JSON.stringify(chunk.block_ids || []),
      JSON.stringify(result),
      meta.schema_version || null,
      JSON.stringify(meta.rejected_items || [])
    ]
  );
}

export async function markAnalysisChunkFailed(pool, reportId, analysisRunId, chunk, code, message, meta = {}) {
  await pool.query(
    `INSERT INTO threat_library_analysis_chunks (
       report_id, analysis_run_id, chunk_index, chunk_key, status, block_ids,
       error_code, error_message, schema_version, validation_details, raw_output_sample, rejected_items,
       attempt_count, started_at, updated_at
     ) VALUES (
       $1, $2::uuid, $3, $4, 'failed', $5::jsonb, $6, $7, $8, $9::jsonb, $10, $11::jsonb, 1, NOW(), NOW()
     )
     ON CONFLICT (report_id, analysis_run_id, chunk_key) DO UPDATE SET
       status = 'failed',
       error_code = EXCLUDED.error_code,
       error_message = EXCLUDED.error_message,
       schema_version = EXCLUDED.schema_version,
       validation_details = EXCLUDED.validation_details,
       raw_output_sample = EXCLUDED.raw_output_sample,
       rejected_items = EXCLUDED.rejected_items,
       attempt_count = threat_library_analysis_chunks.attempt_count + 1,
       updated_at = NOW()`,
    [
      reportId,
      analysisRunId,
      chunk.chunk_index,
      chunk.chunk_key,
      JSON.stringify(chunk.block_ids || []),
      code || null,
      message || null,
      meta.schema_version || null,
      JSON.stringify(meta.validation_details || []),
      meta.raw_output_sample || null,
      JSON.stringify(meta.rejected_items || [])
    ]
  );
}

export async function countReportCandidates(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n FROM threat_report_candidates WHERE report_id = $1`,
    [reportId]
  );
  return rows[0]?.n || 0;
}

export async function insertArtifact(pool, reportId, artifact) {
  const { rows } = await pool.query(
    `INSERT INTO threat_report_artifacts (
       report_id, artifact_type, file_name, mime_type, size_bytes, sha256,
       storage_key, source_metadata, text_excerpt, requires_ocr, fetched_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)
     RETURNING id, public_id, artifact_type, file_name, mime_type, size_bytes, sha256, requires_ocr, fetched_at, created_at`,
    [
      reportId,
      artifact.artifact_type,
      artifact.file_name || null,
      artifact.mime_type || null,
      artifact.size_bytes ?? null,
      artifact.sha256 || null,
      artifact.storage_key || null,
      JSON.stringify(artifact.source_metadata || {}),
      artifact.text_excerpt || null,
      artifact.requires_ocr === true,
      artifact.fetched_at || null
    ]
  );
  return rows[0];
}

/**
 * Replace candidates for a report (idempotent retry).
 */
export async function replaceCandidates(pool, reportId, candidates) {
  await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
  const inserted = [];
  for (const c of candidates) {
    const { rows } = await pool.query(
      `INSERT INTO threat_report_candidates (
         report_id, portable_id, candidate_type, original_value, normalized_value,
         assessment, role, confidence, evidence_text, section, block_id, page_number,
         review_status, match_state, matched_ioc_id, matched_ioc_observable_type
       ) VALUES (
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
       )
       ON CONFLICT (report_id, candidate_type, normalized_value) DO UPDATE SET
         assessment = EXCLUDED.assessment,
         role = EXCLUDED.role,
         confidence = EXCLUDED.confidence,
         evidence_text = COALESCE(EXCLUDED.evidence_text, threat_report_candidates.evidence_text),
         match_state = EXCLUDED.match_state,
         matched_ioc_id = EXCLUDED.matched_ioc_id,
         matched_ioc_observable_type = EXCLUDED.matched_ioc_observable_type,
         updated_at = NOW()
       RETURNING *`,
      [
        reportId,
        c.portable_id || `indicator--${crypto.randomUUID()}`,
        c.candidate_type,
        c.original_value,
        c.normalized_value,
        c.assessment || 'unknown',
        c.role || 'unknown',
        c.confidence ?? null,
        c.evidence_text || null,
        c.section || null,
        c.block_id || null,
        c.page_number ?? null,
        c.review_status || 'pending',
        c.match_state || 'new',
        c.matched_ioc_id ?? null,
        c.matched_ioc_observable_type || null
      ]
    );
    inserted.push(rows[0]);
  }
  return inserted;
}

export async function upsertEntity(pool, entity) {
  const normalized = normalizeEntityName(entity.name);
  const { rows } = await pool.query(
    `INSERT INTO threat_entities (portable_id, entity_type, name, normalized_name, description)
     VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (entity_type, normalized_name) DO UPDATE SET
       description = COALESCE(EXCLUDED.description, threat_entities.description),
       updated_at = NOW()
     RETURNING *`,
    [
      entity.portable_id || `entity--${crypto.randomUUID()}`,
      entity.entity_type,
      entity.name,
      normalized,
      entity.description || null
    ]
  );
  const row = rows[0];
  for (const alias of entity.aliases || []) {
    const na = normalizeEntityName(alias);
    if (!na) continue;
    await pool.query(
      `INSERT INTO threat_entity_aliases (entity_id, alias, normalized_alias)
       VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
      [row.id, alias, na]
    );
  }
  return row;
}

export async function linkReportEntity(pool, reportId, entityId, meta = {}) {
  await pool.query(
    `INSERT INTO threat_report_entities (report_id, entity_id, confidence, evidence_text, block_id, section, page_number)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (report_id, entity_id) DO UPDATE SET
       confidence = COALESCE(EXCLUDED.confidence, threat_report_entities.confidence),
       evidence_text = COALESCE(EXCLUDED.evidence_text, threat_report_entities.evidence_text)`,
    [
      reportId,
      entityId,
      meta.confidence ?? null,
      meta.evidence_text || null,
      meta.block_id || null,
      meta.section || null,
      meta.page_number ?? null
    ]
  );
}

export async function replaceRelationships(pool, reportId, relationships) {
  await pool.query(`DELETE FROM threat_relationships WHERE report_id = $1`, [reportId]);
  for (const r of relationships) {
    await pool.query(
      `INSERT INTO threat_relationships (
         portable_id, report_id, subject_kind, subject_entity_id, subject_candidate_id, subject_ioc_id, subject_portable_ref,
         relationship_type, object_kind, object_entity_id, object_candidate_id, object_ioc_id, object_portable_ref,
         role, confidence, evidence_text, section, page_number, block_id
       ) VALUES (
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
       )`,
      [
        r.portable_id || `relationship--${crypto.randomUUID()}`,
        reportId,
        r.subject_kind,
        r.subject_entity_id ?? null,
        r.subject_candidate_id ?? null,
        r.subject_ioc_id ?? null,
        r.subject_portable_ref || null,
        r.relationship_type,
        r.object_kind,
        r.object_entity_id ?? null,
        r.object_candidate_id ?? null,
        r.object_ioc_id ?? null,
        r.object_portable_ref || null,
        r.role || null,
        r.confidence ?? null,
        r.evidence_text || null,
        r.section || null,
        r.page_number ?? null,
        r.block_id || null
      ]
    );
  }
}

export async function createJob(pool, { reportId, jobType, requestedBy, bullmqJobId }) {
  const { rows } = await pool.query(
    `INSERT INTO threat_library_jobs (report_id, job_type, status, stage, requested_by, bullmq_job_id)
     VALUES ($1,$2,'queued','queued',$3::uuid,$4)
     RETURNING *`,
    [reportId, jobType || 'analyze', requestedBy || null, bullmqJobId || null]
  );
  return rows[0];
}

export async function updateJob(pool, jobId, patch) {
  const { rows } = await pool.query(
    `UPDATE threat_library_jobs SET
       status = COALESCE($2, status),
       stage = COALESCE($3, stage),
       progress = COALESCE($4, progress),
       error_message = $5,
       bullmq_job_id = COALESCE($6, bullmq_job_id),
       started_at = CASE WHEN $2 = 'running' AND started_at IS NULL THEN NOW() ELSE started_at END,
       finished_at = CASE WHEN $2 IN ('completed','failed','cancelled') THEN NOW() ELSE finished_at END
     WHERE id = $1
     RETURNING *`,
    [
      jobId,
      patch.status ?? null,
      patch.stage ?? null,
      patch.progress ?? null,
      patch.error_message ?? null,
      patch.bullmq_job_id ?? null
    ]
  );
  return rows[0];
}

export async function loadReportSnapshot(pool, reportId) {
  const report = await getReportById(pool, reportId);
  if (!report) return null;
  const { rows: candidates } = await pool.query(
    `SELECT * FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`,
    [reportId]
  );
  const { rows: entityLinks } = await pool.query(
    `SELECT e.*, re.confidence AS link_confidence, re.evidence_text AS link_evidence
     FROM threat_report_entities re
     JOIN threat_entities e ON e.id = re.entity_id
     WHERE re.report_id = $1
     ORDER BY e.entity_type, e.name`,
    [reportId]
  );
  const { rows: relationships } = await pool.query(
    `SELECT * FROM threat_relationships WHERE report_id = $1 ORDER BY id`,
    [reportId]
  );
  const { rows: artifacts } = await pool.query(
    `SELECT id, public_id, artifact_type, file_name, mime_type, size_bytes, sha256, requires_ocr, fetched_at, created_at, source_metadata
     FROM threat_report_artifacts WHERE report_id = $1 ORDER BY id`,
    [reportId]
  );
  const { rows: jobs } = await pool.query(
    `SELECT id, public_id, job_type, status, stage, progress, error_message, created_at, started_at, finished_at
     FROM threat_library_jobs WHERE report_id = $1 ORDER BY id DESC LIMIT 5`,
    [reportId]
  );
  return { report, candidates, entities: entityLinks, relationships, artifacts, jobs };
}

/**
 * Soft-delete report + hard-delete owned TL rows via CASCADE; never deletes ioc_items.
 */
export async function deleteThreatReport(pool, reportId) {
  await pool.query(
    `UPDATE threat_reports SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1`,
    [reportId]
  );
  // Hard-delete children to free unique constraints; IOCs remain
  await pool.query(`DELETE FROM threat_relationships WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_report_entities WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_report_artifacts WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_library_jobs WHERE report_id = $1`, [reportId]);
  await deleteReportArtifacts(reportId);
}

export async function getThreatLibraryIocSourceId(pool) {
  const { rows } = await pool.query(
    `SELECT id FROM ioc_sources WHERE name = $1 AND archived_at IS NULL LIMIT 1`,
    [IOC_SOURCE_NAME]
  );
  return rows[0]?.id ? Number(rows[0].id) : null;
}

/**
 * IOC Threat Context for IOC detail page.
 */
export async function getIocThreatContext(pool, iocId) {
  const { rows: candidates } = await pool.query(
    `SELECT c.*, r.public_id AS report_public_id, r.title AS report_title,
            r.published_at, r.tlp, r.source_name, r.source_url, r.source_type
     FROM threat_report_candidates c
     JOIN threat_reports r ON r.id = c.report_id
     WHERE c.matched_ioc_id = $1 AND r.deleted_at IS NULL
       AND r.import_status IN ('ready','imported','review_required')
     ORDER BY r.published_at DESC NULLS LAST, r.created_at DESC`,
    [iocId]
  );

  const { rows: rels } = await pool.query(
    `SELECT tr.*, r.public_id AS report_public_id, r.title AS report_title, r.tlp,
            se.name AS subject_entity_name, se.entity_type AS subject_entity_type,
            oe.name AS object_entity_name, oe.entity_type AS object_entity_type
     FROM threat_relationships tr
     JOIN threat_reports r ON r.id = tr.report_id
     LEFT JOIN threat_entities se ON se.id = tr.subject_entity_id
     LEFT JOIN threat_entities oe ON oe.id = tr.object_entity_id
     WHERE r.deleted_at IS NULL
       AND (tr.subject_ioc_id = $1 OR tr.object_ioc_id = $1
            OR tr.subject_candidate_id IN (SELECT id FROM threat_report_candidates WHERE matched_ioc_id = $1)
            OR tr.object_candidate_id IN (SELECT id FROM threat_report_candidates WHERE matched_ioc_id = $1))
     ORDER BY tr.created_at DESC
     LIMIT 100`,
    [iocId]
  );

  return { claims: candidates, relationships: rels };
}
