/**
 * Persistence helpers for Additional IOC Sources.
 */

import { canonicalizeReportUrl } from '../importIdentity.js';
import { reportIndicatorMembershipSql } from '../indicatorMembership.js';
import { IOC_SOURCE_LIFECYCLE } from './constants.js';
import { transitionPatch } from './sourceState.js';

export function publicIocSource(row, files = null) {
  if (!row) return null;
  const preview = row.preview && typeof row.preview === 'object' ? row.preview : {};
  const estimated = preview.estimated !== false && row.inspection_status !== 'succeeded';
  return {
    id: row.public_id,
    report_id: row.report_public_id || undefined,
    original_url: row.original_url,
    canonical_url: row.canonical_url,
    source_type: row.source_type,
    discovery_method: row.discovery_method,
    discovery_evidence: row.discovery_evidence || {},
    lifecycle_status: row.lifecycle_status,
    inspection_status: row.inspection_status,
    extraction_status: row.extraction_status,
    content_hash: row.content_hash || null,
    repo_revision: row.repo_revision || null,
    last_fetched_at: row.last_fetched_at || null,
    preview: {
      ...preview,
      estimated: estimated || preview.estimated === true
    },
    error_code: row.error_code || null,
    error_detail: row.error_detail || null,
    approved_by: row.approved_by || null,
    approved_at: row.approved_at || null,
    dismissed_by: row.dismissed_by || null,
    dismissed_at: row.dismissed_at || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    files: Array.isArray(files)
      ? files.map((f) => ({
          id: f.public_id,
          path: f.path,
          download_url: f.download_url || null,
          size_bytes: f.size_bytes ?? null,
          content_sha: f.content_sha || null,
          content_type: f.content_type || null,
          selected: f.selected !== false,
          parse_status: f.parse_status,
          estimated_raw_count: f.estimated_raw_count ?? null,
          estimated_unique_count: f.estimated_unique_count ?? null,
          type_breakdown: f.type_breakdown || {},
          error_detail: f.error_detail || null
        }))
      : undefined
  };
}

export async function listIocSourcesForReport(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT s.* FROM threat_report_ioc_sources s
     WHERE s.report_id = $1
     ORDER BY s.created_at ASC, s.id ASC`,
    [reportId]
  );
  return rows;
}

export async function getIocSourceByPublicId(pool, publicId) {
  const { rows } = await pool.query(
    `SELECT s.*, r.public_id AS report_public_id
     FROM threat_report_ioc_sources s
     JOIN threat_reports r ON r.id = s.report_id
     WHERE s.public_id = $1::uuid AND r.deleted_at IS NULL`,
    [publicId]
  );
  return rows[0] || null;
}

export async function listSourceFiles(pool, sourceId) {
  const { rows } = await pool.query(
    `SELECT * FROM threat_report_ioc_source_files WHERE source_id = $1 ORDER BY path ASC`,
    [sourceId]
  );
  return rows;
}

export async function createManualIocSource(pool, reportId, { url, requestedBy }) {
  const canonical = canonicalizeReportUrl(url);
  if (!canonical) {
    const err = new Error('Invalid URL');
    err.code = 'invalid_url';
    throw err;
  }
  const { rows } = await pool.query(
    `INSERT INTO threat_report_ioc_sources (
       report_id, original_url, canonical_url, source_type, discovery_method,
       discovery_evidence, lifecycle_status
     ) VALUES ($1,$2,$3,'unknown','manual',$4::jsonb,$5)
     ON CONFLICT (report_id, canonical_url) DO UPDATE SET
       updated_at = NOW()
     RETURNING *`,
    [
      reportId,
      String(url).trim(),
      canonical,
      JSON.stringify({ discovery_method: 'manual', added_by: requestedBy || null }),
      IOC_SOURCE_LIFECYCLE.DISCOVERED
    ]
  );
  return rows[0];
}

export async function applySourcePatch(pool, sourceId, patch) {
  if (!patch || patch.idempotent) {
    const { rows } = await pool.query(`SELECT * FROM threat_report_ioc_sources WHERE id = $1`, [sourceId]);
    return rows[0] || null;
  }
  const { rows } = await pool.query(
    `UPDATE threat_report_ioc_sources SET
       lifecycle_status = COALESCE($2, lifecycle_status),
       inspection_status = COALESCE($3, inspection_status),
       extraction_status = COALESCE($4, extraction_status),
       source_type = COALESCE($5, source_type),
       preview = COALESCE($6::jsonb, preview),
       content_hash = COALESCE($7, content_hash),
       repo_revision = COALESCE($8, repo_revision),
       last_fetched_at = COALESCE($9, last_fetched_at),
       error_code = $10,
       error_detail = $11,
       approved_by = COALESCE($12::uuid, approved_by),
       approved_at = COALESCE($13, approved_at),
       dismissed_by = COALESCE($14::uuid, dismissed_by),
       dismissed_at = COALESCE($15, dismissed_at),
       updated_at = NOW()
     WHERE id = $1
     RETURNING *`,
    [
      sourceId,
      patch.lifecycle_status ?? null,
      patch.inspection_status ?? null,
      patch.extraction_status ?? null,
      patch.source_type ?? null,
      patch.preview != null ? JSON.stringify(patch.preview) : null,
      patch.content_hash ?? null,
      patch.repo_revision ?? null,
      patch.last_fetched_at ?? null,
      patch.error_code !== undefined ? patch.error_code : null,
      patch.error_detail !== undefined ? patch.error_detail : null,
      patch.approved_by ?? null,
      patch.approved_at ?? null,
      patch.dismissed_by ?? null,
      patch.dismissed_at ?? null
    ]
  );
  return rows[0] || null;
}

export async function transitionSource(pool, source, action, extra = {}) {
  const patch = transitionPatch(source, action, extra);
  return applySourcePatch(pool, source.id, patch);
}

export async function replaceSourceFiles(pool, sourceId, files) {
  await pool.query(`DELETE FROM threat_report_ioc_source_files WHERE source_id = $1`, [sourceId]);
  const inserted = [];
  for (const f of files || []) {
    const { rows } = await pool.query(
      `INSERT INTO threat_report_ioc_source_files (
         source_id, path, download_url, size_bytes, content_sha, content_type,
         selected, parse_status, estimated_raw_count, estimated_unique_count,
         type_breakdown, error_detail
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)
       RETURNING *`,
      [
        sourceId,
        f.path,
        f.download_url || null,
        f.size_bytes ?? null,
        f.content_sha || null,
        f.content_type || null,
        f.selected !== false,
        f.parse_status || 'pending',
        f.estimated_raw_count ?? null,
        f.estimated_unique_count ?? null,
        JSON.stringify(f.type_breakdown || {}),
        f.error_detail || null
      ]
    );
    inserted.push(rows[0]);
  }
  return inserted;
}

export async function setSelectedSourceFiles(pool, sourceId, selectedPaths) {
  if (!Array.isArray(selectedPaths)) return listSourceFiles(pool, sourceId);
  const set = new Set(selectedPaths.map((p) => String(p)));
  await pool.query(
    `UPDATE threat_report_ioc_source_files
     SET selected = (path = ANY($2::text[])), updated_at = NOW()
     WHERE source_id = $1`,
    [sourceId, [...set]]
  );
  return listSourceFiles(pool, sourceId);
}

export async function summarizeIocSources(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE lifecycle_status = 'discovered')::int AS discovered_pending,
       COUNT(*) FILTER (WHERE lifecycle_status IN ('attached','extracting','extracted'))::int AS attached,
       COUNT(*) FILTER (WHERE lifecycle_status = 'extracted')::int AS extracted,
       COUNT(*) FILTER (WHERE lifecycle_status IN ('failed','blocked','unsupported'))::int AS failed
     FROM threat_report_ioc_sources
     WHERE report_id = $1 AND lifecycle_status <> 'dismissed'`,
    [reportId]
  );
  return rows[0] || { total: 0, discovered_pending: 0, attached: 0, extracted: 0, failed: 0 };
}

/**
 * Identity keys for original-document Indicator members (for overlap preview).
 */
export async function loadOriginalIndicatorKeys(pool, reportId) {
  const where = reportIndicatorMembershipSql('c');
  const { rows } = await pool.query(
    `SELECT candidate_type, normalized_value FROM threat_report_candidates c
     WHERE c.report_id = $1 AND ${where}`,
    [reportId]
  );
  return new Set(rows.map((r) => `${r.candidate_type}\0${r.normalized_value}`));
}

export async function loadOtherLinkedKeys(pool, reportId, excludeSourceId) {
  const { rows } = await pool.query(
    `SELECT DISTINCT c.candidate_type, c.normalized_value
     FROM threat_report_candidate_source_links l
     JOIN threat_report_candidates c ON c.id = l.candidate_id
     WHERE c.report_id = $1 AND l.source_id <> $2`,
    [reportId, excludeSourceId]
  );
  return new Set(rows.map((r) => `${r.candidate_type}\0${r.normalized_value}`));
}

export async function loadCandidateSourceLinks(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT l.candidate_id, l.source_id, l.source_assertion, s.public_id AS source_public_id,
            s.source_type, s.canonical_url, s.lifecycle_status
     FROM threat_report_candidate_source_links l
     JOIN threat_report_ioc_sources s ON s.id = l.source_id
     JOIN threat_report_candidates c ON c.id = l.candidate_id
     WHERE c.report_id = $1`,
    [reportId]
  );
  const byCandidate = new Map();
  for (const r of rows) {
    const list = byCandidate.get(r.candidate_id) || [];
    list.push({
      id: r.source_public_id,
      source_type: r.source_type,
      canonical_url: r.canonical_url,
      source_assertion: r.source_assertion,
      lifecycle_status: r.lifecycle_status
    });
    byCandidate.set(r.candidate_id, list);
  }
  return byCandidate;
}
