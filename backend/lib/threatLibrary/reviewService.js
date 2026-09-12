/**
 * Analyst review + explicit IOC creation from Threat Library candidates.
 */

import { createManualIoc } from '../manualIocCreate.js';
import { getThreatLibraryIocSourceId, getReportById, updateReportStatus } from './store.js';
import { CONFIDENCE_POLICY } from './constants.js';

/**
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 * @param {{
 *   candidateIds?: number[],
 *   action: 'approve'|'context_only'|'ignore'|'create_iocs'|'approve_high_confidence_malicious',
 *   user?: object,
 *   audit?: object
 * }} opts
 */
export async function applyCandidateReviewActions(pool, reportId, opts) {
  const action = opts.action;
  const report = await getReportById(pool, reportId);
  if (!report) return { ok: false, status: 404, error: 'Report not found' };

  let ids = Array.isArray(opts.candidateIds) ? opts.candidateIds.map(Number).filter((n) => n > 0) : [];

  if (action === 'approve_high_confidence_malicious') {
    const { rows } = await pool.query(
      `SELECT id FROM threat_report_candidates
       WHERE report_id = $1
         AND assessment = 'malicious'
         AND confidence IS NOT NULL AND confidence >= $2
         AND review_status = 'pending'`,
      [reportId, CONFIDENCE_POLICY.AUTO_APPROVE_SUGGEST]
    );
    ids = rows.map((r) => Number(r.id));
  }

  if (!ids.length && action !== 'finalize') {
    return { ok: false, status: 400, error: 'No candidates selected' };
  }

  if (action === 'approve' || action === 'approve_high_confidence_malicious') {
    await pool.query(
      `UPDATE threat_report_candidates SET review_status = 'approved', updated_at = NOW()
       WHERE report_id = $1 AND id = ANY($2::bigint[])`,
      [reportId, ids]
    );
  } else if (action === 'context_only') {
    await pool.query(
      `UPDATE threat_report_candidates
       SET review_status = 'context_only', assessment = 'context_only', match_state = 'context_only', updated_at = NOW()
       WHERE report_id = $1 AND id = ANY($2::bigint[])`,
      [reportId, ids]
    );
  } else if (action === 'ignore') {
    await pool.query(
      `UPDATE threat_report_candidates SET review_status = 'ignored', updated_at = NOW()
       WHERE report_id = $1 AND id = ANY($2::bigint[])`,
      [reportId, ids]
    );
  } else if (action === 'create_iocs') {
    const sourceId = await getThreatLibraryIocSourceId(pool);
    if (!sourceId) return { ok: false, status: 500, error: 'Threat Library IOC source missing' };

    const { rows: candidates } = await pool.query(
      `SELECT * FROM threat_report_candidates
       WHERE report_id = $1 AND id = ANY($2::bigint[])
         AND matched_ioc_id IS NULL
         AND assessment IN ('malicious','suspicious')
         AND candidate_type = ANY($3::text[])`,
      [reportId, ids, ['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']]
    );

    const created = [];
    const errors = [];
    for (const c of candidates) {
      const result = await createManualIoc(
        pool,
        {
          observable: c.normalized_value,
          source_id: sourceId,
          confidence: c.confidence != null && c.confidence >= 0.85 ? 'high' : 'medium',
          note: `Threat Library report ${report.public_id}: ${c.role || 'unknown'} (${c.assessment})`,
          source_url: report.source_url || null
        },
        { user: opts.user, audit: opts.audit }
      );
      if (result.status >= 200 && result.status < 300 && result.body?.id) {
        await pool.query(
          `UPDATE threat_report_candidates
           SET matched_ioc_id = $2,
               matched_ioc_observable_type = $3,
               match_state = 'existing',
               review_status = 'created_ioc',
               updated_at = NOW()
           WHERE id = $1`,
          [c.id, result.body.id, result.body.observable_type || c.candidate_type]
        );
        // Link relationships that pointed at this candidate to the IOC
        await pool.query(
          `UPDATE threat_relationships SET object_ioc_id = $2
           WHERE report_id = $3 AND object_candidate_id = $1 AND object_ioc_id IS NULL`,
          [c.id, result.body.id, reportId]
        );
        await pool.query(
          `UPDATE threat_relationships SET subject_ioc_id = $2
           WHERE report_id = $3 AND subject_candidate_id = $1 AND subject_ioc_id IS NULL`,
          [c.id, result.body.id, reportId]
        );
        created.push({ candidate_id: c.id, ioc_id: result.body.id, public_id: result.body.public_id });
      } else {
        errors.push({
          candidate_id: c.id,
          message: result.body?.message || `create failed (${result.status})`
        });
      }
    }
    return { ok: true, created, errors };
  } else {
    return { ok: false, status: 400, error: 'Unknown action' };
  }

  return { ok: true, updated: ids.length };
}

/**
 * Finalize report after review (marks ready/imported without creating IOCs implicitly).
 */
export async function finalizeReport(pool, reportId) {
  const report = await getReportById(pool, reportId);
  if (!report) return { ok: false, status: 404, error: 'Report not found' };
  await updateReportStatus(pool, reportId, {
    import_status: 'ready',
    analysis_status: 'ready',
    finalize: true
  });
  return { ok: true };
}
