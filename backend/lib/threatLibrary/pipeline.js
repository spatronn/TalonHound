/**
 * Threat Library analysis pipeline (URL/PDF).
 * Stages are independently statused; retries are idempotent.
 */

import { ingestUrlToCanonicalDocument } from './urlIngest.js';
import { pdfToCanonicalDocument } from './pdfIngest.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { bulkMatchCandidates } from './iocMatch.js';
import { analyzeThreatDocument } from './ai/providers.js';
import { normalizeTlp, deriveMatchState, normalizeEntityName } from './constants.js';
import { storeArtifactBuffer } from './artifactStore.js';
import {
  getAiSettings,
  updateReportStatus,
  insertArtifact,
  replaceCandidates,
  upsertEntity,
  linkReportEntity,
  replaceRelationships,
  updateJob,
  getReportById
} from './store.js';
import { createServiceLogger } from '../appLogger.js';

const log = createServiceLogger('threat-library');

/**
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, pdfBuffer?: Buffer, sourceUrl?: string }} ctx
 */
export async function runAnalysisPipeline(pool, ctx) {
  const report = await getReportById(pool, ctx.reportId);
  if (!report) throw Object.assign(new Error('Report not found'), { code: 'not_found' });

  const setStage = async (stage, extra = {}) => {
    await updateJob(pool, ctx.jobId, {
      status: 'running',
      stage,
      progress: { stage, ...extra }
    });
    await updateReportStatus(pool, report.id, {
      analysis_status: stage === 'candidates' ? 'extracting' : stage,
      import_status: 'processing',
      failure_stage: null,
      failure_reason: null
    });
  };

  try {
    let document = report.canonical_document;
    let requiresOcr = false;

    // --- Fetch / extract ---
    if (report.source_type === 'url') {
      await setStage('fetching');
      log.info('report import started', { reportId: report.id, sourceType: 'url' });
      const fetched = await ingestUrlToCanonicalDocument(ctx.sourceUrl || report.source_url);
      document = fetched.document;
      await insertArtifact(pool, report.id, {
        artifact_type: 'url_fetch',
        mime_type: fetched.contentType,
        size_bytes: fetched.fetchedBytes,
        source_metadata: { url: fetched.url, final_url: fetched.finalUrl },
        text_excerpt: (document.blocks || []).slice(0, 3).map((b) => b.text).join('\n').slice(0, 1000),
        fetched_at: new Date().toISOString()
      });
      await setStage('extracting', { blocks: document.blocks?.length || 0 });
      log.info('fetch completed', { reportId: report.id, blocks: document.blocks?.length || 0 });
    } else if (report.source_type === 'pdf') {
      await setStage('extracting');
      log.info('report import started', { reportId: report.id, sourceType: 'pdf' });
      let pdfBuffer = ctx.pdfBuffer || null;
      let existingArtifact = null;
      if (!pdfBuffer) {
        const { rows: arts } = await pool.query(
          `SELECT * FROM threat_report_artifacts
           WHERE report_id = $1 AND artifact_type = 'pdf_upload' AND storage_key IS NOT NULL
           ORDER BY id DESC LIMIT 1`,
          [report.id]
        );
        existingArtifact = arts[0] || null;
        if (!existingArtifact?.storage_key) {
          throw Object.assign(new Error('PDF buffer missing for analysis'), { code: 'missing_pdf' });
        }
        const { readArtifactBuffer } = await import('./artifactStore.js');
        pdfBuffer = await readArtifactBuffer(existingArtifact.storage_key);
      }
      const pdf = await pdfToCanonicalDocument(pdfBuffer, {
        fileName: report.source_file_name || existingArtifact?.file_name
      });
      document = pdf.document;
      requiresOcr = pdf.requiresOcr;
      if (!existingArtifact) {
        const stored = await storeArtifactBuffer(report.id, pdfBuffer, {
          fileName: pdf.fileName,
          ext: '.pdf'
        });
        await insertArtifact(pool, report.id, {
          artifact_type: 'pdf_upload',
          file_name: pdf.fileName,
          mime_type: 'application/pdf',
          size_bytes: stored.sizeBytes,
          sha256: stored.sha256,
          storage_key: stored.storageKey,
          requires_ocr: requiresOcr,
          source_metadata: { page_count: pdf.pageCount },
          text_excerpt: requiresOcr
            ? 'No extractable text — OCR required'
            : (document.blocks || []).slice(0, 3).map((b) => b.text).join('\n').slice(0, 1000)
        });
      } else if (requiresOcr) {
        await pool.query(
          `UPDATE threat_report_artifacts SET requires_ocr = true WHERE id = $1`,
          [existingArtifact.id]
        );
      }
      if (requiresOcr) {
        await updateReportStatus(pool, report.id, {
          title: document.title,
          canonical_document: document,
          analysis_status: 'failed',
          import_status: 'failed',
          failure_stage: 'extracting',
          failure_reason:
            'Scanned or image-only PDF: no usable text extracted. OCR is not enabled in V1.'
        });
        await updateJob(pool, ctx.jobId, {
          status: 'failed',
          stage: 'extracting',
          error_message: 'requires_ocr'
        });
        return { ok: false, code: 'requires_ocr' };
      }
      log.info('document extracted', { reportId: report.id, blocks: document.blocks?.length || 0 });
    } else {
      throw Object.assign(new Error('Unsupported source type for AI pipeline'), { code: 'bad_source' });
    }

    await insertArtifact(pool, report.id, {
      artifact_type: 'canonical_document',
      mime_type: 'application/json',
      source_metadata: { block_count: document.blocks?.length || 0 },
      text_excerpt: null
    });

    await updateReportStatus(pool, report.id, {
      title: document.title || report.title,
      language: document.language || report.language,
      canonical_document: document,
      analysis_status: 'extracting'
    });

    // --- Deterministic candidates ---
    await setStage('candidates');
    let candidates = extractCandidatesFromDocument(document);
    log.info('candidate count', { reportId: report.id, count: candidates.length });

    // --- AI semantics ---
    await setStage('analyzing');
    const aiSettings = await getAiSettings(pool);
    let aiValue = null;
    try {
      const ai = await analyzeThreatDocument(aiSettings, { document, candidates });
      if (!ai.ok) {
        throw Object.assign(new Error(ai.error || 'AI validation failed'), {
          code: 'ai_validation',
          details: ai.details
        });
      }
      aiValue = ai.value;
      log.info('AI analysis completed', { reportId: report.id });
    } catch (aiErr) {
      // Preserve extracted document; fail the job with actionable error
      await updateReportStatus(pool, report.id, {
        analysis_status: 'failed',
        import_status: 'failed',
        failure_stage: 'analyzing',
        failure_reason: aiErr.message || 'AI analysis failed',
        canonical_document: document
      });
      await updateJob(pool, ctx.jobId, {
        status: 'failed',
        stage: 'analyzing',
        error_message: aiErr.message || 'AI analysis failed'
      });
      return { ok: false, code: aiErr.code || 'ai_failed', error: aiErr.message };
    }

    // Merge AI candidate updates onto deterministic set
    const byKey = new Map(candidates.map((c) => [`${c.candidate_type}\0${c.normalized_value}`, c]));
    for (const u of aiValue.candidate_updates || []) {
      const key = `${u.candidate_type}\0${u.normalized_value}`;
      const existing = byKey.get(key);
      if (!existing) continue;
      existing.assessment = u.assessment;
      existing.role = u.role || existing.role;
      existing.confidence = u.confidence ?? existing.confidence;
      if (u.evidence_text) existing.evidence_text = u.evidence_text;
      if (u.section) existing.section = u.section;
      if (u.evidence_block_ids?.[0]) existing.block_id = u.evidence_block_ids[0];
    }
    candidates = [...byKey.values()];

    // --- Match local IOCs ---
    await setStage('matching');
    const matched = await bulkMatchCandidates(pool, candidates);
    // Re-derive match_state after AI assessments
    matched.candidates = matched.candidates.map((c) => ({
      ...c,
      match_state: deriveMatchState({
        assessment: c.assessment,
        confidence: c.confidence,
        matchedIocId: c.matched_ioc_id,
        valid: c.assessment !== 'invalid'
      })
    }));
    // Recount
    const summary = { total: matched.candidates.length, existing: 0, new: 0, context_only: 0, needs_review: 0, invalid: 0 };
    for (const c of matched.candidates) {
      if (summary[c.match_state] != null) summary[c.match_state] += 1;
    }

    const savedCandidates = await replaceCandidates(pool, report.id, matched.candidates);

    // Entities
    const entityByRef = new Map();
    for (const e of aiValue.entities || []) {
      const row = await upsertEntity(pool, e);
      await linkReportEntity(pool, report.id, row.id, {
        confidence: e.confidence,
        evidence_text: e.evidence_text,
        block_id: e.evidence_block_ids?.[0] || null
      });
      entityByRef.set(normalizeEntityName(e.name), row);
      entityByRef.set(e.name, row);
    }

    // Relationships
    const candByKey = new Map(
      savedCandidates.map((c) => [`${c.candidate_type}:${c.normalized_value}`, c])
    );
    const relRows = [];
    for (const r of aiValue.relationships || []) {
      const subject = resolveRef(r.subject_kind, r.subject_ref, entityByRef, candByKey);
      const object = resolveRef(r.object_kind, r.object_ref, entityByRef, candByKey);
      if (!subject || !object) continue;
      relRows.push({
        subject_kind: r.subject_kind,
        subject_entity_id: subject.entity_id || null,
        subject_candidate_id: subject.candidate_id || null,
        subject_ioc_id: subject.ioc_id || null,
        subject_portable_ref: subject.portable_ref || null,
        relationship_type: r.relationship_type,
        object_kind: r.object_kind,
        object_entity_id: object.entity_id || null,
        object_candidate_id: object.candidate_id || null,
        object_ioc_id: object.ioc_id || null,
        object_portable_ref: object.portable_ref || null,
        role: r.role || null,
        confidence: r.confidence ?? null,
        evidence_text: r.evidence_text || null,
        block_id: r.evidence_block_ids?.[0] || null
      });
    }
    await replaceRelationships(pool, report.id, relRows);

    await updateReportStatus(pool, report.id, {
      title: document.title || report.title,
      language: aiValue.language || document.language || report.language,
      tlp: normalizeTlp(aiValue.tlp || report.tlp),
      confidence: aiValue.confidence ?? null,
      report_type: aiValue.report_type || null,
      summary: aiValue.summary || null,
      candidate_summary: summary,
      ai_result: {
        entity_count: (aiValue.entities || []).length,
        relationship_count: relRows.length,
        candidate_update_count: (aiValue.candidate_updates || []).length
      },
      canonical_document: document,
      analysis_status: 'review_required',
      import_status: 'review_required'
    });

    await updateJob(pool, ctx.jobId, {
      status: 'completed',
      stage: 'review_required',
      progress: { stage: 'review_required', summary }
    });

    log.info('matching complete', { reportId: report.id, ...summary });
    return { ok: true, summary };
  } catch (err) {
    const stage = err.code === 'invalid_url' || err.code === 'destination_blocked' ? 'fetching' : 'failed';
    await updateReportStatus(pool, ctx.reportId, {
      analysis_status: 'failed',
      import_status: 'failed',
      failure_stage: stage,
      failure_reason: err.message || 'Pipeline failed'
    });
    await updateJob(pool, ctx.jobId, {
      status: 'failed',
      stage,
      error_message: err.message || 'Pipeline failed'
    });
    log.warn('pipeline failed', { reportId: ctx.reportId, stage: err.code || stage, error: err.message });
    return { ok: false, error: err.message, code: err.code };
  }
}

function resolveRef(kind, ref, entityByRef, candByKey) {
  if (kind === 'entity') {
    const e = entityByRef.get(normalizeEntityName(ref)) || entityByRef.get(ref);
    if (!e) return null;
    return { entity_id: e.id, portable_ref: e.portable_id };
  }
  if (kind === 'candidate') {
    // ref like "domain:evil.example" or bare value
    let c = candByKey.get(ref);
    if (!c && ref.includes(':')) {
      c = candByKey.get(ref);
    }
    if (!c) {
      for (const [k, v] of candByKey) {
        if (k.endsWith(`:${ref}`) || v.normalized_value === ref) {
          c = v;
          break;
        }
      }
    }
    if (!c) return null;
    return {
      candidate_id: c.id,
      ioc_id: c.matched_ioc_id || null,
      portable_ref: c.portable_id
    };
  }
  return null;
}
