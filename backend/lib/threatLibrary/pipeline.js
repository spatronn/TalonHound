/**
 * Threat Library analysis pipeline (URL/PDF).
 * Stages are independently statused; AI retries resume without re-fetching.
 */

import crypto from 'node:crypto';
import { ingestUrlToCanonicalDocument } from './urlIngest.js';
import { pdfToCanonicalDocument } from './pdfIngest.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { bulkMatchCandidates } from './iocMatch.js';
import { analyzeThreatDocument } from './ai/providers.js';
import { AI_FAILURE_CODES, AI_FAILURE_MESSAGES } from './ai/timeouts.js';
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
  getReportById,
  ensureAnalysisRun,
  loadCompletedChunkResult,
  saveAnalysisChunkResult,
  markAnalysisChunkFailed,
  countReportCandidates,
  isAnalysisCancelRequested
} from './store.js';
import { createServiceLogger } from '../appLogger.js';

const log = createServiceLogger('threat-library');

function hasUsableDocument(doc) {
  return Boolean(doc && Array.isArray(doc.blocks) && doc.blocks.length > 0);
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, pdfBuffer?: Buffer, sourceUrl?: string, resumeAnalysis?: boolean }} ctx
 */
export async function runAnalysisPipeline(pool, ctx) {
  const report = await getReportById(pool, ctx.reportId);
  if (!report) throw Object.assign(new Error('Report not found'), { code: 'not_found' });

  const abort = new AbortController();
  const analysisStartedAt = Date.now();

  const setStage = async (stage, extra = {}) => {
    await updateJob(pool, ctx.jobId, {
      status: 'running',
      stage,
      progress: { stage, ...extra }
    });
    await updateReportStatus(pool, report.id, {
      analysis_status: stage === 'candidates' ? 'extracting' : stage,
      import_status: 'processing',
      analysis_progress: { stage, ...extra },
      clear_failure: true
    });
  };

  try {
    let document = report.canonical_document;
    const resumePreferred = ctx.resumeAnalysis === true || ctx.jobType === 'retry' || hasUsableDocument(document);

    // --- Fetch / extract (skip when reusable artifacts exist) ---
    if (!hasUsableDocument(document)) {
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
            requires_ocr: pdf.requiresOcr,
            source_metadata: { page_count: pdf.pageCount },
            text_excerpt: pdf.requiresOcr
              ? 'No extractable text — OCR required'
              : (document.blocks || []).slice(0, 3).map((b) => b.text).join('\n').slice(0, 1000)
          });
        }
        if (pdf.requiresOcr) {
          await updateReportStatus(pool, report.id, {
            title: document.title,
            canonical_document: document,
            analysis_status: 'failed',
            import_status: 'failed',
            failure_stage: 'extracting',
            failure_code: 'requires_ocr',
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
    } else {
      log.info('reusing canonical document', {
        reportId: report.id,
        blocks: document.blocks?.length || 0,
        resume: resumePreferred
      });
      await updateJob(pool, ctx.jobId, {
        status: 'running',
        stage: 'extracting',
        progress: { stage: 'extracting', reused: true, blocks: document.blocks?.length || 0 }
      });
    }

    // --- Deterministic candidates (reuse when present on retry) ---
    let candidates;
    const existingCount = await countReportCandidates(pool, report.id);
    if (resumePreferred && existingCount > 0) {
      const { rows } = await pool.query(
        `SELECT candidate_type, original_value, normalized_value, assessment, role, confidence,
                evidence_text, section, block_id, page_number, match_state, matched_ioc_id,
                matched_ioc_observable_type, review_status
         FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`,
        [report.id]
      );
      candidates = rows.map((r) => ({
        ...r,
        is_ioc: !['cve', 'attack_technique'].includes(String(r.candidate_type))
      }));
      log.info('reusing candidates', { reportId: report.id, count: candidates.length });
    } else {
      await setStage('candidates');
      candidates = extractCandidatesFromDocument(document);
      await replaceCandidates(pool, report.id, candidates);
      log.info('candidate count', { reportId: report.id, count: candidates.length });
    }

    // --- AI semantics (chunked, checkpointed) ---
    await setStage('analyzing', {
      analysis_chunks_total: null,
      analysis_chunks_completed: 0
    });
    await updateReportStatus(pool, report.id, { clear_cancel: true });

    const aiSettings = await getAiSettings(pool);
    const { resolveAiTimeoutPolicy } = await import('./ai/timeouts.js');
    const timeoutPolicy = resolveAiTimeoutPolicy(aiSettings);
    log.info('AI analysis starting', {
      reportId: report.id,
      provider: aiSettings?.provider,
      model: aiSettings?.model,
      base_url: aiSettings?.base_url,
      timeout_policy: timeoutPolicy,
      resume: resumePreferred,
      candidate_count: candidates.length
    });
    const analysisRunId = await ensureAnalysisRun(pool, report.id, {
      // Keep same run on retry so completed chunks are reused
      forceNew: false
    });
    // If previous run fully failed with no completed chunks, still reuse run id — OK.
    // Start a new run only when explicitly requested via ctx.newAnalysisRun
    const runId = ctx.newAnalysisRun ? await ensureAnalysisRun(pool, report.id, { forceNew: true }) : analysisRunId;

    let aiValue = null;
    try {
      const ai = await analyzeThreatDocument(
        aiSettings,
        { document, candidates },
        {
          analysisStartedAt,
          signal: abort.signal,
          shouldCancel: async () => isAnalysisCancelRequested(pool, report.id),
          loadCompletedChunk: async (chunkKey) =>
            loadCompletedChunkResult(pool, report.id, runId, chunkKey),
          saveChunkResult: async (chunk, result, meta) =>
            saveAnalysisChunkResult(pool, report.id, runId, chunk, result, meta || {}),
          markChunkFailed: async (chunk, code, message, meta) =>
            markAnalysisChunkFailed(pool, report.id, runId, chunk, code, message, meta || {}),
          onProgress: async (progress) => {
            if (await isAnalysisCancelRequested(pool, report.id)) {
              abort.abort();
            }
            await updateJob(pool, ctx.jobId, {
              status: 'running',
              stage: 'analyzing',
              progress
            });
            await updateReportStatus(pool, report.id, {
              analysis_status: 'analyzing',
              import_status: 'processing',
              analysis_progress: progress,
              analysis_run_id: runId
            });
          }
        }
      );
      if (!ai.ok) {
        throw Object.assign(new Error(ai.error || 'AI validation failed'), {
          code: AI_FAILURE_CODES.AI_VALIDATION,
          details: ai.details
        });
      }
      aiValue = ai.value;
      log.info('AI analysis completed', {
        reportId: report.id,
        chunks: ai.meta?.chunks_total
      });
    } catch (aiErr) {
      const code = aiErr.code || 'ai_failed';
      if (code !== AI_FAILURE_CODES.JOB_CANCELLED) {
        // best-effort mark current chunk failed is handled inside analyze when save fails
      }
      const message =
        AI_FAILURE_MESSAGES[code] && aiErr.message === AI_FAILURE_MESSAGES[code]
          ? aiErr.message
          : aiErr.message || AI_FAILURE_MESSAGES[code] || 'AI analysis failed';

      if (code === AI_FAILURE_CODES.JOB_CANCELLED) {
        await updateReportStatus(pool, report.id, {
          analysis_status: 'failed',
          import_status: 'failed',
          failure_stage: 'analyzing',
          failure_code: code,
          failure_reason: message,
          canonical_document: document,
          clear_cancel: true
        });
        await updateJob(pool, ctx.jobId, {
          status: 'cancelled',
          stage: 'analyzing',
          error_message: message
        });
        return { ok: false, code, error: message };
      }

      await updateReportStatus(pool, report.id, {
        analysis_status: 'failed',
        import_status: 'failed',
        failure_stage: 'analyzing',
        failure_code: code,
        failure_reason: message,
        failure_details: {
          issues: Array.isArray(aiErr.details) ? aiErr.details.slice(0, 30) : [],
          schema_version: aiErr.schema_version || null,
          rejected: Array.isArray(aiErr.rejected) ? aiErr.rejected.slice(0, 30) : []
        },
        canonical_document: document
      });
      await updateJob(pool, ctx.jobId, {
        status: 'failed',
        stage: 'analyzing',
        error_message: message,
        progress: {
          stage: 'analyzing',
          failure_code: code,
          issues: Array.isArray(aiErr.details) ? aiErr.details.slice(0, 10) : []
        }
      });
      return { ok: false, code, error: message };
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
    matched.candidates = matched.candidates.map((c) => ({
      ...c,
      match_state: deriveMatchState({
        assessment: c.assessment,
        confidence: c.confidence,
        matchedIocId: c.matched_ioc_id,
        valid: c.assessment !== 'invalid'
      })
    }));
    const summary = {
      total: matched.candidates.length,
      existing: 0,
      new: 0,
      context_only: 0,
      needs_review: 0,
      invalid: 0
    };
    for (const c of matched.candidates) {
      if (summary[c.match_state] != null) summary[c.match_state] += 1;
    }

    const savedCandidates = await replaceCandidates(pool, report.id, matched.candidates);

    // Clear prior entity links/relationships for this report before re-applying (idempotent finalize)
    await pool.query(`DELETE FROM threat_report_entities WHERE report_id = $1`, [report.id]);
    await pool.query(`DELETE FROM threat_relationships WHERE report_id = $1`, [report.id]);

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

    const candByKey = new Map(
      savedCandidates.map((c) => [`${c.candidate_type}:${c.normalized_value}`, c])
    );
    const relRows = [];
    for (const r of aiValue.relationships || []) {
      const subject = resolveRef(r.subject_kind, r.subject_ref, entityByRef, candByKey);
      const object = resolveRef(r.object_kind, r.object_ref, entityByRef, candByKey);
      if (!subject || !object) continue;
      relRows.push({
        portable_id: `relationship--${crypto.randomUUID()}`,
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
      import_status: 'review_required',
      analysis_progress: {
        stage: 'review_required',
        completed: true
      },
      clear_failure: true,
      clear_cancel: true
    });

    // Fix progress meta from analyze if present on ai object - we stored value only
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
      failure_code: err.code || null,
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
    let c = candByKey.get(ref);
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
