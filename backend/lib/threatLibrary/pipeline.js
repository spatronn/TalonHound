/**
 * Threat Library analysis pipeline (URL/PDF).
 * Stages are independently statused; AI retries resume without re-fetching.
 */

import crypto from 'node:crypto';
import { ingestUrlToCanonicalDocument } from './urlIngest.js';
import { pdfToCanonicalDocument } from './pdfIngest.js';
import { extractCandidatesFromDocument, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { applyEvidencePolicy } from './evidencePolicy.js';
import { hostnameFromUrl } from './candidateTyping.js';
import { bulkMatchCandidates } from './iocMatch.js';
import { analyzeThreatDocument } from './ai/providers.js';
import { AI_FAILURE_CODES, AI_FAILURE_MESSAGES } from './ai/timeouts.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './ai/contract.js';
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
            failure_code: 'pdf_ocr_required',
            failure_reason:
              'The PDF appears to contain only scanned images or no extractable text layer. OCR is not enabled in V1.'
          });
          await updateJob(pool, ctx.jobId, {
            status: 'failed',
            stage: 'extracting',
            error_message: 'pdf_ocr_required'
          });
          return { ok: false, code: 'pdf_ocr_required' };
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

    // --- Deterministic candidates (refresh when extraction contract changes) ---
    let candidates;
    const existingCount = await countReportCandidates(pool, report.id);
    const priorExtractionVersion = report.analysis_progress?.candidate_extraction_version || null;
    const extractionChanged = priorExtractionVersion !== THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION;
    const shouldReuseCandidates =
      resumePreferred && existingCount > 0 && !extractionChanged && !ctx.refreshCandidates;

    if (shouldReuseCandidates) {
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
      // Ensure source provenance is on the document for zone/source marking
      let sourceUrl = report.source_url || document.meta?.source_url || null;
      let sourceHost = document.meta?.source_host || null;
      if (!sourceHost && sourceUrl) {
        try {
          sourceHost = hostnameFromUrl(sourceUrl);
        } catch {
          sourceHost = null;
        }
      }
      document = {
        ...document,
        meta: {
          ...(document.meta || {}),
          source_url: sourceUrl,
          source_host: sourceHost,
          candidate_extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
        }
      };
      candidates = extractCandidatesFromDocument(document, { sourceUrl });
      await replaceCandidates(pool, report.id, candidates);
      log.info('candidate count', {
        reportId: report.id,
        count: candidates.length,
        extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
        refreshed: extractionChanged || Boolean(ctx.refreshCandidates)
      });
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
    // New run when extraction/typing contract changed or caller requests reset
    const runId =
      ctx.newAnalysisRun || extractionChanged || ctx.refreshCandidates
        ? await ensureAnalysisRun(pool, report.id, { forceNew: true })
        : analysisRunId;

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

    // Merge AI candidate updates onto deterministic set, then enforce evidence policy
    const byKey = new Map(candidates.map((c) => [`${c.candidate_type}\0${c.normalized_value}`, c]));
    for (const u of aiValue.candidate_updates || []) {
      const key = `${u.candidate_type}\0${u.normalized_value}`;
      const existing = byKey.get(key);
      if (!existing) continue;
      applyEvidencePolicy(existing, {
        assessment: u.assessment,
        role: u.role || existing.role,
        confidence: u.confidence ?? existing.confidence
      });
      if (u.evidence_text) existing.evidence_text = u.evidence_text;
      if (u.section) existing.section = u.section;
      if (u.evidence_block_ids?.[0]) existing.block_id = u.evidence_block_ids[0];
    }
    candidates = [...byKey.values()].map((c) => applyEvidencePolicy(c));

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
        completed: true,
        candidate_extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
        schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
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
    const stage = resolvePipelineFailureStage(err);
    const failureDetails = {
      ...(err.fetchMeta && typeof err.fetchMeta === 'object' ? { fetch: err.fetchMeta } : {}),
      ...(err.extraction && typeof err.extraction === 'object' ? { extraction: err.extraction } : {})
    };
    // Persist a url_fetch diagnostic row when fetch happened but extraction failed (no raw HTML body).
    if (err.fetchMeta && report?.source_type === 'url') {
      try {
        await insertArtifact(pool, report.id, {
          artifact_type: 'url_fetch',
          mime_type: err.fetchMeta.content_type || 'text/html',
          size_bytes: err.fetchMeta.fetched_bytes || null,
          source_metadata: {
            ...err.fetchMeta,
            failure_code: err.code || null,
            extraction: err.extraction || null
          },
          text_excerpt: null,
          fetched_at: new Date().toISOString()
        });
      } catch {
        /* non-fatal */
      }
    }
    await updateReportStatus(pool, ctx.reportId, {
      analysis_status: 'failed',
      import_status: 'failed',
      failure_stage: stage,
      failure_code: err.code || null,
      failure_reason: err.message || 'Pipeline failed',
      failure_details: Object.keys(failureDetails).length ? failureDetails : undefined
    });
    await updateJob(pool, ctx.jobId, {
      status: 'failed',
      stage,
      error_message: err.message || 'Pipeline failed',
      progress: { stage, failure_code: err.code || null, ...failureDetails }
    });
    log.warn('pipeline failed', { reportId: ctx.reportId, stage: err.code || stage, error: err.message });
    return { ok: false, error: err.message, code: err.code };
  }
}

const FETCH_FAILURE_CODES = new Set([
  'invalid_url',
  'destination_blocked',
  'dns_lookup_failed',
  'timeout',
  'response_too_large',
  'redirect_invalid',
  'redirect_limit',
  'redirect_blocked',
  'fetch_http_error'
]);

const EXTRACT_FAILURE_CODES = new Set([
  'empty_document',
  'document_empty_after_extraction',
  'document_below_quality_threshold',
  'source_verification_required',
  'source_blocked',
  'source_access_denied',
  'article_not_found',
  'html_parse_failed',
  'unsupported_content_type',
  'pdf_via_url_unsupported',
  'requires_ocr',
  'pdf_ocr_required',
  'pdf_password_required',
  'pdf_parse_failed',
  'pdf_invalid',
  'pdf_empty_document',
  'missing_pdf'
]);

function resolvePipelineFailureStage(err) {
  const code = String(err?.code || '');
  if (FETCH_FAILURE_CODES.has(code)) return 'fetching';
  if (EXTRACT_FAILURE_CODES.has(code)) return 'extracting';
  if (code.startsWith('ai_') || code === 'ai_validation') return 'analyzing';
  return 'failed';
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
