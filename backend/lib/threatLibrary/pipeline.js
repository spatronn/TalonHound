/**
 * Threat Library analysis pipeline (URL/PDF).
 * Stages are independently statused; AI retries resume without re-fetching.
 */

import crypto from 'node:crypto';
import { ingestUrlToCanonicalDocument } from './urlIngest.js';
import { pdfToCanonicalDocument, THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } from './pdfIngest.js';
import { THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import {
  summarizeCandidateSet,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { analyzeThreatDocument } from './ai/providers.js';
import { AI_FAILURE_CODES, AI_FAILURE_MESSAGES } from './ai/timeouts.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './ai/contract.js';
import { normalizeEntityName } from './constants.js';
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
  loadReportCandidatesForAnalysis,
  isAnalysisCancelRequested
} from './store.js';
import { resolveEffectiveTlp } from './tlpPolicy.js';
import { buildEvidenceIndex, publisherTokens, validateRelationship } from './relationshipPolicy.js';
import { persistReportIntelligence } from './reportIntelligence.js';
import {
  applyPublicationDate,
  compactExtractionDiagnostics,
  extractReportCandidates,
  hasUsableDocument,
  isDocumentContractCurrent,
  loadStoredPdfArtifact,
  matchCandidateSet,
  mergeAiCandidateUpdates,
  rebuildDocumentFromRetainedSource
} from './extractionStages.js';
import { THREAT_LIBRARY_JOB_MODES } from './jobModes.js';
import { createServiceLogger } from '../appLogger.js';

// Deterministic stages live in extractionStages.js (shared with the
// AI-free extraction refresh); re-exported for existing callers.
export { isDocumentContractCurrent, compactExtractionDiagnostics, mergeAiCandidateUpdates };

const log = createServiceLogger('threat-library');

/**
 * Full URL/PDF analysis: fetch / extract → deterministic candidates → AI
 * semantics → merge → match → review_required. Runs for `analyze`, `retry`
 * and `rerun_ai` jobs; `refresh_extraction` never reaches this function
 * (jobRunner.js routes it to the AI-free extractionRefresh.js).
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, pdfBuffer?: Buffer, sourceUrl?: string, resumeAnalysis?: boolean, jobType?: string, newAnalysisRun?: boolean }} ctx
 * @param {{ analyzeThreatDocument?: Function }} [deps] provider seam (tests)
 */
export async function runAnalysisPipeline(pool, ctx, deps = {}) {
  if (ctx?.jobType === THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION) {
    // Defence in depth: the deterministic refresh must never enter the AI pipeline.
    throw Object.assign(new Error('refresh_extraction jobs never run the AI pipeline'), { code: 'invalid_job_mode' });
  }
  const analyze = deps.analyzeThreatDocument || analyzeThreatDocument;
  const report = await getReportById(pool, ctx.reportId);
  if (!report) throw Object.assign(new Error('Report not found'), { code: 'not_found' });

  const abort = new AbortController();
  const analysisStartedAt = Date.now();
  const progressCarry = {
    candidate_extraction_version:
      report.analysis_progress?.candidate_extraction_version ||
      report.canonical_document?.meta?.candidate_extraction_version ||
      null,
    extraction_diagnostics: report.analysis_progress?.extraction_diagnostics || null
  };

  const setStage = async (stage, extra = {}) => {
    const analysis_progress = mergeAnalysisProgress(progressCarry, { stage, ...extra });
    await updateJob(pool, ctx.jobId, {
      status: 'running',
      stage,
      progress: analysis_progress
    });
    await updateReportStatus(pool, report.id, {
      analysis_status: stage === 'candidates' ? 'extracting' : stage,
      import_status: 'processing',
      analysis_progress,
      clear_failure: true
    });
  };

  try {
    let document = report.canonical_document;
    /** Raw source HTML for this run (fetched or retained) — the publication-date extractor reads it. */
    let sourceHtml = null;
    const resumePreferred =
      ctx.resumeAnalysis === true ||
      ctx.jobType === THREAT_LIBRARY_JOB_MODES.RETRY ||
      ctx.jobType === THREAT_LIBRARY_JOB_MODES.RERUN_AI ||
      hasUsableDocument(document);
    const documentContractCurrent = isDocumentContractCurrent(report, document);
    let documentRebuilt = false;
    if (hasUsableDocument(document) && !documentContractCurrent) {
      log.info('canonical document contract outdated; re-extracting from stored artifact', {
        reportId: report.id,
        stored_extractor: document?.meta?.extractor || null,
        current_extractor:
          report.source_type === 'pdf' ? THREAT_LIBRARY_PDF_EXTRACTOR_VERSION : THREAT_LIBRARY_HTML_EXTRACTOR_VERSION
      });
      documentRebuilt = true;
    }

    // --- Fetch / extract (skip when reusable artifacts exist) ---
    if (!hasUsableDocument(document) || !documentContractCurrent) {
      if (report.source_type === 'url') {
        // Retained source HTML lets a contract change re-extract without touching the network.
        let reextracted = null;
        if (documentRebuilt) {
          try {
            reextracted = await rebuildDocumentFromRetainedSource(pool, report);
          } catch (err) {
            log.warn('retained HTML unusable; falling back to fetch', { reportId: report.id, error: err.message });
            reextracted = null;
          }
        }
        if (reextracted) {
          sourceHtml = reextracted.sourceHtml;
          await setStage('extracting');
          document = reextracted.document;
          log.info('document re-extracted from retained HTML', {
            reportId: report.id,
            blocks: document.blocks?.length || 0,
            extractor: document.meta?.extractor || null
          });
        } else {
          await setStage('fetching');
          log.info('report import started', { reportId: report.id, sourceType: 'url' });
          const fetched = await ingestUrlToCanonicalDocument(ctx.sourceUrl || report.source_url);
          document = fetched.document;
          sourceHtml = fetched.bodyText || null;
          let stored = null;
          if (fetched.bodyText) {
            try {
              stored = await storeArtifactBuffer(report.id, Buffer.from(fetched.bodyText, 'utf8'), {
                fileName: 'source.html',
                ext: '.html'
              });
            } catch (err) {
              log.warn('source HTML retention failed (non-fatal)', { reportId: report.id, error: err.message });
            }
          }
          await insertArtifact(pool, report.id, {
            artifact_type: 'url_fetch',
            file_name: stored ? 'source.html' : null,
            mime_type: fetched.contentType,
            size_bytes: fetched.fetchedBytes,
            sha256: stored?.sha256 || null,
            storage_key: stored?.storageKey || null,
            source_metadata: {
              url: fetched.url,
              final_url: fetched.finalUrl,
              http_status: fetched.httpStatus ?? null,
              extraction: fetched.extraction || null
            },
            text_excerpt: (document.blocks || []).slice(0, 3).map((b) => b.text).join('\n').slice(0, 1000),
            fetched_at: new Date().toISOString()
          });
          await setStage('extracting', { blocks: document.blocks?.length || 0 });
          log.info('fetch completed', { reportId: report.id, blocks: document.blocks?.length || 0 });
        }
      } else if (report.source_type === 'pdf') {
        await setStage('extracting');
        log.info('report import started', { reportId: report.id, sourceType: 'pdf' });
        let pdfBuffer = ctx.pdfBuffer || null;
        let existingArtifact = null;
        if (!pdfBuffer) {
          existingArtifact = await loadStoredPdfArtifact(pool, report.id);
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

    // --- Publication date (deterministic, provenance-ranked, never lifecycle) ---
    const publicationDate = await applyPublicationDate(pool, report, { document, sourceHtml });

    // --- Deterministic candidates (refresh when extraction contract changes) ---
    let candidates;
    let extractionDiagnostics = report.analysis_progress?.extraction_diagnostics || null;
    const existingCount = await countReportCandidates(pool, report.id);
    const reuse = decideCandidateReuse({
      priorExtractionVersion: report.analysis_progress?.candidate_extraction_version || null,
      documentRebuilt,
      existingCount,
      resumePreferred,
      refreshCandidates: Boolean(ctx.refreshCandidates)
    });
    const { extractionChanged, shouldReuseCandidates } = reuse;

    if (shouldReuseCandidates) {
      candidates = await loadReportCandidatesForAnalysis(pool, report.id);
      progressCarry.candidate_extraction_version =
        progressCarry.candidate_extraction_version || THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION;
      log.info('reusing candidates', {
        reportId: report.id,
        count: candidates.length,
        ...summarizeCandidateSet(candidates)
      });
    } else {
      await setStage('candidates');
      // Source provenance is stamped on the document for zone/source marking.
      const extracted = extractReportCandidates(report, document);
      document = extracted.document;
      candidates = extracted.candidates;
      extractionDiagnostics = extracted.diagnostics;
      await replaceCandidates(pool, report.id, candidates);
      progressCarry.candidate_extraction_version = THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION;
      progressCarry.extraction_diagnostics = compactExtractionDiagnostics(extractionDiagnostics);
      const tables = extracted.diagnostics?.explicit_tables || {};
      const typing = extracted.diagnostics?.type_resolution || {};
      log.info('candidate count', {
        reportId: report.id,
        count: candidates.length,
        extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
        refreshed: extractionChanged || Boolean(ctx.refreshCandidates),
        document_rebuilt: documentRebuilt,
        ...summarizeCandidateSet(candidates),
        explicit_ioc_tables: tables.explicit_tables ?? 0,
        explicit_ioc_rows_seen: tables.rows_seen ?? 0,
        explicit_ioc_rows_valid: tables.rows_valid ?? 0,
        explicit_ioc_rows_rejected: tables.rows_rejected ?? 0,
        explicit_ioc_rejection_reasons: tables.rejection_reasons || {},
        explicit_ioc_candidates_created: tables.candidates_created ?? 0,
        type_syntactic_occurrences: typing.syntactic_occurrences ?? 0,
        type_network_ioc_candidates: typing.network_ioc_candidates ?? 0,
        type_artifact_candidates: typing.artifact_candidates ?? 0,
        type_artifact_occurrences_dropped: typing.artifact_occurrences_dropped ?? 0,
        type_relative_paths: typing.relative_paths ?? 0,
        type_canonical_rejections: typing.canonical_rejections ?? 0,
        type_excluded_reasons: typing.excluded_reasons || {}
      });
      const structural = extracted.diagnostics?.structural_completeness || null;
      if (structural?.warning) {
        // A curated IOC section / table did not yield deterministic assertions:
        // its values rely on the model (or nothing). Diagnostic only.
        log.warn('structured IOC section degraded to AI path', {
          reportId: report.id,
          tables_not_interpreted: structural.tables_not_interpreted.slice(0, 20),
          degraded_blocks: structural.degraded_blocks.slice(0, 20),
          degraded_candidates: structural.degraded_candidates
        });
      }
      if (tables.inconsistent) {
        // Valid explicit rows that produced no candidate: an extractor bug, never a source problem.
        log.warn('explicit IOC extraction inconsistency', {
          reportId: report.id,
          explicit_identities: tables.explicit_identities,
          candidates_created: tables.candidates_created,
          missing_identities: (tables.missing_identities || []).slice(0, 40),
          dropped_asserted_identities: (tables.dropped_asserted_identities || []).slice(0, 40)
        });
      }
    }
    const candidateSet = summarizeCandidateSet(candidates);

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
      candidate_count: candidates.length,
      ai_needed_candidates: candidateSet.ai_needed,
      explicit_assertions: candidateSet.explicit_assertions,
      context_only: candidateSet.context_only,
      schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
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
    let aiMeta = null;
    const progressGate = createProgressGate(async (progress) => {
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
        analysis_progress: mergeAnalysisProgress(progressCarry, progress),
        analysis_run_id: runId
      });
    });
    try {
      const ai = await analyze(
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
          onProgress: (progress) => progressGate.push(progress)
        }
      );
      await progressGate.close();
      if (!ai.ok) {
        throw Object.assign(new Error(ai.error || 'AI validation failed'), {
          code: AI_FAILURE_CODES.AI_VALIDATION,
          details: ai.details
        });
      }
      aiValue = ai.value;
      aiMeta = ai.meta || null;
      log.info('AI analysis completed', {
        reportId: report.id,
        chunks: ai.meta?.chunks_total,
        chunks_from_cache: ai.meta?.chunks_from_cache,
        ai_calls: ai.meta?.ai_calls,
        ai_needed_candidates: ai.meta?.ai_needed_candidates,
        prompt_chars_total: ai.meta?.prompt_chars_total,
        elapsed_ms: ai.meta?.elapsed_ms,
        synthesis: ai.meta?.synthesis,
        timing: ai.meta?.timing
      });
    } catch (aiErr) {
      // No in-flight "analyzing" progress write may land after the terminal status below.
      await progressGate.close();
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

      const progressDetail = aiErr.progress && typeof aiErr.progress === 'object' ? aiErr.progress : null;
      log.warn('AI analysis failed', {
        reportId: report.id,
        code,
        progress: progressDetail
      });
      await updateReportStatus(pool, report.id, {
        analysis_status: 'failed',
        import_status: 'failed',
        failure_stage: 'analyzing',
        failure_code: code,
        failure_reason: message,
        failure_details: {
          issues: Array.isArray(aiErr.details) ? aiErr.details.slice(0, 30) : [],
          schema_version: aiErr.schema_version || null,
          rejected: Array.isArray(aiErr.rejected) ? aiErr.rejected.slice(0, 30) : [],
          provider_error: aiErr.provider_error && typeof aiErr.provider_error === 'object'
            ? aiErr.provider_error
            : null,
          progress: progressDetail
            ? {
                analysis_chunks_total: progressDetail.analysis_chunks_total ?? null,
                analysis_chunks_completed: progressDetail.analysis_chunks_completed ?? null,
                analysis_chunks_remaining: progressDetail.analysis_chunks_remaining ?? null,
                ai_calls: progressDetail.ai_calls ?? null,
                elapsed_ms: progressDetail.elapsed_ms ?? null,
                total_analysis_timeout_ms: progressDetail.total_analysis_timeout_ms ?? null,
                timing: Array.isArray(progressDetail.timing) ? progressDetail.timing.slice(-24) : [],
                resumable: true
              }
            : null
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

    // Merge AI candidate updates onto the deterministic set (never the reverse).
    // AI identities are untrusted: IPv4 carved from a hostname prefix is dropped.
    candidates = mergeAiCandidateUpdates(candidates, aiValue, { document });

    // --- Match local IOCs ---
    await setStage('matching');
    const matched = await matchCandidateSet(pool, candidates);
    const summary = matched.summary;

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
      const known = entityByRef.get(normalizeEntityName(e.name));
      const names = [...new Set([...(known?.names || []), row.name, e.name, ...(e.aliases || [])].filter(Boolean))];
      const entry = { ...row, names };
      entityByRef.set(normalizeEntityName(e.name), entry);
      entityByRef.set(e.name, entry);
    }

    const candByKey = new Map(
      savedCandidates.map((c) => [`${c.candidate_type}:${c.normalized_value}`, c])
    );
    const { rows: relRows, rejected: relRejected } = buildValidatedRelationships({
      relationships: aiValue.relationships || [],
      entityByRef,
      candByKey,
      document,
      report
    });
    if (relRejected.length) {
      log.info('relationships rejected by policy', {
        reportId: report.id,
        accepted: relRows.length,
        rejected: relRejected.length,
        reasons: relRejected.reduce((acc, r) => ({ ...acc, [r.reason]: (acc[r.reason] || 0) + 1 }), {})
      });
    }
    await replaceRelationships(pool, report.id, relRows);

    let reportIntelligence = null;
    try {
      reportIntelligence = await persistReportIntelligence(pool, report.id, aiValue, { log });
    } catch (err) {
      log.warn('report intelligence persist failed (non-fatal)', { reportId: report.id, error: err.message });
      reportIntelligence = { error: err.message };
    }

    // Effective TLP: manual override > explicit marking in the document >
    // safe default. The model's `tlp` is recorded as a hint only — a
    // sharing restriction is never inferred from subject matter.
    const latestReport = (await getReportById(pool, report.id)) || report;
    const tlpResolution = resolveEffectiveTlp({ report: latestReport, document, aiHint: aiValue.tlp || null });

    await updateReportStatus(pool, report.id, {
      title: document.title || report.title,
      language: aiValue.language || document.language || report.language,
      tlp: tlpResolution.tlp,
      tlp_source: tlpResolution.tlp_source,
      confidence: aiValue.confidence ?? null,
      report_type: aiValue.report_type || null,
      summary: aiValue.summary || null,
      candidate_summary: summary,
      ai_result: {
        tlp: {
          effective: tlpResolution.tlp,
          source: tlpResolution.tlp_source,
          detected: tlpResolution.detection,
          ai_hint: tlpResolution.ai_hint
        },
        publication_date: publicationDate,
        entity_count: (aiValue.entities || []).length,
        relationship_count: relRows.length,
        candidate_update_count: (aiValue.candidate_updates || []).length,
        report_intelligence: reportIntelligence,
        ai_calls: aiMeta?.ai_calls ?? null,
        chunks_total: aiMeta?.chunks_total ?? null,
        chunks_from_cache: aiMeta?.chunks_from_cache ?? null,
        prompt_chars_total: aiMeta?.prompt_chars_total ?? null,
        elapsed_ms: aiMeta?.elapsed_ms ?? null,
        synthesis: aiMeta?.synthesis ?? null
      },
      canonical_document: document,
      analysis_status: 'review_required',
      import_status: 'review_required',
      analysis_progress: {
        stage: 'review_required',
        completed: true,
        candidate_extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
        document_extractor: document.meta?.extractor || null,
        schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
        extraction_diagnostics: compactExtractionDiagnostics(extractionDiagnostics),
        analysis_chunks_total: aiMeta?.chunks_total ?? null,
        analysis_chunks_completed: aiMeta?.chunks_total ?? null,
        ai_calls: aiMeta?.ai_calls ?? null,
        ai_needed_candidates: aiMeta?.ai_needed_candidates ?? null,
        elapsed_ms: aiMeta?.elapsed_ms ?? null,
        timing: Array.isArray(aiMeta?.timing) ? aiMeta.timing.slice(-24) : []
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

/**
 * Candidate reuse on Retry: stored candidates are reused only when the
 * extraction contract that produced them is current and the document was not
 * rebuilt; otherwise they are rebuilt from the canonical document and the
 * semantic analysis starts a new run (older chunk checkpoints are incompatible).
 * @param {{ priorExtractionVersion: string|null, documentRebuilt: boolean, existingCount: number, resumePreferred: boolean, refreshCandidates: boolean }} input
 */
/**
 * Keep extraction provenance on analysis_progress across stage writes.
 * setStage('analyzing') used to replace the object and drop the version,
 * which made Retry re-extract an already-valid deterministic candidate set.
 * @param {{ candidate_extraction_version?: string|null, extraction_diagnostics?: object|null }} carry
 * @param {object} extra
 */
export function mergeAnalysisProgress(carry, extra = {}) {
  const out = { ...(extra && typeof extra === 'object' ? extra : {}) };
  if (out.candidate_extraction_version == null && carry?.candidate_extraction_version) {
    out.candidate_extraction_version = carry.candidate_extraction_version;
  }
  if (out.extraction_diagnostics == null && carry?.extraction_diagnostics) {
    out.extraction_diagnostics = carry.extraction_diagnostics;
  }
  return out;
}

export function decideCandidateReuse(input) {
  const extractionChanged =
    input.priorExtractionVersion !== THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION || input.documentRebuilt === true;
  const shouldReuseCandidates =
    input.resumePreferred === true && Number(input.existingCount) > 0 && !extractionChanged && !input.refreshCandidates;
  return { extractionChanged, shouldReuseCandidates };
}

/**
 * Serializes AI progress writes and closes them once analysis settles. The
 * stream client fires activity callbacks without awaiting them, so without
 * this an in-flight "analyzing" progress write could land after the terminal
 * failure write and leave a failed report looking active (Retry then sees an
 * "already running" analysis with no job).
 * @param {(progress: object) => Promise<void>} write
 */
export function createProgressGate(write) {
  let closed = false;
  let tail = Promise.resolve();
  return {
    push(progress) {
      if (closed) return Promise.resolve();
      const next = tail.then(() => (closed ? undefined : write(progress)));
      tail = next.catch(() => {});
      return next;
    },
    async close() {
      closed = true;
      await tail;
    }
  };
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

/**
 * AI relationships → persistable rows. Model output is a proposal: every
 * relationship passes the deterministic relationship policy (known type,
 * compatible endpoint kinds, evidence in the source naming both endpoints,
 * explicit quote for the publisher) or it is dropped.
 * @param {{ relationships: object[], entityByRef: Map, candByKey: Map, document: object|null, report: object }} input
 */
export function buildValidatedRelationships({ relationships, entityByRef, candByKey, document, report }) {
  const evidenceIndex = buildEvidenceIndex(document, { sourceUrl: report?.source_url || null });
  const tokens = publisherTokens(report, document);
  const rows = [];
  const rejected = [];
  for (const r of relationships || []) {
    const subject = resolveRef(r.subject_kind, r.subject_ref, entityByRef, candByKey);
    const object = resolveRef(r.object_kind, r.object_ref, entityByRef, candByKey);
    if (!subject || !object) continue;
    const verdict = validateRelationship(r, subject.endpoint, object.endpoint, {
      requireEvidence: true,
      evidenceIndex,
      publisherTokens: tokens
    });
    if (!verdict.ok) {
      rejected.push({ subject_ref: r.subject_ref, relationship_type: r.relationship_type, object_ref: r.object_ref, reason: verdict.reason });
      continue;
    }
    rows.push({
      portable_id: `relationship--${crypto.randomUUID()}`,
      subject_kind: r.subject_kind,
      subject_entity_id: subject.entity_id || null,
      subject_candidate_id: subject.candidate_id || null,
      subject_ioc_id: subject.ioc_id || null,
      subject_portable_ref: subject.portable_ref || null,
      relationship_type: verdict.relationship_type,
      object_kind: r.object_kind,
      object_entity_id: object.entity_id || null,
      object_candidate_id: object.candidate_id || null,
      object_ioc_id: object.ioc_id || null,
      object_portable_ref: object.portable_ref || null,
      role: r.role || null,
      confidence: r.confidence ?? null,
      evidence_text: r.evidence_text || null,
      block_id: verdict.block_id || r.evidence_block_ids?.[0] || null
    });
  }
  return { rows, rejected };
}

function resolveRef(kind, ref, entityByRef, candByKey) {
  if (kind === 'entity') {
    const e = entityByRef.get(normalizeEntityName(ref)) || entityByRef.get(ref);
    if (!e) return null;
    return {
      entity_id: e.id,
      portable_ref: e.portable_id,
      endpoint: { kind: 'entity', entity_type: e.entity_type, names: e.names || [e.name] }
    };
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
      portable_ref: c.portable_id,
      endpoint: {
        kind: 'candidate',
        candidate_type: c.candidate_type,
        assessment: c.assessment || null,
        names: [c.normalized_value, c.original_value].filter(Boolean)
      }
    };
  }
  return null;
}
