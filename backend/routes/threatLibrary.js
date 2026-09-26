/**
 * Threat Library HTTP routes.
 */

import multer from 'multer';
import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY, AUDIT_STATUS } from '../lib/auditConstants.js';
import {
  buildDeleteAuditEvent,
  buildImportAuditEvent,
  buildImportFailedAuditEvent,
  buildSourceUrlAuditEvent,
  buildTlpAuditEvent,
  buildReportTagAuditEvent,
  buildThibExportAuditEvent,
  reportAuditEntity,
  reportAuditSnapshot,
  initiatedBy,
  safeErrorCategory
} from '../lib/threatLibrary/audit.js';
import { registerRouteModule } from '../lib/routeRegistry.js';
import { PDF_MAX_BYTES, THIB_MAX_BYTES, normalizeTlp, TLP_DISPLAY, TLP_VALUES } from '../lib/threatLibrary/constants.js';
import { isValidTlp } from '../lib/threatLibrary/tlpPolicy.js';
import { serializePublicationDate } from '../lib/threatLibrary/publicationDate.js';
import { validateThreatLibraryUrl } from '../lib/threatLibrary/urlIngest.js';
import { validatePdfBuffer, isAcceptablePdfUploadMeta } from '../lib/threatLibrary/pdfIngest.js';
import { maskAiSettingsForClient } from '../lib/threatLibrary/ai/providers.js';
import { exportThibBundle, validateThibBundle, previewThibImport } from '../lib/threatLibrary/thib/codec.js';
import { importThibBundle } from '../lib/threatLibrary/thibImport.js';
import { applyCandidateReviewActions, finalizeReport } from '../lib/threatLibrary/reviewService.js';
import { storeArtifactBuffer } from '../lib/threatLibrary/artifactStore.js';
import { getThreatLibraryJobOptions } from '../lib/threatLibrary/queueConfig.js';
import {
  getAiSettings,
  updateAiSettings,
  clearAiApiKey,
  createThreatReport,
  listThreatReports,
  getReportByPublicId,
  loadReportSnapshot,
  loadMatchedIocPublicIds,
  deleteThreatReport,
  createJob,
  updateJob,
  insertArtifact,
  requestAnalysisCancel,
  updateReportStatus,
  countReportCandidates,
  attachReportCounts,
  updateReportSourceUrl,
  updateReportTlp
} from '../lib/threatLibrary/store.js';
import { loadIocThreatContext } from '../lib/threatLibrary/iocThreatContext.js';
import {
  loadReportTags,
  loadReportTagsByReportIds,
  findEnabledTag,
  addReportTag,
  removeReportTag,
  countReportTagInheritingIocs
} from '../lib/threatLibrary/reportTags.js';
import {
  reportTagInheritanceEligibleSql,
  loadInheritedReportTagRows,
  groupInheritedTagsBySeed
} from '../lib/threatLibrary/reportTagInheritance.js';
import { resolveArtifactScopedIocIds } from '../lib/fileArtifacts/read.js';
import { validateReportSourceUrl } from '../lib/threatLibrary/sourceUrl.js';
import { parseReportListPageSize } from '../lib/threatLibrary/reportListQuery.js';
import {
  IMPORT_DUPLICATE_MESSAGES,
  canonicalizeReportUrl,
  claimReportImport
} from '../lib/threatLibrary/importIdentity.js';
import { resolveReportPhase, resolveCandidateState } from '../lib/threatLibrary/reportPhase.js';
import { defaultTimeoutsForProvider } from '../lib/threatLibrary/ai/timeouts.js';
import {
  isActiveAnalysisStatus,
  resolveRetryStartStatus,
  buildRetryProgress
} from '../lib/threatLibrary/retryState.js';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: Math.max(PDF_MAX_BYTES, THIB_MAX_BYTES), files: 1 }
});

/**
 * Compact provenance for the review UI (occurrence list capped; no raw DB ids).
 * @param {object|null} evidence
 */
function publicCandidateEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object') return null;
  const occurrences = Array.isArray(evidence.occurrences) ? evidence.occurrences.slice(0, 12) : [];
  return {
    source_assertion: evidence.source_assertion || null,
    evidence_strength: evidence.evidence_strength || null,
    evidence_tier: evidence.evidence_tier || null,
    policy_decision: evidence.policy_decision || null,
    decision_source: evidence.decision_source || null,
    ai_needed: evidence.ai_needed === true,
    is_direct_source_observable: evidence.is_direct_source_observable !== false,
    is_parser_derived_metadata: evidence.is_parser_derived_metadata === true,
    derived_from: evidence.derived_from || null,
    occurrence_count: evidence.occurrence_count ?? occurrences.length,
    zones: Array.isArray(evidence.zones) ? evidence.zones : [],
    parsed: evidence.parsed && typeof evidence.parsed === 'object' ? evidence.parsed : {},
    table_rows: (Array.isArray(evidence.table_rows) ? evidence.table_rows : []).slice(0, 6).map((r) => ({
      table_id: r.table_id || null,
      page: r.page ?? null,
      row_index: r.row_index ?? null,
      declared_type: r.declared_type || null,
      type_cell: r.type_cell || null,
      raw_value: r.raw_value || null,
      description: r.description || null,
      explicit: r.explicit === true,
      related_values: Array.isArray(r.related_values) ? r.related_values : []
    })),
    occurrences: occurrences.map((o) => ({
      block_id: o.block_id || null,
      page: o.page ?? null,
      zone: o.zone || null,
      section_heading: o.section_heading || null,
      form: o.form || null,
      port: o.port ?? null,
      table_row: o.table_row ?? null,
      surrounding_text: o.surrounding_text || null
    }))
  };
}

function publicReport(row) {
  if (!row) return null;
  return {
    id: row.public_id,
    title: row.title,
    source_type: row.source_type,
    source_name: row.source_name,
    source_url: row.source_url,
    source_file_name: row.source_file_name,
    source_sha256: row.source_sha256,
    // published_at = original publication instant (or 00:00 UTC of the stated
    // day when precision is 'date'); published_date = calendar day as the
    // source stated it. created_at (Imported) is a separate concept.
    ...serializePublicationDate(row),
    language: row.language,
    tlp: row.tlp,
    tlp_display: TLP_DISPLAY[row.tlp] || `TLP:${String(row.tlp || '').toUpperCase()}`,
    // Provenance of the effective TLP: explicit (document marking) / default / manual.
    tlp_source: row.tlp_source || 'default',
    confidence: row.confidence,
    report_type: row.report_type,
    summary: row.summary,
    import_status: row.import_status,
    analysis_status: row.analysis_status,
    failure_stage: row.failure_stage,
    failure_reason: row.failure_reason,
    failure_code: row.failure_code || null,
    failure_details: row.failure_details || {},
    analysis_progress: row.analysis_progress || {},
    candidate_summary: row.candidate_summary || {},
    // Presentation phase derived from analysis_status (single source of truth).
    review_phase: resolveReportPhase(row),
    candidate_state: resolveCandidateState(row),
    indicator_count: row.indicator_count,
    // Raw persisted rows vs. rows that belong in the analyst review set.
    raw_candidate_count: row.indicator_count ?? null,
    review_candidate_count: row.review_candidate_count ?? null,
    matched_count: row.matched_count,
    entity_count: row.entity_count,
    created_at: row.created_at,
    updated_at: row.updated_at,
    finalized_at: row.finalized_at,
    // Analyst-managed report tags (campaign/threat context), present when loaded.
    ...(Array.isArray(row.tags) ? { tags: row.tags } : {})
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditLog: Function, auditSuccess: Function, auditFailure?: Function, resolveActor?: Function }} audit
 * @param {{ threatLibraryQueue?: import('bullmq').Queue }} deps
 */
export function registerThreatLibraryRoutes(app, pool, audit, deps = {}) {
  registerRouteModule('threat_library');

  const queue = deps.threatLibraryQueue || null;

  /**
   * Session principal with its persisted public id. Interactive sessions only
   * carry the numeric user id, so this is what stamps created_by /
   * requested_by and what the service layer receives as the initiating user.
   */
  async function actorOf(req) {
    if (typeof audit?.resolveActor === 'function') {
      const actor = await audit.resolveActor(req);
      if (actor) return actor;
    }
    return req.user || null;
  }

  async function writeAudit(req, event) {
    if (typeof audit?.auditLog !== 'function') return;
    await audit.auditLog({ req, ...event });
  }

  /** Counts + analyst report tags for report responses (one extra small query). */
  async function reportWithDetail(row) {
    if (!row) return row;
    const counted = await attachReportCounts(pool, row);
    return { ...counted, tags: await loadReportTags(pool, row.id) };
  }

  async function enqueueAnalyze(reportId, jobRow, extra = {}) {
    if (!queue) {
      const err = new Error('Threat Library queue unavailable');
      err.code = 'queue_unavailable';
      throw err;
    }
    const job = await queue.add(
      extra.jobType || 'analyze',
      { reportId, jobId: jobRow.id, ...extra },
      getThreatLibraryJobOptions()
    );
    await updateJob(pool, jobRow.id, { bullmq_job_id: String(job.id) });
    return job;
  }

  /**
   * Duplicate URL / PDF import: an expected no-op (200), not a failure. The
   * existing report is returned so the client can link to it; nothing was
   * created, fetched, extracted or queued.
   * @param {object} existing threat_reports row
   * @param {'url'|'sha256'} reason
   */
  async function duplicateImportBody(existing, reason) {
    return {
      already_imported: true,
      duplicate_reason: reason,
      message: IMPORT_DUPLICATE_MESSAGES[reason],
      report: publicReport(await reportWithDetail(existing))
    };
  }

  // --- AI settings (admin) ---
  app.get('/api/threat-library/ai-settings', requireRole(ROLES.ADMIN), async (_req, res) => {
    try {
      const settings = await getAiSettings(pool);
      return res.json({ settings: maskAiSettingsForClient(settings) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load AI settings', detail: err.message });
    }
  });

  app.put('/api/threat-library/ai-settings', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const body = req.body || {};
      if (body.enabled === true && body.privacy_ack !== true) {
        const current = await getAiSettings(pool);
        if (!current?.privacy_ack_at && ['openai', 'anthropic', 'openai_compatible'].includes(body.provider || current?.provider)) {
          if ((body.provider || current?.provider) !== 'ollama') {
            return res.status(400).json({
              message:
                'Acknowledge that report content may be sent to the configured external AI provider before enabling.'
            });
          }
        }
      }
      // When switching provider without explicit timeouts, apply provider-appropriate defaults.
      if (body.provider && body.inactivity_timeout_ms == null && body.first_token_timeout_ms == null) {
        const defaults = defaultTimeoutsForProvider(body.provider);
        body.connection_timeout_ms = body.connection_timeout_ms ?? defaults.connection_timeout_ms;
        body.first_token_timeout_ms = body.first_token_timeout_ms ?? defaults.first_token_timeout_ms;
        body.inactivity_timeout_ms = body.inactivity_timeout_ms ?? defaults.inactivity_timeout_ms;
        body.total_analysis_timeout_ms = body.total_analysis_timeout_ms ?? defaults.total_analysis_timeout_ms;
        body.timeout_ms = body.timeout_ms ?? defaults.inactivity_timeout_ms;
      }
      const actor = await actorOf(req);
      const updated = await updateAiSettings(pool, body, actor?.publicId);
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.THREAT_LIBRARY_AI_SETTINGS_UPDATED,
        entityType: AUDIT_ENTITY.SYSTEM,
        entityDisplay: 'Threat Library AI settings',
        severity: AUDIT_SEVERITY.WARNING,
        after: {
          enabled: updated.enabled,
          provider: updated.provider,
          model: updated.model,
          api_key_updated: Boolean(body.api_key),
          inactivity_timeout_ms: updated.inactivity_timeout_ms,
          total_analysis_timeout_ms: updated.total_analysis_timeout_ms
        }
      });
      return res.json({ settings: maskAiSettingsForClient(updated) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update AI settings', detail: err.message });
    }
  });

  app.delete('/api/threat-library/ai-settings/api-key', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const actor = await actorOf(req);
      const updated = await clearAiApiKey(pool, actor?.publicId);
      return res.json({ settings: maskAiSettingsForClient(updated) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to clear API key', detail: err.message });
    }
  });

  app.post('/api/threat-library/ai-settings/probe', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const settings = await getAiSettings(pool);
      const { probeAiProvider } = await import('../lib/threatLibrary/ai/probe.js');
      const result = await probeAiProvider(settings);
      await pool.query(
        `UPDATE threat_library_ai_settings
         SET last_probe_at = NOW(), last_probe_ok = $2, last_probe_detail = $3::jsonb, updated_at = NOW()
         WHERE id = 1`,
        [result.ok === true, JSON.stringify({
          ok: result.ok,
          elapsed_ms: result.elapsed_ms,
          error: result.error,
          details: result.details,
          schema_version: result.schema_version
        })]
      );
      return res.json({ probe: result });
    } catch (err) {
      return res.status(400).json({
        message: err.message || 'Provider probe failed',
        code: err.code || 'probe_failed'
      });
    }
  });

  // --- List / detail ---
  app.get('/api/threat-library/reports', async (req, res) => {
    try {
      const result = await listThreatReports(pool, {
        // Only the UI page sizes (25 / 50) are served; anything else -> 25.
        limit: parseReportListPageSize(req.query.limit),
        offset: req.query.offset,
        // Library navigation search over stored report metadata only.
        search: req.query.search
      });
      const tagsByReport = await loadReportTagsByReportIds(pool, result.items.map((r) => r.id));
      return res.json({
        items: result.items.map((r) => publicReport({ ...r, tags: tagsByReport.get(Number(r.id)) || [] })),
        total: result.total,
        limit: result.limit,
        offset: result.offset
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list reports', detail: err.message });
    }
  });

  app.get('/api/threat-library/reports/:publicId', async (req, res) => {
    try {
      const report = await getReportByPublicId(pool, req.params.publicId);
      if (!report) return res.status(404).json({ message: 'Report not found' });
      const snap = await loadReportSnapshot(pool, report.id);
      const matchedIocPublicId = await loadMatchedIocPublicIds(pool, snap.candidates);
      return res.json({
        report: publicReport(await reportWithDetail(snap.report)),
        candidates: snap.candidates.map((c) => ({
          id: c.id,
          public_id: c.public_id,
          candidate_type: c.candidate_type,
          original_value: c.original_value,
          normalized_value: c.normalized_value,
          assessment: c.assessment,
          role: c.role,
          confidence: c.confidence,
          evidence_text: c.evidence_text,
          section: c.section,
          block_id: c.block_id,
          page_number: c.page_number,
          review_status: c.review_status === 'created_ioc' ? 'approved' : c.review_status,
          match_state: c.match_state,
          matched_ioc_id: c.matched_ioc_id,
          matched_ioc_observable_type: c.matched_ioc_observable_type,
          // Linked IOC record's public id (exact PK lookup); null when unknown.
          matched_ioc_public_id: matchedIocPublicId(c),
          promotion_outcome: c.promotion_outcome || (c.review_status === 'created_ioc' ? 'created' : null),
          promotion_detail: c.promotion_detail || null,
          promoted_at: c.promoted_at || null,
          is_ioc: c.is_ioc !== false,
          source_assertion: c.source_assertion || c.evidence?.source_assertion || null,
          evidence: publicCandidateEvidence(c.evidence)
        })),
        entities: snap.entities.map((e) => ({
          id: e.public_id,
          entity_type: e.entity_type,
          name: e.name,
          description: e.description,
          confidence: e.link_confidence,
          evidence_text: e.link_evidence
        })),
        relationships: snap.relationships,
        artifacts: snap.artifacts,
        jobs: snap.jobs,
        // Omit full canonical_document by default size; include block count
        document_meta: snap.report.canonical_document
          ? {
              title: snap.report.canonical_document.title,
              language: snap.report.canonical_document.language,
              block_count: (snap.report.canonical_document.blocks || []).length
            }
          : null
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load report', detail: err.message });
    }
  });

  app.get('/api/threat-library/reports/:publicId/status', async (req, res) => {
    try {
      const report = await getReportByPublicId(pool, req.params.publicId);
      if (!report) return res.status(404).json({ message: 'Report not found' });
      const { rows: jobs } = await pool.query(
        `SELECT public_id, status, stage, progress, error_message, created_at, finished_at
         FROM threat_library_jobs WHERE report_id = $1 ORDER BY id DESC LIMIT 1`,
        [report.id]
      );
      return res.json({
        report: publicReport(await reportWithDetail(report)),
        job: jobs[0] || null
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load status', detail: err.message });
    }
  });

  // --- URL import ---
  app.post('/api/threat-library/import/url', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    try {
      const url = String(req.body?.url || '').trim();
      const policy = validateThreatLibraryUrl(url);
      if (!policy.ok) return res.status(400).json({ message: policy.error });

      const canonicalUrl = canonicalizeReportUrl(policy.url);
      if (!canonicalUrl) return res.status(400).json({ message: 'URL must be a valid http or https URL' });

      const actor = await actorOf(req);
      // Duplicate check BEFORE any report row, job or queue entry exists: a
      // URL already in the library is never fetched or analysed again.
      const claim = await claimReportImport(pool, { kind: 'url', key: canonicalUrl }, (db) => createThreatReport(db, {
        title: policy.parsed.hostname || 'URL report',
        source_type: 'url',
        source_url: policy.url,
        source_url_canonical: canonicalUrl,
        source_name: policy.parsed.hostname,
        tlp: normalizeTlp(req.body?.tlp || 'clear'),
        // A TLP supplied with the import request is an analyst assertion.
        tlp_source: req.body?.tlp ? 'manual' : 'default',
        created_by: actor?.publicId
      }));
      if (claim.duplicate) {
        await writeAudit(req, buildImportAuditEvent({
          sourceType: 'url',
          report: claim.report,
          user: actor,
          details: { source_url: policy.url, host: policy.parsed.hostname, already_imported: true, duplicate_reason: 'url' }
        }));
        return res.status(200).json(await duplicateImportBody(claim.report, 'url'));
      }
      const report = claim.report;
      const jobRow = await createJob(pool, {
        reportId: report.id,
        jobType: 'analyze',
        requestedBy: actor?.publicId
      });
      await enqueueAnalyze(report.id, jobRow, { sourceUrl: policy.url });

      await writeAudit(req, buildImportAuditEvent({
        sourceType: 'url',
        report,
        user: actor,
        jobPublicId: jobRow.public_id,
        details: { source_url: policy.url, host: policy.parsed.hostname }
      }));

      return res.status(202).json({ already_imported: false, report: publicReport(report), job_id: jobRow.public_id });
    } catch (err) {
      await writeAudit(req, buildImportFailedAuditEvent({
        sourceType: 'url',
        user: req.user,
        code: safeErrorCategory(err),
        details: { host: (() => { try { return new URL(String(req.body?.url || '')).hostname; } catch { return null; } })() }
      })).catch(() => {});
      return res.status(500).json({ message: 'URL import failed', detail: err.message });
    }
  });

  // --- PDF import ---
  app.post(
    '/api/threat-library/import/pdf',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    (req, res, next) => {
      upload.single('file')(req, res, (err) => {
        if (!err) return next();
        if (err instanceof multer.MulterError) {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({
              message: `PDF exceeds maximum size (${PDF_MAX_BYTES} bytes)`,
              code: 'pdf_too_large'
            });
          }
          return res.status(400).json({
            message: 'PDF upload failed',
            code: 'pdf_upload_failed',
            detail: err.code
          });
        }
        return res.status(400).json({
          message: 'PDF upload failed',
          code: 'pdf_upload_failed'
        });
      });
    },
    async (req, res) => {
      try {
        const file = req.file;
        if (!file?.buffer) {
          return res.status(400).json({
            message: 'PDF file is required. Ensure the upload uses multipart field name "file".',
            code: 'pdf_upload_failed'
          });
        }
        if (!isAcceptablePdfUploadMeta(file.mimetype, file.originalname)) {
          return res.status(400).json({
            message: 'Only PDF uploads are allowed',
            code: 'pdf_invalid'
          });
        }
        const validation = validatePdfBuffer(file.buffer, {
          fileName: file.originalname,
          mimeType: file.mimetype
        });
        if (!validation.ok) {
          return res.status(400).json({
            message: validation.error,
            code: validation.code || 'pdf_invalid'
          });
        }

        const actor = await actorOf(req);
        // validation.sha256 = SHA-256 of the original uploaded bytes. Checked
        // BEFORE the file is stored, extracted or queued: identical bytes
        // under any filename are the same report.
        const claim = await claimReportImport(pool, { kind: 'sha256', key: validation.sha256 }, (db) => createThreatReport(db, {
          title: validation.fileName.replace(/\.pdf$/i, ''),
          source_type: 'pdf',
          source_file_name: validation.fileName,
          source_sha256: validation.sha256,
          source_name: validation.fileName,
          tlp: normalizeTlp(req.body?.tlp || 'clear'),
          tlp_source: req.body?.tlp ? 'manual' : 'default',
          created_by: actor?.publicId
        }));
        if (claim.duplicate) {
          await writeAudit(req, buildImportAuditEvent({
            sourceType: 'pdf',
            report: claim.report,
            user: actor,
            details: {
              file_name: validation.fileName,
              sha256: validation.sha256,
              size_bytes: validation.sizeBytes,
              already_imported: true,
              duplicate_reason: 'sha256'
            }
          }));
          return res.status(200).json(await duplicateImportBody(claim.report, 'sha256'));
        }
        const report = claim.report;

        let stored;
        try {
          stored = await storeArtifactBuffer(report.id, file.buffer, {
            fileName: validation.fileName,
            ext: '.pdf'
          });
        } catch (storeErr) {
          // No PDF was kept, so the report can never be analysed: retire it
          // rather than leave a hash identity that blocks re-uploading the file.
          await deleteThreatReport(pool, report.id).catch(() => {});
          return res.status(500).json({
            message: 'Failed to store the uploaded PDF',
            code: 'pdf_storage_failed',
            detail: storeErr.message
          });
        }
        await insertArtifact(pool, report.id, {
          artifact_type: 'pdf_upload',
          file_name: validation.fileName,
          mime_type: 'application/pdf',
          size_bytes: stored.sizeBytes,
          sha256: stored.sha256,
          storage_key: stored.storageKey
        });

        const jobRow = await createJob(pool, {
          reportId: report.id,
          jobType: 'analyze',
          requestedBy: actor?.publicId
        });
        await enqueueAnalyze(report.id, jobRow);

        await writeAudit(req, buildImportAuditEvent({
          sourceType: 'pdf',
          report,
          user: actor,
          jobPublicId: jobRow.public_id,
          details: {
            file_name: validation.fileName,
            sha256: validation.sha256,
            size_bytes: validation.sizeBytes
          }
        }));

        return res.status(202).json({ already_imported: false, report: publicReport(report), job_id: jobRow.public_id });
      } catch (err) {
        await writeAudit(req, buildImportFailedAuditEvent({
          sourceType: 'pdf',
          user: req.user,
          code: safeErrorCategory(err),
          details: { file_name: req.file?.originalname ? String(req.file.originalname).slice(0, 255) : null }
        })).catch(() => {});
        return res.status(500).json({
          message: 'PDF import failed',
          code: err.code || 'pdf_upload_failed',
          detail: err.message
        });
      }
    }
  );

  // --- THIB validate / import (no AI) ---
  app.post(
    '/api/threat-library/import/thib/validate',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    upload.single('file'),
    async (req, res) => {
      try {
        let raw = req.body?.bundle;
        if (req.file?.buffer) {
          raw = JSON.parse(req.file.buffer.toString('utf8'));
        } else if (typeof raw === 'string') {
          raw = JSON.parse(raw);
        }
        if (!raw || typeof raw !== 'object') {
          return res.status(400).json({ message: 'THIB JSON is required' });
        }
        const preview = await previewThibImport(pool, raw);
        if (!preview.ok) return res.status(400).json(preview);
        return res.json({
          ok: true,
          already_imported: preview.already_imported === true,
          summary: preview.summary,
          report_preview: preview.bundle?.report || preview.report,
          message: preview.already_imported ? 'Already imported' : undefined
        });
      } catch (err) {
        return res.status(400).json({ message: 'Invalid THIB JSON', detail: err.message });
      }
    }
  );

  app.post(
    '/api/threat-library/import/thib',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    upload.single('file'),
    async (req, res) => {
      try {
        let raw = req.body?.bundle;
        if (req.file?.buffer) {
          raw = JSON.parse(req.file.buffer.toString('utf8'));
        } else if (typeof raw === 'string') {
          raw = JSON.parse(raw);
        }
        const actor = await actorOf(req);
        const result = await importThibBundle(pool, raw, {
          createdBy: actor?.publicId,
          conflictMode: req.body?.conflict_mode || 'keep_both'
        });
        if (!result.ok) return res.status(400).json(result);
        await writeAudit(req, buildImportAuditEvent({
          sourceType: 'thib',
          report: result.report,
          user: actor,
          details: {
            file_name: req.file?.originalname ? String(req.file.originalname).slice(0, 255) : null,
            already_imported: result.already_imported === true,
            conflict_mode: req.body?.conflict_mode || 'keep_both',
            // Counts only — the THIB payload itself is never stored in audit.
            summary: result.summary && typeof result.summary === 'object'
              ? Object.fromEntries(Object.entries(result.summary).filter(([, v]) => typeof v === 'number' || typeof v === 'boolean'))
              : null
          }
        }));
        return res.status(result.already_imported ? 200 : 201).json({
          already_imported: result.already_imported === true,
          message: result.message,
          report: publicReport(result.report),
          summary: result.summary
        });
      } catch (err) {
        return res.status(500).json({ message: 'THIB import failed', detail: err.message });
      }
    }
  );

  // --- Review actions ---
  app.post(
    '/api/threat-library/reports/:publicId/review',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        const result = await applyCandidateReviewActions(pool, report.id, {
          action: req.body?.action,
          candidateIds: req.body?.candidate_ids,
          confirm: req.body?.confirm === true,
          user: await actorOf(req),
          audit,
          req
        });
        if (!result.ok) {
          return res.status(result.status || 400).json({
            message: result.error,
            code: result.code || null,
            phase: result.phase || null,
            summary: result.summary || undefined,
            results: result.results || undefined,
            pending_count: result.pending_count,
            report: result.code ? publicReport(await reportWithDetail(report)) : undefined
          });
        }
        return res.json(result);
      } catch (err) {
        // The operation aborted before its summary event could be written:
        // record the failure itself (safe category only) so it is never silent.
        if (req.body?.action === 'create_iocs' && req.body?.confirm === true) {
          const report = await getReportByPublicId(pool, req.params.publicId).catch(() => null);
          await writeAudit(req, {
            action: AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED,
            ...reportAuditEntity(report || { public_id: req.params.publicId, title: null }),
            severity: AUDIT_SEVERITY.WARNING,
            status: AUDIT_STATUS.FAILED,
            metadata: {
              ...reportAuditSnapshot(report),
              initiated_by: initiatedBy(req.user),
              selected: Array.isArray(req.body?.candidate_ids) ? req.body.candidate_ids.length : 0,
              created: 0,
              already_existing: 0,
              failed: 0,
              result: 'operation_failed',
              error_code: safeErrorCategory(err)
            }
          }).catch(() => {});
        }
        return res.status(500).json({ message: 'Review action failed', detail: err.message });
      }
    }
  );

  app.post(
    '/api/threat-library/reports/:publicId/finalize',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        const result = await finalizeReport(pool, report.id, { user: await actorOf(req), audit, req });
        if (!result.ok) {
          return res.status(result.status || 400).json({
            message: result.error,
            code: result.code || null,
            phase: result.phase || null,
            pending_count: result.pending_count,
            report: publicReport(await reportWithDetail(report))
          });
        }
        const updated = await getReportByPublicId(pool, req.params.publicId);
        return res.json({ report: publicReport(await reportWithDetail(updated)) });
      } catch (err) {
        return res.status(500).json({ message: 'Finalize failed', detail: err.message });
      }
    }
  );

  // --- Export THIB ---
  app.get(
    '/api/threat-library/reports/:publicId/export/thib',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        if (report.tlp === 'red' && req.user?.role !== ROLES.ADMIN) {
          return res.status(403).json({ message: 'TLP:RED export requires admin' });
        }
        if (report.tlp === 'red' && req.query.confirm_red !== '1') {
          return res.status(400).json({
            message: 'TLP:RED export blocked. Pass confirm_red=1 as admin to proceed deliberately.',
            code: 'tlp_red_export_blocked'
          });
        }
        const snap = await loadReportSnapshot(pool, report.id);
        let bundle;
        try {
          // Temporarily allow red for admin confirm
          if (report.tlp === 'red') {
            const { attachThibIntegrity } = await import('../lib/threatLibrary/thib/integrity.js');
            // Use export with patched tlp amber_strict for structure then restore — cleaner: call export after override
            const patched = { ...snap, report: { ...snap.report, tlp: 'amber_strict' } };
            bundle = exportThibBundle(patched);
            bundle.report.tlp = 'red';
            bundle = attachThibIntegrity(bundle);
          } else {
            bundle = exportThibBundle(snap);
          }
        } catch (err) {
          if (err.code === 'tlp_red_export_blocked') {
            return res.status(400).json({ message: err.message, code: err.code });
          }
          throw err;
        }
        await writeAudit(req, buildThibExportAuditEvent({
          report,
          bundle,
          user: req.user,
          confirmRed: req.query.confirm_red === '1'
        }));
        const name = `${String(report.title || 'report').replace(/[^\w.\-]+/g, '_').slice(0, 80)}.thib.json`;
        res.setHeader('content-type', 'application/json');
        res.setHeader('content-disposition', `attachment; filename="${name}"`);
        return res.send(JSON.stringify(bundle, null, 2));
      } catch (err) {
        return res.status(500).json({ message: 'Export failed', detail: err.message });
      }
    }
  );

  // --- Retry failed analysis ---
  app.post(
    '/api/threat-library/reports/:publicId/retry',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        if (report.source_type === 'thib') {
          return res.status(400).json({ message: 'THIB imports do not use the AI analysis pipeline' });
        }

        // Idempotent: do not enqueue a second concurrent analysis for the same report.
        if (isActiveAnalysisStatus(report.analysis_status)) {
          const { rows: activeJobs } = await pool.query(
            `SELECT public_id, status, stage, progress, error_message, created_at
             FROM threat_library_jobs
             WHERE report_id = $1 AND status = ANY(ARRAY['queued','running'])
             ORDER BY id DESC LIMIT 1`,
            [report.id]
          );
          return res.status(202).json({
            report: publicReport(report),
            job_id: activeJobs[0]?.public_id || null,
            job: activeJobs[0] || null,
            already_running: true,
            code: 'analysis_already_running',
            resumed: true
          });
        }

        const { rows: activeJobs } = await pool.query(
          `SELECT public_id FROM threat_library_jobs
           WHERE report_id = $1 AND status = ANY(ARRAY['queued','running'])
           ORDER BY id DESC LIMIT 1`,
          [report.id]
        );
        if (activeJobs[0]) {
          // Job queued/running but report still terminal (race) — promote report to active.
          const candidateCount = await countReportCandidates(pool, report.id);
          const hasDocument = Boolean(report.canonical_document?.blocks?.length);
          const startStatus = resolveRetryStartStatus({ hasDocument, candidateCount });
          const progress = buildRetryProgress(startStatus, {
            candidate_extraction_version: report.analysis_progress?.candidate_extraction_version || null
          });
          const updated = await updateReportStatus(pool, report.id, {
            analysis_status: startStatus,
            import_status: 'processing',
            analysis_progress: progress,
            clear_failure: true,
            clear_cancel: true
          });
          return res.status(202).json({
            report: publicReport(await reportWithDetail(updated)),
            job_id: activeJobs[0].public_id,
            already_running: true,
            code: 'analysis_already_running',
            resumed: true
          });
        }

        const candidateCount = await countReportCandidates(pool, report.id);
        const hasDocument = Boolean(report.canonical_document?.blocks?.length);
        const startStatus = resolveRetryStartStatus({ hasDocument, candidateCount });
        const progress = buildRetryProgress(startStatus, {
          candidate_extraction_version: report.analysis_progress?.candidate_extraction_version || null
        });

        // Commit active status + clear stale failure BEFORE enqueue/202 so UI polling sees analyzing.
        const updated = await updateReportStatus(pool, report.id, {
          analysis_status: startStatus,
          import_status: 'processing',
          analysis_progress: progress,
          clear_failure: true,
          clear_cancel: true
        });

        const jobRow = await createJob(pool, {
          reportId: report.id,
          jobType: 'retry',
          requestedBy: (await actorOf(req))?.publicId
        });
        await updateJob(pool, jobRow.id, {
          status: 'queued',
          stage: startStatus,
          progress
        });
        await enqueueAnalyze(report.id, jobRow, {
          sourceUrl: report.source_url || undefined,
          resumeAnalysis: true,
          jobType: 'retry',
          // Keep analysis_run_id so completed chunks resume
          newAnalysisRun: req.body?.reset_checkpoints === true
        });
        return res.status(202).json({
          report: publicReport(await reportWithDetail(updated)),
          job_id: jobRow.public_id,
          job: {
            public_id: jobRow.public_id,
            status: 'queued',
            stage: startStatus,
            progress
          },
          resumed: true,
          already_running: false
        });
      } catch (err) {
        return res.status(500).json({ message: 'Retry failed', detail: err.message });
      }
    }
  );

  app.post(
    '/api/threat-library/reports/:publicId/cancel',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        const updated = await requestAnalysisCancel(pool, report.id);
        return res.json({
          ok: true,
          report: publicReport(await reportWithDetail(updated)),
          message: 'Cancel requested. The worker will stop at the next safe checkpoint.'
        });
      } catch (err) {
        return res.status(500).json({ message: 'Cancel failed', detail: err.message });
      }
    }
  );

  // --- Provenance: source URL (does not reanalyze) ---
  app.patch(
    '/api/threat-library/reports/:publicId',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        const body = req.body || {};
        const hasSourceUrl = Object.prototype.hasOwnProperty.call(body, 'source_url');
        const hasTlp = Object.prototype.hasOwnProperty.call(body, 'tlp');
        if (!hasSourceUrl && !hasTlp) {
          return res.status(400).json({ message: 'source_url or tlp is required' });
        }
        let parsed = null;
        if (hasSourceUrl) {
          parsed = validateReportSourceUrl(body.source_url);
          if (!parsed.ok) {
            return res.status(400).json({ message: parsed.message, code: parsed.error });
          }
        }
        let nextTlp = null;
        if (hasTlp) {
          const raw = String(body.tlp || '').trim().toLowerCase().replace(/^tlp:/, '').replace(/\+/g, '_').replace(/-/g, '_');
          const candidate = raw === 'white' ? 'clear' : raw;
          if (!isValidTlp(candidate)) {
            return res.status(400).json({
              message: `tlp must be one of: ${TLP_VALUES.join(', ')}`,
              code: 'invalid_tlp'
            });
          }
          nextTlp = candidate;
        }
        let updated = report;
        if (parsed) {
          updated = await updateReportSourceUrl(pool, report.id, parsed.value);
          if (!updated) return res.status(404).json({ message: 'Report not found' });
          await writeAudit(req, buildSourceUrlAuditEvent({
            report,
            oldUrl: report.source_url || null,
            newUrl: parsed.value,
            user: req.user
          }));
        }
        if (nextTlp) {
          const previousTlp = normalizeTlp(report.tlp);
          const previousSource = report.tlp_source || 'default';
          updated = await updateReportTlp(pool, report.id, nextTlp);
          if (!updated) return res.status(404).json({ message: 'Report not found' });
          await writeAudit(req, buildTlpAuditEvent({
            report,
            oldTlp: previousTlp,
            oldSource: previousSource,
            newTlp: nextTlp,
            user: req.user
          }));
        }
        return res.json({
          report: publicReport(await reportWithDetail(updated))
        });
      } catch (err) {
        return res.status(500).json({ message: 'Failed to update report', detail: err.message });
      }
    }
  );

  // --- Report tags (campaign / threat context, inherited by linked IOCs at read time) ---
  async function reportTagMutation(req, res, { added }) {
    const report = await getReportByPublicId(pool, req.params.publicId);
    if (!report) return res.status(404).json({ message: 'Report not found' });
    const tagId = added ? req.body?.tag_id : req.params.tagId;
    const tag = await findEnabledTag(pool, tagId);
    if (!tag) {
      if (added) return res.status(404).json({ message: 'Tag not found or disabled', code: 'tag_not_found' });
      // Removing a tag that is not (or no longer) assigned is a no-op.
      return res.json({ changed: false, tags: await loadReportTags(pool, report.id) });
    }
    const changed = added
      ? await addReportTag(pool, report.id, tag.id)
      : await removeReportTag(pool, report.id, tag.id);
    if (changed) {
      const inheritingIocCount = await countReportTagInheritingIocs(
        pool,
        report.id,
        reportTagInheritanceEligibleSql('c', 'r')
      );
      await writeAudit(req, buildReportTagAuditEvent({ report, tag, added, inheritingIocCount, user: req.user }));
    }
    return res.json({ changed, tags: await loadReportTags(pool, report.id) });
  }

  app.post(
    '/api/threat-library/reports/:publicId/tags',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        return await reportTagMutation(req, res, { added: true });
      } catch (err) {
        return res.status(500).json({ message: 'Failed to add report tag', detail: err.message });
      }
    }
  );

  app.delete(
    '/api/threat-library/reports/:publicId/tags/:tagId',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      try {
        return await reportTagMutation(req, res, { added: false });
      } catch (err) {
        return res.status(500).json({ message: 'Failed to remove report tag', detail: err.message });
      }
    }
  );

  // --- IOC: tags inherited from Threat Library reports (IOC Details "Threat Context" tags) ---
  // Same artifact scope and eligibility as effective tags in search / MCP / REST.
  app.get('/api/ioc/:id/tags/threat-library', async (req, res) => {
    try {
      const iocId = Number(req.params.id);
      if (!Number.isInteger(iocId) || iocId <= 0) {
        return res.status(400).json({ message: 'Invalid IOC id' });
      }
      const scope = await resolveArtifactScopedIocIds(pool, iocId);
      const rows = await loadInheritedReportTagRows(pool, scope.length ? scope : [iocId]);
      const grouped = groupInheritedTagsBySeed(rows, new Map([[iocId, scope.length ? scope : [iocId]]]));
      return res.json({ items: grouped.get(iocId) || [] });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load Threat Library tags', detail: err.message });
    }
  });

  // --- Delete ---
  app.delete(
    '/api/threat-library/reports/:publicId',
    requireRole(ROLES.ADMIN),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        await deleteThreatReport(pool, report.id);
        // Snapshot the report identity: the row is gone, the audit must stand alone.
        await writeAudit(req, buildDeleteAuditEvent({ report, user: req.user }));
        return res.json({ ok: true });
      } catch (err) {
        return res.status(500).json({ message: 'Delete failed', detail: err.message });
      }
    }
  );

  // --- IOC Threat Context ---
  app.get('/api/ioc/:id/threat-context', async (req, res) => {
    try {
      const iocId = Number(req.params.id);
      if (!Number.isFinite(iocId) || iocId <= 0) {
        return res.status(400).json({ message: 'Invalid IOC id' });
      }
      // Same serializer as MCP get_ioc_context.threat_context — one canonical shape.
      return res.json(await loadIocThreatContext(pool, iocId));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load threat context', detail: err.message });
    }
  });
}
