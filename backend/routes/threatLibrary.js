/**
 * Threat Library HTTP routes.
 */

import multer from 'multer';
import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { registerRouteModule } from '../lib/routeRegistry.js';
import { PDF_MAX_BYTES, THIB_MAX_BYTES, normalizeTlp, TLP_DISPLAY } from '../lib/threatLibrary/constants.js';
import { validateThreatLibraryUrl } from '../lib/threatLibrary/urlIngest.js';
import { validatePdfBuffer } from '../lib/threatLibrary/pdfIngest.js';
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
  deleteThreatReport,
  createJob,
  updateJob,
  insertArtifact,
  getIocThreatContext
} from '../lib/threatLibrary/store.js';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: Math.max(PDF_MAX_BYTES, THIB_MAX_BYTES), files: 1 }
});

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
    published_at: row.published_at,
    language: row.language,
    tlp: row.tlp,
    tlp_display: TLP_DISPLAY[row.tlp] || `TLP:${String(row.tlp || '').toUpperCase()}`,
    confidence: row.confidence,
    report_type: row.report_type,
    summary: row.summary,
    import_status: row.import_status,
    analysis_status: row.analysis_status,
    failure_stage: row.failure_stage,
    failure_reason: row.failure_reason,
    candidate_summary: row.candidate_summary || {},
    indicator_count: row.indicator_count,
    matched_count: row.matched_count,
    entity_count: row.entity_count,
    created_at: row.created_at,
    updated_at: row.updated_at,
    finalized_at: row.finalized_at
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function, auditFailure?: Function }} audit
 * @param {{ threatLibraryQueue?: import('bullmq').Queue }} deps
 */
export function registerThreatLibraryRoutes(app, pool, audit, deps = {}) {
  registerRouteModule('threat_library');

  const queue = deps.threatLibraryQueue || null;

  async function enqueueAnalyze(reportId, jobRow, extra = {}) {
    if (!queue) {
      const err = new Error('Threat Library queue unavailable');
      err.code = 'queue_unavailable';
      throw err;
    }
    const job = await queue.add(
      'analyze',
      { reportId, jobId: jobRow.id, ...extra },
      getThreatLibraryJobOptions()
    );
    await updateJob(pool, jobRow.id, { bullmq_job_id: String(job.id) });
    return job;
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
          // Allow ollama without ack; require ack for external-ish providers when enabling
          if ((body.provider || current?.provider) !== 'ollama') {
            return res.status(400).json({
              message:
                'Acknowledge that report content may be sent to the configured external AI provider before enabling.'
            });
          }
        }
      }
      const updated = await updateAiSettings(pool, body, req.user?.publicId);
      await audit.auditSuccess({
        action: AUDIT_ACTION.THREAT_LIBRARY_AI_SETTINGS_UPDATED || 'threat_library.ai_settings.updated',
        entityType: AUDIT_ENTITY.SYSTEM || 'system',
        severity: AUDIT_SEVERITY.WARNING,
        actor: req.user,
        after: {
          enabled: updated.enabled,
          provider: updated.provider,
          model: updated.model,
          api_key_updated: Boolean(body.api_key)
        }
      });
      return res.json({ settings: maskAiSettingsForClient(updated) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update AI settings', detail: err.message });
    }
  });

  app.delete('/api/threat-library/ai-settings/api-key', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const updated = await clearAiApiKey(pool, req.user?.publicId);
      return res.json({ settings: maskAiSettingsForClient(updated) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to clear API key', detail: err.message });
    }
  });

  // --- List / detail ---
  app.get('/api/threat-library/reports', async (req, res) => {
    try {
      const result = await listThreatReports(pool, {
        limit: req.query.limit,
        offset: req.query.offset
      });
      return res.json({
        items: result.items.map(publicReport),
        total: result.total
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
      return res.json({
        report: publicReport(snap.report),
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
          review_status: c.review_status,
          match_state: c.match_state,
          matched_ioc_id: c.matched_ioc_id,
          matched_ioc_observable_type: c.matched_ioc_observable_type
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
        report: publicReport(report),
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

      const report = await createThreatReport(pool, {
        title: policy.parsed.hostname || 'URL report',
        source_type: 'url',
        source_url: policy.url,
        source_name: policy.parsed.hostname,
        tlp: normalizeTlp(req.body?.tlp || 'clear'),
        created_by: req.user?.publicId
      });
      const jobRow = await createJob(pool, {
        reportId: report.id,
        jobType: 'analyze',
        requestedBy: req.user?.publicId
      });
      await enqueueAnalyze(report.id, jobRow, { sourceUrl: policy.url });

      await audit.auditSuccess({
        action: 'threat_library.import.url',
        entityType: 'threat_report',
        entityId: report.public_id,
        severity: AUDIT_SEVERITY.INFO,
        actor: req.user,
        after: { source_type: 'url', host: policy.parsed.hostname }
      });

      return res.status(202).json({ report: publicReport(report), job_id: jobRow.public_id });
    } catch (err) {
      return res.status(500).json({ message: 'URL import failed', detail: err.message });
    }
  });

  // --- PDF import ---
  app.post(
    '/api/threat-library/import/pdf',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    upload.single('file'),
    async (req, res) => {
      try {
        const file = req.file;
        if (!file?.buffer) return res.status(400).json({ message: 'PDF file is required' });
        if (file.mimetype && file.mimetype !== 'application/pdf' && !file.originalname?.toLowerCase().endsWith('.pdf')) {
          return res.status(400).json({ message: 'Only application/pdf uploads are allowed' });
        }
        const validation = validatePdfBuffer(file.buffer, { fileName: file.originalname });
        if (!validation.ok) return res.status(400).json({ message: validation.error });

        const report = await createThreatReport(pool, {
          title: validation.fileName.replace(/\.pdf$/i, ''),
          source_type: 'pdf',
          source_file_name: validation.fileName,
          source_sha256: validation.sha256,
          source_name: validation.fileName,
          tlp: normalizeTlp(req.body?.tlp || 'clear'),
          created_by: req.user?.publicId
        });

        const stored = await storeArtifactBuffer(report.id, file.buffer, {
          fileName: validation.fileName,
          ext: '.pdf'
        });
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
          requestedBy: req.user?.publicId
        });
        await enqueueAnalyze(report.id, jobRow);

        await audit.auditSuccess({
          action: 'threat_library.import.pdf',
          entityType: 'threat_report',
          entityId: report.public_id,
          severity: AUDIT_SEVERITY.INFO,
          actor: req.user,
          after: { source_type: 'pdf', sha256: validation.sha256, size_bytes: validation.sizeBytes }
        });

        return res.status(202).json({ report: publicReport(report), job_id: jobRow.public_id });
      } catch (err) {
        return res.status(500).json({ message: 'PDF import failed', detail: err.message });
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
        const result = await importThibBundle(pool, raw, {
          createdBy: req.user?.publicId,
          conflictMode: req.body?.conflict_mode || 'keep_both'
        });
        if (!result.ok) return res.status(400).json(result);
        await audit.auditSuccess({
          action: 'threat_library.import.thib',
          entityType: 'threat_report',
          entityId: result.report?.public_id,
          severity: AUDIT_SEVERITY.INFO,
          actor: req.user,
          after: {
            already_imported: result.already_imported === true,
            summary: result.summary || null
          }
        });
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
          user: req.user,
          audit
        });
        if (!result.ok) return res.status(result.status || 400).json({ message: result.error });
        return res.json(result);
      } catch (err) {
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
        await finalizeReport(pool, report.id);
        const updated = await getReportByPublicId(pool, req.params.publicId);
        return res.json({ report: publicReport(updated) });
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
        const jobRow = await createJob(pool, {
          reportId: report.id,
          jobType: 'retry',
          requestedBy: req.user?.publicId
        });
        await enqueueAnalyze(report.id, jobRow, {
          sourceUrl: report.source_url || undefined
        });
        return res.status(202).json({ report: publicReport(report), job_id: jobRow.public_id });
      } catch (err) {
        return res.status(500).json({ message: 'Retry failed', detail: err.message });
      }
    }
  );

  // --- Delete ---
  app.delete(
    '/api/threat-library/reports/:publicId',
    requireRole(ROLES.ADMIN),
    async (req, res) => {
      try {
        const report = await getReportByPublicId(pool, req.params.publicId);
        if (!report) return res.status(404).json({ message: 'Report not found' });
        await deleteThreatReport(pool, report.id);
        await audit.auditSuccess({
          action: 'threat_library.report.deleted',
          entityType: 'threat_report',
          entityId: report.public_id,
          severity: AUDIT_SEVERITY.WARNING,
          actor: req.user,
          before: { title: report.title, source_type: report.source_type }
        });
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
      const ctx = await getIocThreatContext(pool, iocId);
      return res.json({
        claims: ctx.claims.map((c) => ({
          role: c.role,
          assessment: c.assessment,
          confidence: c.confidence,
          evidence_text: c.evidence_text,
          section: c.section,
          page_number: c.page_number,
          report: {
            id: c.report_public_id,
            title: c.report_title,
            published_at: c.published_at,
            tlp: c.tlp,
            tlp_display: TLP_DISPLAY[c.tlp] || c.tlp,
            source_name: c.source_name,
            source_type: c.source_type
          }
        })),
        relationships: ctx.relationships
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load threat context', detail: err.message });
    }
  });
}
