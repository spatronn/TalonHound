/**
 * Threat Library URL import — the single application-layer operation behind
 * Import Intelligence → URL → Start Import (POST /api/threat-library/import/url)
 * and the MCP tool threat_library_import_url.
 *
 * URL policy (scheme, SSRF host/IP rules, embedded credentials) → canonical URL
 * identity → claimReportImport (advisory-locked duplicate check BEFORE any
 * report, job or queue entry exists) → report row + `analyze` job → analysis
 * slot dispatch. Fetching, extraction and AI analysis happen only in
 * threat-library-worker, which re-applies the SSRF policy on every redirect hop
 * with DNS pinning. Nothing here fetches, parses or reviews anything.
 */

import { validateThreatLibraryUrl } from './urlIngest.js';
import { canonicalizeReportUrl, claimReportImport } from './importIdentity.js';
import { createThreatReport, createJob, updateJob } from './store.js';
import { normalizeTlp } from './constants.js';
import { buildImportAuditEvent, buildImportFailedAuditEvent, safeErrorCategory } from './audit.js';
import { dispatchQueuedThreatLibraryAnalyses, enqueueClaimedThreatLibraryJob } from './analysisConcurrency.js';

export const URL_IMPORT_OUTCOMES = Object.freeze({
  INVALID_URL: 'invalid_url',
  ALREADY_IMPORTED: 'already_imported',
  QUEUED: 'queued'
});

/**
 * Persist the job as queued, then claim up to the configured AI concurrency
 * slots. Returns without waiting for a slot.
 * @param {import('pg').Pool} pool
 * @param {import('bullmq').Queue|null} queue
 * @param {{ id: number }} jobRow
 * @param {object} [extra] dispatch payload stored on the job
 * @param {object|null} [progress]
 */
export async function scheduleThreatLibraryAnalysis(pool, queue, jobRow, extra = {}, progress = null) {
  if ((extra && Object.keys(extra).length) || progress) {
    await updateJob(pool, jobRow.id, {
      status: 'queued',
      stage: 'queued',
      progress: { ...(progress || {}), dispatch: extra }
    });
  }
  if (!queue) {
    const err = new Error('Threat Library queue unavailable');
    err.code = 'queue_unavailable';
    throw err;
  }
  return dispatchQueuedThreatLibraryAnalyses(pool, {
    enqueue: (job) => enqueueClaimedThreatLibraryJob(queue, job)
  });
}

function hostOf(raw) {
  try {
    return new URL(String(raw || '')).hostname;
  } catch {
    return null;
  }
}

/**
 * @param {{
 *   pool: import('pg').Pool,
 *   queue: import('bullmq').Queue|null,
 *   writeAudit: (event: object) => Promise<void>,
 *   resolveActor: () => Promise<object|null>
 * }} deps
 * @param {{
 *   url: unknown,
 *   tlp?: string|null,
 *   principal?: object|null,
 *   auditDetails?: object
 * }} input `principal` = request user (failure audit); `auditDetails` = extra
 *   provenance merged into the import audit metadata (e.g. MCP key identity).
 * @returns {Promise<
 *   { outcome: 'invalid_url', message: string }
 *   | { outcome: 'already_imported', duplicateReason: 'url', report: object, sourceUrl: string, canonicalUrl: string }
 *   | { outcome: 'queued', report: object, job: object, sourceUrl: string, canonicalUrl: string }
 * >} Internal failures are audited (threat_library.report.import_failed) and rethrown.
 */
export async function importThreatLibraryUrl(deps, input = {}) {
  const { pool, queue, writeAudit, resolveActor } = deps;
  const extraDetails = input.auditDetails && typeof input.auditDetails === 'object' ? input.auditDetails : {};
  const url = String(input.url || '').trim();
  try {
    const policy = validateThreatLibraryUrl(url);
    if (!policy.ok) return { outcome: URL_IMPORT_OUTCOMES.INVALID_URL, message: policy.error };

    const canonicalUrl = canonicalizeReportUrl(policy.url);
    if (!canonicalUrl) {
      return { outcome: URL_IMPORT_OUTCOMES.INVALID_URL, message: 'URL must be a valid http or https URL' };
    }

    const actor = await resolveActor();
    // Duplicate check BEFORE any report row, job or queue entry exists: a
    // URL already in the library is never fetched or analysed again.
    const claim = await claimReportImport(pool, { kind: 'url', key: canonicalUrl }, (db) => createThreatReport(db, {
      title: policy.parsed.hostname || 'URL report',
      source_type: 'url',
      source_url: policy.url,
      source_url_canonical: canonicalUrl,
      source_name: policy.parsed.hostname,
      tlp: normalizeTlp(input.tlp || 'clear'),
      // A TLP supplied with the import request is an analyst assertion.
      tlp_source: input.tlp ? 'manual' : 'default',
      created_by: actor?.publicId
    }));
    if (claim.duplicate) {
      await writeAudit(buildImportAuditEvent({
        sourceType: 'url',
        report: claim.report,
        user: actor,
        details: {
          source_url: policy.url,
          host: policy.parsed.hostname,
          already_imported: true,
          duplicate_reason: 'url',
          ...extraDetails
        }
      }));
      return {
        outcome: URL_IMPORT_OUTCOMES.ALREADY_IMPORTED,
        duplicateReason: 'url',
        report: claim.report,
        sourceUrl: policy.url,
        canonicalUrl
      };
    }

    const report = claim.report;
    const jobRow = await createJob(pool, {
      reportId: report.id,
      jobType: 'analyze',
      requestedBy: actor?.publicId
    });
    await scheduleThreatLibraryAnalysis(pool, queue, jobRow, { sourceUrl: policy.url, jobType: 'analyze' });

    await writeAudit(buildImportAuditEvent({
      sourceType: 'url',
      report,
      user: actor,
      jobPublicId: jobRow.public_id,
      details: { source_url: policy.url, host: policy.parsed.hostname, ...extraDetails }
    }));

    return { outcome: URL_IMPORT_OUTCOMES.QUEUED, report, job: jobRow, sourceUrl: policy.url, canonicalUrl };
  } catch (err) {
    await writeAudit(buildImportFailedAuditEvent({
      sourceType: 'url',
      user: input.principal || null,
      code: safeErrorCategory(err),
      details: { host: hostOf(input.url), ...extraDetails }
    })).catch(() => {});
    throw err;
  }
}
