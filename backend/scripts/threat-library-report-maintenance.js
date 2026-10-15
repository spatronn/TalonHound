#!/usr/bin/env node
/**
 * Targeted Threat Library maintenance for ONE report, through the same
 * lifecycle code the UI actions use. Dry-run by default (read-only database
 * session); pass --apply to write. Idempotent.
 *
 *   dismiss-source      Dismiss one IOC Source of the report (UI "Dismiss").
 *                       Refused unless the source is still pending review and
 *                       has produced nothing: no files, no extracted
 *                       candidates. Writes the standard dismissed audit event.
 *
 *   refresh-extraction  Queue a Refresh extraction exactly like the UI action
 *                       (claim the report, create the job, dispatch to the
 *                       Threat Library worker) and wait for its result. The
 *                       dry-run prints what the refresh would change: title,
 *                       candidate identities, Indicators, entity links,
 *                       summary. Analyst state is kept by the refresh itself.
 *
 *   node scripts/threat-library-report-maintenance.js dismiss-source --report <uuid> --source <uuid> [--apply] [--reason "..."]
 *   node scripts/threat-library-report-maintenance.js refresh-extraction --report <uuid> [--apply]
 *       [--accept-membership-changes --reason "..." [--preview-fingerprint <sha256 from a dry-run>]]
 *
 *                       The dry-run includes the membership guard verdict
 *                       (refreshMembershipGuard.js). A refresh whose diff is a
 *                       material Indicator loss is blocked by the worker unless
 *                       --accept-membership-changes is given with a reason
 *                       (recorded in the job dispatch and the audit event).
 */

import '../lib/ensure-db-password.js';
import pg from 'pg';
import { AUDIT_ACTION, AUDIT_SEVERITY, AUDIT_STATUS } from '../lib/auditConstants.js';
import { createAuditLogService } from '../lib/auditLogService.js';
import { reportAuditEntity, reportAuditSnapshot } from '../lib/threatLibrary/audit.js';
import {
  claimReportForMaintenance,
  createJob,
  getReportByPublicId,
  loadReportCandidateRows,
  loadReportEntityLinks,
  restoreReportStatus,
  updateJob
} from '../lib/threatLibrary/store.js';
import { getIocSourceByPublicId, transitionSource } from '../lib/threatLibrary/iocSources/store.js';
import { canDismiss } from '../lib/threatLibrary/iocSources/sourceState.js';
import {
  evaluateMaintenanceAction,
  MAINTENANCE_ALLOWED_STATUSES,
  THREAT_LIBRARY_JOB_MODES
} from '../lib/threatLibrary/jobModes.js';
import {
  computeExtractionRefresh,
  guardExtractionRefresh,
  linkedRowsLeavingDocument,
  membershipGuardSummary
} from '../lib/threatLibrary/extractionRefresh.js';

/** Fingerprint of the plan's material losses (the acceptance binds to it). */
function buildPlanFingerprint(report, previousRows, refreshed, linkedCandidateIds) {
  return guardExtractionRefresh(report, previousRows, refreshed, null, { linkedCandidateIds }).diff.material_fingerprint;
}
import {
  REFRESH_GUARD_THRESHOLDS,
  REFRESH_MEMBERSHIP_POLICIES,
  compactRefreshMembershipDiff
} from '../lib/threatLibrary/refreshMembershipGuard.js';
import {
  hasUsableDocument,
  isDocumentContractCurrent,
  rebuildDocumentFromRetainedSource,
  reselectReportTitle
} from '../lib/threatLibrary/extractionStages.js';
import { groundStoredPublisherEntities } from '../lib/threatLibrary/publisherEntityGrounding.js';
import { groundStoredVulnerabilities } from '../lib/threatLibrary/vulnerabilityGrounding.js';
import { isReportIndicatorMember } from '../lib/threatLibrary/indicatorMembership.js';

const MAINTENANCE_ACTOR = Object.freeze({
  actorUsername: 'system:threat-library-maintenance',
  actorEmail: null,
  actorRole: 'system'
});

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  const opt = (name) => {
    const i = rest.indexOf(`--${name}`);
    return i >= 0 ? rest[i + 1] : null;
  };
  return {
    command,
    apply: rest.includes('--apply'),
    report: opt('report'),
    source: opt('source'),
    reason: opt('reason') || 'Not an IOC dataset: ordinary site link (automatic IOC Source discovery retired)',
    explicitReason: opt('reason'),
    previewFingerprint: opt('preview-fingerprint'),
    acceptMembershipChanges: rest.includes('--accept-membership-changes'),
    timeoutMs: Number(opt('timeout-ms') || 600_000)
  };
}

function connectionConfig(readOnly) {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    max: 3,
    ...(readOnly ? { options: '-c default_transaction_read_only=on' } : {})
  };
}

/**
 * Preconditions for dismissing a source without touching anything it produced.
 * Pure. Returns the list of violated preconditions (empty = safe).
 */
export function dismissPreconditions({ source, reportId, fileCount, linkCount }) {
  const problems = [];
  if (!source) return ['source_not_found'];
  if (Number(source.report_id) !== Number(reportId)) problems.push('source_belongs_to_another_report');
  if (String(source.lifecycle_status) === 'dismissed') return ['already_dismissed'];
  if (!canDismiss(source.lifecycle_status)) problems.push(`lifecycle_${source.lifecycle_status}_not_dismissable`);
  if (['running', 'succeeded'].includes(String(source.extraction_status))) problems.push(`extraction_${source.extraction_status}`);
  if (fileCount > 0) problems.push(`has_${fileCount}_source_files`);
  if (linkCount > 0) problems.push(`has_${linkCount}_extracted_candidate_links`);
  return problems;
}

async function dismissSource(pool, args) {
  const report = await getReportByPublicId(pool, args.report);
  if (!report) throw new Error(`report ${args.report} not found`);
  const source = await getIocSourceByPublicId(pool, args.source);
  const counts = source
    ? (await pool.query(
      `SELECT
         (SELECT COUNT(*)::int FROM threat_report_ioc_source_files WHERE source_id = $1) AS files,
         (SELECT COUNT(*)::int FROM threat_report_candidate_source_links WHERE source_id = $1) AS links`,
      [source.id]
    )).rows[0]
    : { files: 0, links: 0 };
  const problems = dismissPreconditions({ source, reportId: report.id, fileCount: counts.files, linkCount: counts.links });
  const snapshot = source && {
    source_public_id: source.public_id,
    canonical_url: source.canonical_url,
    discovery_method: source.discovery_method,
    lifecycle_status: source.lifecycle_status,
    inspection_status: source.inspection_status,
    extraction_status: source.extraction_status,
    files: counts.files,
    extracted_candidate_links: counts.links
  };
  if (problems.includes('already_dismissed')) return { action: 'noop', reason: 'already_dismissed', source: snapshot };
  if (problems.length) return { action: 'refused', problems, source: snapshot };
  if (!args.apply) return { action: 'would_dismiss', source: snapshot };

  const updated = await transitionSource(pool, source, 'dismiss', { dismissed_by: null });
  await createAuditLogService(pool).auditLog({
    ...MAINTENANCE_ACTOR,
    action: AUDIT_ACTION.THREAT_LIBRARY_IOC_SOURCE_DISMISSED,
    ...reportAuditEntity(report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    source: 'maintenance_script',
    before: { lifecycle_status: source.lifecycle_status },
    after: { lifecycle_status: updated?.lifecycle_status || 'dismissed' },
    metadata: {
      ...reportAuditSnapshot(report),
      ...snapshot,
      reason: args.reason,
      initiated_by: MAINTENANCE_ACTOR.actorUsername
    }
  });
  return { action: 'dismissed', source: { ...snapshot, lifecycle_status: updated?.lifecycle_status } };
}

const key = (c) => `${c.candidate_type}\u0000${c.normalized_value}`;
const show = (k) => k.replace('\u0000', ':');

/**
 * Membership policy for a refresh run from CLI flags (protect unless the
 * operator explicitly accepts with a reason).
 */
export function refreshMembershipPolicyFromArgs(args) {
  if (!args.acceptMembershipChanges) return { ok: true, policy: null };
  const reason = String(args.explicitReason || '').trim();
  if (reason.length < REFRESH_GUARD_THRESHOLDS.acceptanceReasonMinChars) {
    return { ok: false, code: 'acceptance_reason_missing' };
  }
  return {
    ok: true,
    policy: {
      mode: REFRESH_MEMBERSHIP_POLICIES.ACCEPT,
      reason,
      // Pinned to a reviewed dry-run when given; else bound to the plan computed
      // right before dispatch (the worker re-checks it either way).
      preview_fingerprint: args.previewFingerprint || null,
      // Must equal extractionRefresh.MAINTENANCE_CLI_ACTOR (the worker resolves it to `system`).
      requested_by: MAINTENANCE_ACTOR.actorUsername,
      requested_at: new Date().toISOString()
    }
  };
}

async function planRefresh(pool, report, membershipPolicy = null) {
  let document = report.canonical_document;
  let documentRebuilt = false;
  if (!hasUsableDocument(document)) return { refusable: 'refresh_document_missing' };
  if (!isDocumentContractCurrent(report, document)) {
    const rebuilt = await rebuildDocumentFromRetainedSource(pool, report);
    if (!rebuilt) return { refusable: 'refresh_source_unavailable' };
    document = rebuilt.document;
    documentRebuilt = true;
  }
  const title = await reselectReportTitle(pool, report, { document });
  document = title.document;
  const previousRows = await loadReportCandidateRows(pool, report.id);
  const refreshed = await computeExtractionRefresh(pool, { report, document, previousRows, documentRebuilt });
  const linkedCandidateIds = await linkedRowsLeavingDocument(pool, previousRows, refreshed.candidates);
  const before = new Map(previousRows.map((r) => [key(r), r]));
  const after = new Map(refreshed.candidates.map((c) => [key(c), c]));
  const indicators = (rows) => rows.filter((r) => isReportIndicatorMember(r)).map(key).sort();
  const beforeIndicators = indicators(previousRows);
  const afterIndicators = indicators(refreshed.candidates);
  const entities = await loadReportEntityLinks(pool, report.id);
  const vuln = groundStoredVulnerabilities({ summary: report.summary ?? null, entities }, refreshed.document);
  const publisher = groundStoredPublisherEntities(
    { summary: vuln.summary_changed ? vuln.summary : report.summary ?? null, entities },
    { report, document: refreshed.document }
  );
  const analystRows = previousRows.filter((r) => r.review_status && r.review_status !== 'pending');
  const policy = membershipPolicy && !membershipPolicy.preview_fingerprint
    ? { ...membershipPolicy, preview_fingerprint: buildPlanFingerprint(report, previousRows, refreshed, linkedCandidateIds) }
    : membershipPolicy;
  // The CLI operator (server shell) accepts as `system`, exactly as the worker resolves it.
  const { diff, guard } = guardExtractionRefresh(report, previousRows, refreshed, policy, { linkedCandidateIds, acceptorRole: policy ? 'system' : null });
  const compactDiff = compactRefreshMembershipDiff(diff);
  return {
    document_rebuilt: documentRebuilt,
    membership_guard: membershipGuardSummary(guard, compactDiff),
    membership_diff: compactDiff,
    title: { current: report.title, next: title.changed ? title.title : report.title, changed: title.changed, source: title.source || null },
    candidates: {
      before: previousRows.length,
      after: refreshed.candidates.length,
      added: [...after.keys()].filter((k) => !before.has(k)).map(show),
      removed: [...before.keys()].filter((k) => !after.has(k)).map(show)
    },
    indicators: {
      before: beforeIndicators.length,
      after: afterIndicators.length,
      unchanged: JSON.stringify(beforeIndicators) === JSON.stringify(afterIndicators)
    },
    analyst_reviewed_rows: analystRows.map((r) => ({ identity: show(key(r)), review_status: r.review_status, kept: after.has(key(r)) })),
    entity_links_to_unlink: [...vuln.entity_ids_removed, ...publisher.entity_ids_removed],
    publisher_entities_removed: publisher.entities_removed,
    summary: {
      changed: vuln.summary_changed || publisher.summary_changed,
      next: publisher.summary_changed ? publisher.summary : vuln.summary_changed ? vuln.summary : report.summary
    }
  };
}

async function waitForJob(pool, jobId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const { rows } = await pool.query(`SELECT status, stage, error_message, progress FROM threat_library_jobs WHERE id = $1`, [jobId]);
    const job = rows[0];
    if (job && ['completed', 'failed', 'cancelled'].includes(job.status)) return job;
    if (Date.now() > deadline) return { ...job, status: 'timeout' };
    await new Promise((r) => setTimeout(r, 1000));
  }
}

async function refreshExtraction(pool, args) {
  const report = await getReportByPublicId(pool, args.report);
  if (!report) throw new Error(`report ${args.report} not found`);
  const mode = THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION;
  const gate = evaluateMaintenanceAction(report, mode);
  if (!gate.ok) return { action: 'refused', code: gate.code, message: gate.message };
  const { rows: active } = await pool.query(
    `SELECT id FROM threat_library_jobs WHERE report_id = $1 AND status = ANY(ARRAY['queued','running']) LIMIT 1`,
    [report.id]
  );
  if (active[0]) return { action: 'refused', code: 'analysis_already_running' };
  const policy = refreshMembershipPolicyFromArgs(args);
  if (!policy.ok) return { action: 'refused', code: policy.code };
  const plan = await planRefresh(pool, report, policy.policy);
  if (plan.refusable) return { action: 'refused', code: plan.refusable };
  if (policy.policy && args.previewFingerprint && args.previewFingerprint !== plan.membership_diff?.material_fingerprint) {
    return { action: 'refused', code: 'preview_stale', plan };
  }
  const dispatchPolicy = policy.policy
    ? { ...policy.policy, preview_fingerprint: args.previewFingerprint || plan.membership_diff?.material_fingerprint || null }
    : null;
  if (!args.apply) return { action: 'would_refresh', plan };

  // Same sequence as POST /reports/:id/refresh-extraction (acceptMaintenanceJob).
  await import('../lib/ensure-redis-password.js');
  const { default: IORedis } = await import('ioredis');
  const { Queue } = await import('bullmq');
  const { getRedisUrl } = await import('../lib/redis-url.js');
  const { getThreatLibraryQueueName } = await import('../lib/threatLibrary/queueConfig.js');
  const { dispatchQueuedThreatLibraryAnalyses, enqueueClaimedThreatLibraryJob } = await import('../lib/threatLibrary/analysisConcurrency.js');
  const redis = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
  const queue = new Queue(getThreatLibraryQueueName(), { connection: redis });
  const restoreStatus = { analysis_status: report.analysis_status, import_status: report.import_status };
  const progress = { stage: 'pending', mode, requested_at: new Date().toISOString() };
  try {
    const claimed = await claimReportForMaintenance(pool, report.id, {
      allowedStatuses: MAINTENANCE_ALLOWED_STATUSES[mode],
      analysisProgress: progress
    });
    if (!claimed) return { action: 'refused', code: 'analysis_already_running' };
    let jobRow = null;
    try {
      jobRow = await createJob(pool, { reportId: report.id, jobType: mode, requestedBy: null });
      await updateJob(pool, jobRow.id, { status: 'queued', stage: 'queued', progress: { ...progress, dispatch: { jobType: mode, restoreStatus, ...(dispatchPolicy ? { membershipPolicy: dispatchPolicy } : {}) } } });
      await dispatchQueuedThreatLibraryAnalyses(pool, { enqueue: (job) => enqueueClaimedThreatLibraryJob(queue, job) });
    } catch (err) {
      if (jobRow) await updateJob(pool, jobRow.id, { status: 'failed', stage: 'queued', error_message: 'dispatch_failed' }).catch(() => {});
      await restoreReportStatus(pool, report.id, restoreStatus, report.analysis_progress || {}).catch(() => {});
      throw err;
    }
    const job = await waitForJob(pool, jobRow.id, args.timeoutMs);
    return { action: 'refreshed', job_id: jobRow.public_id, status: job.status, refresh: job.progress?.refresh || null, error: job.error_message || null, plan };
  } finally {
    await queue.close().catch(() => {});
    redis.disconnect();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.report || !['dismiss-source', 'refresh-extraction'].includes(args.command)) {
    console.error('usage: threat-library-report-maintenance.js <dismiss-source|refresh-extraction> --report <uuid> [--source <uuid>] [--apply]');
    process.exit(2);
  }
  const pool = new pg.Pool(connectionConfig(!args.apply));
  try {
    const result = args.command === 'dismiss-source'
      ? await dismissSource(pool, args)
      : await refreshExtraction(pool, args);
    console.log(JSON.stringify({ mode: args.apply ? 'apply' : 'dry-run', command: args.command, report: args.report, ...result }, null, 2));
  } finally {
    await pool.end();
  }
}

const invokedDirectly = process.argv[1] && /threat-library-report-maintenance\.js$/.test(process.argv[1]);
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
