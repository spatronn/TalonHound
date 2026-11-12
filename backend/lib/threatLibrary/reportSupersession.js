/**
 * Logical-report supersession for Threat Library reports: reading it (detail
 * API, MCP, write guards) and the explicit, audited reconciliation of two
 * EXISTING reports of one publisher article.
 *
 * Supersession is non-destructive. `threat_reports.superseded_by_report_id`
 * points a duplicate at its primary; the duplicate keeps every row it owns
 * (candidates and their review state, entities, relationships, tags,
 * artifacts, jobs, extraction runs, audit). Listings, the IOC threat context
 * and report-tag inheritance read only primaries; the duplicate's public id
 * stays resolvable and names its primary.
 *
 * Reconciliation never merges or copies intelligence. It refuses (and writes
 * nothing) unless the duplicate is provably redundant for everything that
 * carries an analyst obligation or reaches IOCs:
 *   - a shared, proven source identity key (redirect / corroborated canonical
 *     / WordPress post id / submitted URL) — titles, dates, IOC sets are never
 *     identity evidence;
 *   - every IOC the duplicate links (matched_ioc_id) is linked by the primary;
 *   - every duplicate candidate exists on the primary (type + value), and any
 *     non-pending analyst decision on the duplicate equals the primary's;
 *   - every duplicate relationship exists on the primary;
 *   - the duplicate has no attached / extracted linked IOC Sources;
 *   - the duplicate is not finalized while the primary is not;
 *   - neither report has a queued / running job.
 * AI-derived context that only the duplicate has (entities, report tags) is
 * NOT copied into the primary (no silent combination); it is listed in the
 * supersession record and stays readable on the duplicate.
 */

import { readArtifactBuffer } from './artifactStore.js';
import { lockIdentityKeys, recordIdentityKeys, resolvePrimaryReport } from './importIdentity.js';
import { resolveSourceIdentity } from './sourceIdentity.js';
import { markReportSuperseded } from './sourceIdentityClaim.js';
import { AUDIT_ACTION, AUDIT_SEVERITY, AUDIT_STATUS } from '../auditConstants.js';
import { reportAuditEntity, reportAuditSnapshot } from './audit.js';

const DECIDED_REVIEW_STATUSES = new Set(['approved', 'created_ioc', 'ignored', 'context_only', 'rejected']);
const LIVE_IOC_SOURCE_STATUSES = new Set(['attached', 'extracting', 'extracted']);

/**
 * Reports in one logical group: the primary and every report superseded
 * (transitively) into it.
 * @param {{ query: Function }} db
 * @param {number} primaryId
 */
async function loadSupersessionGroup(db, primaryId) {
  const { rows } = await db.query(
    `WITH RECURSIVE tree AS (
       SELECT id, 0 AS depth FROM threat_reports WHERE id = $1
       UNION ALL
       SELECT r.id, t.depth + 1 FROM threat_reports r JOIN tree t ON r.superseded_by_report_id = t.id
        WHERE t.depth < 16
     )
     SELECT r.id, r.public_id, r.title, r.source_url, r.import_status, r.created_at,
            r.superseded_at, r.supersession, r.superseded_by_report_id
       FROM threat_reports r JOIN tree t ON t.id = r.id
      WHERE r.deleted_at IS NULL
      ORDER BY r.created_at ASC, r.id ASC
      LIMIT 50`,
    [primaryId]
  );
  return rows;
}

/**
 * Read model for the detail API / MCP: which logical report this row belongs
 * to and which URL variants (superseded reports) it groups.
 * @param {{ query: Function }} db
 * @param {object} report threat_reports row
 * @returns {Promise<{ superseded_by: object|null, source_variants: object[] }>}
 */
export async function loadReportIdentitySummary(db, report) {
  if (!report?.id) return { superseded_by: null, source_variants: [] };
  const primary = report.superseded_by_report_id ? await resolvePrimaryReport(db, report.id) : report;
  const group = primary ? await loadSupersessionGroup(db, primary.id) : [];
  const { rows: keyRows } = await db.query(
    `SELECT report_id, identity_key, evidence FROM threat_report_identity_keys
      WHERE report_id = ANY($1::bigint[]) ORDER BY id`,
    [group.map((g) => g.id)]
  );
  const keysByReport = new Map();
  for (const k of keyRows) {
    const id = Number(k.report_id);
    if (!keysByReport.has(id)) keysByReport.set(id, []);
    keysByReport.get(id).push({ key: k.identity_key, evidence: k.evidence || [] });
  }
  const variants = group.map((g) => ({
    report_id: g.public_id,
    title: g.title,
    source_url: g.source_url,
    import_status: g.import_status,
    imported_at: g.created_at,
    relation: Number(g.id) === Number(primary.id) ? 'primary' : 'superseded',
    superseded_at: g.superseded_at || null,
    supersession_reason: g.supersession?.reason || null,
    identity_keys: keysByReport.get(Number(g.id)) || []
  }));
  const supersededBy = report.superseded_by_report_id && primary && Number(primary.id) !== Number(report.id)
    ? {
        report_id: primary.public_id,
        title: primary.title,
        superseded_at: report.superseded_at,
        reason: report.supersession?.reason || null,
        evidence: report.supersession?.evidence || []
      }
    : null;
  return { superseded_by: supersededBy, source_variants: variants.length > 1 ? variants : [] };
}

/**
 * Write-guard for analyst actions: a superseded report is read-only.
 * @param {{ query: Function }} db
 * @param {object} report
 * @returns {Promise<null|{ code: 'REPORT_SUPERSEDED', message: string, primary_report_id: string|null }>}
 */
export async function supersededReportConflict(db, report) {
  if (!report?.superseded_by_report_id) return null;
  const primary = await resolvePrimaryReport(db, report.id);
  return {
    code: 'REPORT_SUPERSEDED',
    message: 'This report is a duplicate of another Threat Library report of the same article and is read-only. Work on the primary report.',
    primary_report_id: primary?.public_id || null
  };
}

/**
 * Source identity of an already-imported URL report, recomputed from what the
 * worker retained at fetch time (url_fetch artifact: submitted + final URL,
 * stored source.html). No network.
 * @param {{ query: Function }} db
 * @param {object} report
 * @param {{ readArtifact?: (storageKey: string) => Promise<Buffer> }} [deps]
 */
export async function resolveStoredReportIdentity(db, report, deps = {}) {
  const read = deps.readArtifact || readArtifactBuffer;
  if (report?.source_type !== 'url') return null;
  const { rows } = await db.query(
    `SELECT storage_key, source_metadata FROM threat_report_artifacts
      WHERE report_id = $1 AND artifact_type = 'url_fetch'
      ORDER BY (storage_key IS NOT NULL) DESC, id DESC LIMIT 1`,
    [report.id]
  );
  const artifact = rows[0] || null;
  let html = null;
  let htmlError = null;
  if (artifact?.storage_key) {
    try {
      html = (await read(artifact.storage_key)).toString('utf8');
    } catch (err) {
      htmlError = err?.code || err?.message || 'unreadable';
    }
  }
  const submittedUrl = artifact?.source_metadata?.url || report.source_url;
  if (!submittedUrl) return null;
  const identity = resolveSourceIdentity({
    submittedUrl,
    finalUrl: artifact?.source_metadata?.final_url || null,
    html
  });
  return { ...identity, artifact: { present: Boolean(artifact), html: Boolean(html), html_error: htmlError } };
}

function candidateKey(c) {
  return `${String(c.candidate_type || '').toLowerCase()}|${String(c.normalized_value || '')}`;
}

function relationshipKey(r) {
  const end = (kind, entity, candidateValue, ioc, portable) =>
    `${kind}:${entity ?? ''}:${candidateValue ?? ''}:${ioc ?? ''}:${portable ?? ''}`;
  return [
    r.relationship_type,
    end(r.subject_kind, r.subject_entity_id, r.subject_candidate_value, r.subject_ioc_id, r.subject_portable_ref),
    end(r.object_kind, r.object_entity_id, r.object_candidate_value, r.object_ioc_id, r.object_portable_ref)
  ].join('|');
}

async function loadReconciliationFacts(db, reportId) {
  const [candidates, entities, relationships, tags, iocSources, references, activeJobs] = await Promise.all([
    db.query(
      `SELECT id, candidate_type, normalized_value, review_status, assessment, role,
              matched_ioc_id, matched_ioc_observable_type
         FROM threat_report_candidates WHERE report_id = $1`,
      [reportId]
    ),
    db.query(
      `SELECT re.entity_id, e.entity_type, e.name
         FROM threat_report_entities re JOIN threat_entities e ON e.id = re.entity_id
        WHERE re.report_id = $1`,
      [reportId]
    ),
    db.query(
      `SELECT tr.relationship_type, tr.subject_kind, tr.subject_entity_id, tr.subject_ioc_id,
              tr.subject_portable_ref, sc.normalized_value AS subject_candidate_value,
              tr.object_kind, tr.object_entity_id, tr.object_ioc_id, tr.object_portable_ref,
              oc.normalized_value AS object_candidate_value
         FROM threat_relationships tr
         LEFT JOIN threat_report_candidates sc ON sc.id = tr.subject_candidate_id
         LEFT JOIN threat_report_candidates oc ON oc.id = tr.object_candidate_id
        WHERE tr.report_id = $1`,
      [reportId]
    ),
    db.query(
      `SELECT t.name FROM threat_report_tags rt JOIN tags t ON t.id = rt.tag_id WHERE rt.report_id = $1`,
      [reportId]
    ),
    db.query(`SELECT lifecycle_status AS status FROM threat_report_ioc_sources WHERE report_id = $1`, [reportId]),
    db.query(`SELECT COUNT(*)::int AS n FROM threat_report_source_references WHERE report_id = $1`, [reportId]),
    db.query(`SELECT COUNT(*)::int AS n FROM threat_library_jobs WHERE report_id = $1 AND status IN ('queued', 'running')`, [reportId])
  ]);
  return {
    candidates: candidates.rows,
    entities: entities.rows,
    relationships: relationships.rows,
    tags: tags.rows.map((t) => t.name),
    iocSources: iocSources.rows,
    sourceReferenceCount: references.rows[0]?.n || 0,
    activeJobs: activeJobs.rows[0]?.n || 0
  };
}

/**
 * Decide whether `secondary` can be superseded into `primary`. Pure over the
 * loaded facts; writes nothing.
 * @param {{ query: Function }} db
 * @param {{ primary: object, secondary: object, primaryIdentity: object|null, secondaryIdentity: object|null }} input
 */
export async function planReportReconciliation(db, { primary, secondary, primaryIdentity, secondaryIdentity }) {
  const blockers = [];
  if (!primary || !secondary) {
    return { ok: false, blockers: ['report_not_found'] };
  }
  if (Number(primary.id) === Number(secondary.id)) blockers.push('same_report');
  if (primary.deleted_at || secondary.deleted_at) blockers.push('report_deleted');
  if (primary.superseded_by_report_id) blockers.push('primary_is_superseded');
  if (secondary.superseded_by_report_id) blockers.push('secondary_already_superseded');
  if (secondary.finalized_at && !primary.finalized_at) blockers.push('secondary_finalized_but_primary_not');
  if (primary.source_type !== 'url' || secondary.source_type !== 'url') blockers.push('not_url_reports');

  // Identity: a key both reports proved, from their own retained fetch evidence.
  const pKeys = new Map((primaryIdentity?.keys || []).map((k) => [k.key, k]));
  const sharedKeys = (secondaryIdentity?.keys || [])
    .filter((k) => pKeys.has(k.key))
    .map((k) => ({ key: k.key, primary_evidence: pKeys.get(k.key).evidence, secondary_evidence: k.evidence }));
  if (!sharedKeys.length) blockers.push('no_shared_source_identity');

  const [p, s] = await Promise.all([loadReconciliationFacts(db, primary.id), loadReconciliationFacts(db, secondary.id)]);

  const primaryIocs = new Set(p.candidates.filter((c) => c.matched_ioc_id != null)
    .map((c) => `${c.matched_ioc_observable_type || c.candidate_type}:${c.matched_ioc_id}`));
  const missingIocLinks = s.candidates
    .filter((c) => c.matched_ioc_id != null)
    .map((c) => `${c.matched_ioc_observable_type || c.candidate_type}:${c.matched_ioc_id}`)
    .filter((k) => !primaryIocs.has(k));
  if (missingIocLinks.length) blockers.push('secondary_links_iocs_primary_does_not');

  const primaryByKey = new Map(p.candidates.map((c) => [candidateKey(c), c]));
  const missingCandidates = [];
  const conflictingDecisions = [];
  const pendingCoveredByPrimary = [];
  for (const c of s.candidates) {
    const twin = primaryByKey.get(candidateKey(c));
    if (!twin) {
      missingCandidates.push(candidateKey(c));
      continue;
    }
    if (DECIDED_REVIEW_STATUSES.has(c.review_status) && c.review_status !== twin.review_status) {
      conflictingDecisions.push({ candidate: candidateKey(c), secondary: c.review_status, primary: twin.review_status });
    }
    if (c.review_status === 'pending') {
      pendingCoveredByPrimary.push({ candidate: candidateKey(c), primary_review_status: twin.review_status });
    }
  }
  if (missingCandidates.length) blockers.push('secondary_has_candidates_primary_lacks');
  if (conflictingDecisions.length) blockers.push('conflicting_analyst_decisions');

  const primaryRels = new Set(p.relationships.map(relationshipKey));
  const missingRelationships = s.relationships.map(relationshipKey).filter((k) => !primaryRels.has(k));
  if (missingRelationships.length) blockers.push('secondary_has_relationships_primary_lacks');

  // A queued / running job would be stranded (dispatch skips superseded reports).
  if (s.activeJobs > 0 || p.activeJobs > 0) blockers.push('active_job');

  const liveSources = s.iocSources.filter((x) => LIVE_IOC_SOURCE_STATUSES.has(String(x.status)));
  if (liveSources.length) blockers.push('secondary_has_live_linked_ioc_sources');

  const primaryEntityIds = new Set(p.entities.map((e) => Number(e.entity_id)));
  const primaryTags = new Set(p.tags);
  const secondaryOnly = {
    entities: s.entities.filter((e) => !primaryEntityIds.has(Number(e.entity_id)))
      .map((e) => ({ entity_type: e.entity_type, name: e.name })),
    tags: s.tags.filter((t) => !primaryTags.has(t)).sort(),
    source_reference_count: s.sourceReferenceCount
  };

  return {
    ok: blockers.length === 0,
    blockers,
    shared_keys: sharedKeys,
    checks: {
      primary: { candidates: p.candidates.length, entities: p.entities.length, relationships: p.relationships.length, tags: p.tags.length, ioc_links: primaryIocs.size },
      secondary: { candidates: s.candidates.length, entities: s.entities.length, relationships: s.relationships.length, tags: s.tags.length, ioc_links: new Set(s.candidates.filter((c) => c.matched_ioc_id != null).map((c) => c.matched_ioc_id)).size },
      missing_ioc_links: missingIocLinks,
      missing_candidates: missingCandidates,
      conflicting_decisions: conflictingDecisions,
      missing_relationships: missingRelationships,
      secondary_pending_covered_by_primary: pendingCoveredByPrimary.length
    },
    secondary_only: secondaryOnly
  };
}

async function loadReportForUpdate(client, publicId) {
  const { rows } = await client.query(
    'SELECT * FROM threat_reports WHERE public_id = $1::uuid FOR UPDATE',
    [publicId]
  );
  return rows[0] || null;
}

/**
 * Supersede `secondaryPublicId` into `primaryPublicId` after re-checking every
 * invariant inside one transaction (rows locked, identity keys locked). The
 * supersession row update, identity keys and the audit row commit together;
 * any failure rolls everything back. Re-running on an already reconciled pair
 * is a no-op.
 * @param {import('pg').Pool} pool
 * @param {{
 *   primaryPublicId: string,
 *   secondaryPublicId: string,
 *   actor?: { publicId?: string, email?: string, username?: string, role?: string }|null,
 *   auditLogInTransaction: (client: object, event: object) => Promise<void>,
 *   dryRun?: boolean,
 *   deps?: { readArtifact?: Function }
 * }} input
 */
export async function reconcileDuplicateReports(pool, input) {
  const { primaryPublicId, secondaryPublicId, actor = null, auditLogInTransaction, dryRun = false, deps = {} } = input;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Lock both rows in id order (no deadlock with a concurrent reverse request).
    const { rows: order } = await client.query(
      'SELECT id, public_id FROM threat_reports WHERE public_id = ANY($1::uuid[]) ORDER BY id',
      [[primaryPublicId, secondaryPublicId]]
    );
    for (const r of order) await loadReportForUpdate(client, r.public_id);
    const primary = await loadReportForUpdate(client, primaryPublicId);
    const secondary = await loadReportForUpdate(client, secondaryPublicId);
    if (primary && secondary && Number(secondary.superseded_by_report_id) === Number(primary.id)) {
      await client.query('ROLLBACK');
      return { status: 'already_reconciled', primary_report_id: primary.public_id, secondary_report_id: secondary.public_id };
    }
    const primaryIdentity = primary ? await resolveStoredReportIdentity(client, primary, deps) : null;
    const secondaryIdentity = secondary ? await resolveStoredReportIdentity(client, secondary, deps) : null;
    const plan = await planReportReconciliation(client, { primary, secondary, primaryIdentity, secondaryIdentity });
    if (!plan.ok || dryRun) {
      await client.query('ROLLBACK');
      return { status: plan.ok ? 'dry_run' : 'blocked', plan, primaryIdentity, secondaryIdentity };
    }
    await lockIdentityKeys(client, [...primaryIdentity.keys, ...secondaryIdentity.keys].map((k) => k.key));
    const decidedAt = new Date().toISOString();
    const supersession = {
      reason: 'reconciliation',
      decided_by: actor?.email || actor?.username || actor?.publicId || 'system',
      decided_at: decidedAt,
      identity_version: secondaryIdentity.version,
      primary_public_id: primary.public_id,
      evidence: plan.shared_keys,
      checks: plan.checks,
      secondary_only: plan.secondary_only
    };
    const marked = await markReportSuperseded(client, {
      reportId: Number(secondary.id),
      primaryId: Number(primary.id),
      supersession
    });
    if (!marked) throw Object.assign(new Error('Secondary report could not be superseded'), { code: 'supersede_failed' });
    const primaryKeys = await recordIdentityKeys(client, primary.id, primaryIdentity.keys, 'reconciliation');
    const secondaryKeys = await recordIdentityKeys(client, secondary.id, secondaryIdentity.keys, 'reconciliation');
    for (const [row, identity] of [[primary, primaryIdentity], [secondary, secondaryIdentity]]) {
      await client.query(
        `UPDATE threat_reports SET source_identity = $2::jsonb WHERE id = $1 AND source_identity IS NULL`,
        [row.id, JSON.stringify({ ...identity, outcome: 'reconciled', claimed_at: decidedAt })]
      );
    }
    await auditLogInTransaction(client, {
      action: AUDIT_ACTION.THREAT_LIBRARY_REPORT_SUPERSEDED,
      ...reportAuditEntity(secondary),
      severity: AUDIT_SEVERITY.INFO,
      status: AUDIT_STATUS.SUCCESS,
      actor: actor || null,
      ...(actor ? {} : { actorRole: 'system', actorUsername: 'reconciliation' }),
      source: 'system',
      metadata: {
        ...reportAuditSnapshot(secondary),
        superseded_by_report_id: primary.public_id,
        superseded_by_title: primary.title,
        reason: 'reconciliation',
        shared_identity_keys: plan.shared_keys.map((k) => k.key),
        checks: plan.checks,
        secondary_only: plan.secondary_only
      }
    });
    await client.query('COMMIT');
    return {
      status: 'reconciled',
      primary_report_id: primary.public_id,
      secondary_report_id: secondary.public_id,
      plan,
      identity_keys: { primary: primaryKeys, secondary: secondaryKeys }
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
