/**
 * File-identity audit.
 *
 * Future verified hash equivalence and artifact merges append one
 * ioc.file_identity.linked event. Historical links that were stored before
 * that writer existed are explained at read time as recovered evidence.
 * Recovered rows are not inserted and are not backdated enrichment events.
 */

import { AUDIT_ACTION, AUDIT_ENTITY } from './auditConstants.js';
import { resolveArtifactScopedIocIds } from './fileArtifacts/read.js';

const RECOVERED_ID_BASE = 8000000000000;

/**
 * Idempotent audit for a real identity change (new sibling hash or artifact merge).
 * Does not rewrite source memberships and does not treat an enrichment provider
 * as a threat-intelligence source.
 *
 * @param {import('pg').PoolClient|import('pg').Pool} client
 */
export async function recordFileIdentityLinkedAudit(client, {
  artifactId,
  operation,
  observedHashType = null,
  observedHashValue = null,
  sourceName = null,
  trigger = null,
  correlationId = null,
  subjectIocId = null,
  subjectPublicId = null,
  mergedArtifactIds = []
} = {}) {
  const artifact = String(artifactId || '').trim();
  const op = String(operation || '').trim();
  const observed = String(observedHashValue || '').trim().toLowerCase();
  if (!artifact || !op || !observed) return { written: false, reason: 'invalid_args' };

  const { rows: hashes } = await client.query(
    `SELECT hash_type, normalized_hash_value, is_primary, verification_source
     FROM file_artifact_hashes
     WHERE artifact_id = $1::uuid
     ORDER BY hash_type`,
    [artifact]
  );
  if (!hashes.length) return { written: false, reason: 'no_hashes' };

  const { rows: links } = await client.query(
    `SELECT ioc_item_id, ioc_observable_type, ioc_public_id, is_canonical_ioc
     FROM file_artifact_ioc_links
     WHERE artifact_id = $1::uuid
     ORDER BY ioc_item_id`,
    [artifact]
  );

  const existing = await client.query(
    `SELECT 1
     FROM audit_logs
     WHERE action = $1
       AND metadata->>'artifact_id' = $2
       AND metadata->>'operation' = $3
       AND metadata->>'observed_hash_value' = $4
     LIMIT 1`,
    [AUDIT_ACTION.IOC_FILE_IDENTITY_LINKED, artifact, op, observed]
  );
  if (existing.rowCount) return { written: false, reason: 'exists' };

  const enrichmentProvider = String(sourceName || '').toLowerCase() === 'virustotal'
    ? 'virustotal'
    : null;
  const metadata = {
    event_kind: 'file_identity_linked',
    derived: false,
    artifact_id: artifact,
    operation: op,
    trigger: trigger || null,
    observed_hash_type: observedHashType || null,
    observed_hash_value: observed,
    source_name: sourceName || null,
    enrichment_provider: enrichmentProvider,
    counts_as_threat_source: false,
    hashes: hashes.map((h) => ({
      hash_type: h.hash_type,
      value: h.normalized_hash_value,
      is_primary: Boolean(h.is_primary),
      verification_source: h.verification_source || null
    })),
    linked_iocs: links.map((l) => ({
      ioc_item_id: Number(l.ioc_item_id),
      observable_type: l.ioc_observable_type,
      public_id: l.ioc_public_id,
      is_canonical_ioc: Boolean(l.is_canonical_ioc)
    })),
    merged_artifact_ids: (mergedArtifactIds || []).filter(Boolean),
    correlation_id: correlationId || null,
    reason: 'Verified exact-hash equivalence joined one file identity. Publisher source memberships were left on the hash each source reported.'
  };

  const canonical = links.find((l) => l.is_canonical_ioc) || links[0] || null;
  const subjectId = Number(subjectIocId) || (canonical ? Number(canonical.ioc_item_id) : null);
  const entityId = subjectPublicId || (canonical?.ioc_public_id ? String(canonical.ioc_public_id) : String(subjectId || artifact));

  const ins = await client.query(
    `INSERT INTO audit_logs (
       actor_username, actor_role, action, entity_type, entity_id, entity_display,
       subject_ioc_id, subject_ioc_type, subject_ioc_value,
       target_type, target_value, severity, status, source, metadata
     ) VALUES (
       'System', 'system', $1, $2, $3, $4,
       $5::bigint, $6, $7,
       'file_artifact', $8, 'info', 'success', $9, $10::jsonb
     )
     RETURNING id`,
    [
      AUDIT_ACTION.IOC_FILE_IDENTITY_LINKED,
      AUDIT_ENTITY.IOC,
      entityId,
      observed,
      Number.isFinite(subjectId) ? subjectId : null,
      observedHashType || null,
      observed,
      artifact,
      enrichmentProvider ? 'enrichment' : 'integration',
      JSON.stringify(metadata)
    ]
  );
  return { written: true, id: ins.rows[0]?.id ?? null };
}

/**
 * IOC rows that share a proven file identity with the page IOC.
 * Always includes the page row.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {{ id: number|string, public_id?: string, observable?: string, observable_type?: string }} pageItem
 */
export async function loadFileIdentityScopeItems(pool, pageItem) {
  const pageId = Number(pageItem?.id);
  if (!Number.isFinite(pageId) || pageId <= 0) return [pageItem];
  let ids = [pageId];
  try {
    const resolved = await resolveArtifactScopedIocIds(pool, pageId);
    if (resolved?.length) ids = [...new Set(resolved.map(Number))];
  } catch (err) {
    if (!(err && (err.code === '42P01' || String(err.message || '').includes('file_artifact')))) {
      throw err;
    }
  }
  if (ids.length === 1) return [pageItem];
  const { rows } = await pool.query(
    `SELECT id, public_id, observable, observable_type
     FROM ioc_items
     WHERE id = ANY($1::bigint[])
     ORDER BY id ASC`,
    [ids]
  );
  if (!rows.length) return [pageItem];
  const page = rows.find((row) => Number(row.id) === pageId);
  const rest = rows.filter((row) => Number(row.id) !== pageId);
  return page ? [page, ...rest] : [pageItem, ...rows];
}

/**
 * One recovered history row per artifact that has no persisted link audit.
 * Timestamp is the earliest stored link time (evidence time), marked derived.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {Array<{ id: number|string }>} scopeItems
 * @param {Array<{ action?: string, metadata?: object }>} persistedRows
 */
export async function loadRecoveredFileIdentityEvents(pool, scopeItems, persistedRows = []) {
  const ids = (scopeItems || []).map((item) => Number(item.id)).filter((id) => Number.isFinite(id) && id > 0);
  if (!ids.length) return [];

  let rows = [];
  try {
    const res = await pool.query(
      `SELECT l.artifact_id,
              MIN(l.id) AS min_link_id,
              MIN(l.created_at) AS first_linked_at,
              jsonb_agg(DISTINCT jsonb_build_object(
                'ioc_item_id', l.ioc_item_id,
                'observable_type', l.ioc_observable_type,
                'public_id', l.ioc_public_id::text,
                'is_canonical', l.is_canonical_ioc
              )) AS linked_iocs,
              (
                SELECT jsonb_agg(jsonb_build_object(
                  'hash_type', h.hash_type,
                  'value', h.normalized_hash_value,
                  'is_primary', h.is_primary,
                  'verification_source', h.verification_source
                ) ORDER BY h.hash_type)
                FROM file_artifact_hashes h
                WHERE h.artifact_id = l.artifact_id
              ) AS hashes
       FROM file_artifact_ioc_links l
       WHERE l.ioc_item_id = ANY($1::bigint[])
       GROUP BY l.artifact_id`,
      [ids]
    );
    rows = res.rows;
  } catch (err) {
    if (err && (err.code === '42P01' || String(err.message || '').includes('file_artifact'))) return [];
    throw err;
  }

  const covered = new Set(
    (persistedRows || [])
      .filter((row) => row?.action === AUDIT_ACTION.IOC_FILE_IDENTITY_LINKED)
      .map((row) => row?.metadata?.artifact_id)
      .filter(Boolean)
  );

  return rows
    .filter((row) => row.artifact_id && !covered.has(String(row.artifact_id)))
    .map((row) => {
      const linkId = Number(row.min_link_id) || 0;
      const hashes = Array.isArray(row.hashes) ? row.hashes : [];
      const linked = Array.isArray(row.linked_iocs) ? row.linked_iocs : [];
      return {
        id: -(RECOVERED_ID_BASE + linkId),
        created_at: row.first_linked_at,
        actor_user_id: null,
        actor_username: 'System',
        actor_email: null,
        actor_role: 'system',
        action: AUDIT_ACTION.IOC_FILE_IDENTITY_RECOVERED,
        action_label: 'File identity recovered from stored links',
        entity_type: AUDIT_ENTITY.IOC,
        entity_id: String(row.artifact_id),
        entity_display: hashes.map((h) => `${h.hash_type}:${h.value}`).join(', ') || null,
        subject_ioc_id: null,
        subject_ioc_type: null,
        subject_ioc_value: null,
        target_type: 'file_artifact',
        target_value: String(row.artifact_id),
        severity: 'info',
        status: 'success',
        ip_address: null,
        user_agent: null,
        request_id: null,
        source: 'system',
        before_data: null,
        after_data: null,
        metadata: {
          event_kind: 'file_identity_recovered',
          derived: true,
          recovered_from: 'file_artifact_ioc_links',
          not_an_original_event: true,
          artifact_id: String(row.artifact_id),
          hashes,
          linked_iocs: linked,
          reason: 'Recovered from persisted file-artifact links and each hash verification source. Not a backdated enrichment, merge, or reconciliation event.'
        }
      };
    });
}
