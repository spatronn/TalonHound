/**
 * IOC source first-import provenance for Audit / History.
 *
 * Semantic: exactly one source-import event per (ioc, feed/source).
 * - Historical: derived from ioc_feed_memberships.first_seen_in_feed (no mass backfill).
 * - New memberships created via upsertMembershipOnImport: persisted once.
 * - Read path merges persisted + derived and dedupes by action + ioc_id + feed_id.
 */

import { AUDIT_ACTION, AUDIT_ENTITY, auditActionLabel } from './auditConstants.js';

export const IOC_SOURCE_IMPORTED_ACTION = AUDIT_ACTION.IOC_SOURCE_IMPORTED;

export function sourceImportDedupeKey({ iocId, feedId }) {
  return `${IOC_SOURCE_IMPORTED_ACTION}:${Number(iocId)}:${String(feedId || '').trim()}`;
}

export function sourceImportActionLabel(feedName) {
  const name = String(feedName || '').trim() || 'Unknown feed';
  return `Imported from ${name}`;
}

export function extractSourceImportFeedId(row) {
  const meta = row?.metadata && typeof row.metadata === 'object' ? row.metadata : null;
  const fromMeta = meta?.feed_id ?? meta?.source_feed_id ?? null;
  if (fromMeta != null && String(fromMeta).trim()) return String(fromMeta).trim();
  return null;
}

/**
 * Canonical History timestamp for a feed membership: first_seen_in_feed.
 * Falls back to membership created_at only when first_seen is missing.
 */
export function canonicalSourceFirstImportAt(membership) {
  return membership?.first_seen_in_feed || membership?.created_at || null;
}

/**
 * @param {{
 *   membership: object,
 *   iocItem: { id: number|string, public_id?: string|null, observable?: string|null, observable_type?: string|null }
 * }} args
 */
export function buildDerivedSourceImportEvent({ membership, iocItem }) {
  const membershipId = Number(membership?.id);
  const iocId = Number(iocItem?.id);
  const feedId = membership?.feed_id != null ? String(membership.feed_id) : null;
  const feedKey = membership?.feed_key || null;
  const feedName = membership?.feed_name || membership?.feed_key || 'Unknown feed';
  const createdAt = canonicalSourceFirstImportAt(membership);
  const observable = iocItem?.observable || null;
  const observableType = iocItem?.observable_type || membership?.ioc_observable_type || null;

  return {
    // Negative synthetic id keeps the existing numeric frontend key stable and
    // never collides with persisted audit_logs.id (BIGSERIAL starts at 1).
    id: Number.isFinite(membershipId) ? -membershipId : null,
    created_at: createdAt,
    actor_user_id: null,
    actor_username: 'System',
    actor_email: null,
    actor_role: 'system',
    action: IOC_SOURCE_IMPORTED_ACTION,
    action_label: sourceImportActionLabel(feedName),
    entity_type: AUDIT_ENTITY.IOC,
    entity_id: iocItem?.public_id ? String(iocItem.public_id) : String(iocId),
    entity_display: observable,
    subject_ioc_id: Number.isFinite(iocId) ? iocId : null,
    subject_ioc_type: observableType,
    subject_ioc_value: observable,
    target_type: 'feed',
    target_value: feedName,
    severity: 'info',
    status: 'success',
    ip_address: null,
    user_agent: null,
    request_id: null,
    source: 'integration',
    before_data: null,
    after_data: null,
    metadata: {
      event_kind: 'source_import',
      derived: true,
      feed_id: feedId,
      feed_key: feedKey,
      feed_name: feedName,
      membership_id: Number.isFinite(membershipId) ? membershipId : null,
      first_seen_in_feed: createdAt,
      actor_type: 'feed_import'
    },
    _dedupe_key: sourceImportDedupeKey({ iocId, feedId })
  };
}

/**
 * Normalize a persisted audit row for History display (dynamic label + canonical ts).
 */
export function decoratePersistedSourceImportRow(row) {
  if (!row || row.action !== IOC_SOURCE_IMPORTED_ACTION) return row;
  const meta = row.metadata && typeof row.metadata === 'object' ? row.metadata : {};
  const feedName = meta.feed_name || meta.feed_key || row.target_value || 'Unknown feed';
  const firstSeen = meta.first_seen_in_feed || row.created_at;
  return {
    ...row,
    created_at: firstSeen,
    actor_username: row.actor_username || 'System',
    actor_role: row.actor_role || 'system',
    action_label: sourceImportActionLabel(feedName),
    target_type: row.target_type || 'feed',
    target_value: row.target_value || feedName,
    _dedupe_key: sourceImportDedupeKey({
      iocId: row.subject_ioc_id,
      feedId: extractSourceImportFeedId(row)
    })
  };
}

/**
 * Merge persisted audit rows with derived source-import events.
 * Dedupes by (action, ioc_id, feed_id). Persisted wins over derived.
 */
export function mergeIocAuditHistory({ persistedRows = [], derivedRows = [], limit = 50 } = {}) {
  const capped = Math.min(100, Math.max(1, Number(limit) || 50));
  const seen = new Set();
  const merged = [];

  for (const raw of persistedRows) {
    const row = decoratePersistedSourceImportRow(raw);
    if (row.action === IOC_SOURCE_IMPORTED_ACTION) {
      const key = row._dedupe_key || sourceImportDedupeKey({
        iocId: row.subject_ioc_id,
        feedId: extractSourceImportFeedId(row)
      });
      if (key && seen.has(key)) continue;
      if (key) seen.add(key);
    }
    const { _dedupe_key, ...publicRow } = row;
    merged.push(publicRow);
  }

  for (const raw of derivedRows) {
    const key = raw._dedupe_key || sourceImportDedupeKey({
      iocId: raw.subject_ioc_id,
      feedId: extractSourceImportFeedId(raw)
    });
    if (key && seen.has(key)) continue;
    if (key) seen.add(key);
    const { _dedupe_key, ...publicRow } = raw;
    merged.push(publicRow);
  }

  merged.sort((a, b) => {
    const ta = Date.parse(a.created_at || 0) || 0;
    const tb = Date.parse(b.created_at || 0) || 0;
    if (tb !== ta) return tb - ta;
    const ia = Number(a.id) || 0;
    const ib = Number(b.id) || 0;
    return ib - ia;
  });

  return merged.slice(0, capped);
}

/**
 * Load feed memberships for one IOC (bounded) and build derived source-import events.
 */
export async function loadDerivedSourceImportEvents(pool, iocItem) {
  const iocId = Number(iocItem?.id);
  if (!Number.isFinite(iocId) || iocId <= 0) return [];

  const { rows } = await pool.query(
    `SELECT m.id, m.feed_id, m.ioc_observable_type, m.first_seen_in_feed, m.created_at, m.status,
            f.key AS feed_key, f.name AS feed_name
     FROM ioc_feed_memberships m
     JOIN integration_feeds f ON f.integration_id = m.feed_id
     WHERE m.ioc_item_id = $1
     ORDER BY m.first_seen_in_feed ASC NULLS LAST, m.id ASC`,
    [iocId]
  );

  return rows.map((membership) => buildDerivedSourceImportEvent({ membership, iocItem }));
}

/**
 * Persist exactly one source-import audit for a newly created feed membership.
 * Idempotent on (action, subject_ioc_id, feed_id). Safe under concurrency.
 *
 * @param {import('pg').PoolClient|import('pg').Pool} client
 */
export async function recordSourceImportAudit(client, {
  iocItemId,
  observableType = null,
  observableValue = null,
  publicId = null,
  feedId,
  membershipId = null,
  firstSeenAt = null,
  feedName = null,
  feedKey = null
} = {}) {
  const iocId = Number(iocItemId);
  if (!Number.isFinite(iocId) || iocId <= 0 || !feedId) {
    return { written: false, reason: 'invalid_args' };
  }

  let resolvedName = feedName;
  let resolvedKey = feedKey;
  if (!resolvedName || !resolvedKey) {
    const feedRes = await client.query(
      `SELECT key, name FROM integration_feeds WHERE integration_id = $1::uuid LIMIT 1`,
      [feedId]
    );
    resolvedKey = resolvedKey || feedRes.rows[0]?.key || null;
    resolvedName = resolvedName || feedRes.rows[0]?.name || resolvedKey || 'Unknown feed';
  }

  const firstSeen = firstSeenAt instanceof Date
    ? firstSeenAt
    : (firstSeenAt ? new Date(firstSeenAt) : new Date());
  const createdAt = Number.isFinite(firstSeen.getTime()) ? firstSeen : new Date();
  const entityId = publicId ? String(publicId) : String(iocId);
  const metadata = {
    event_kind: 'source_import',
    derived: false,
    feed_id: String(feedId),
    feed_key: resolvedKey,
    feed_name: resolvedName,
    membership_id: membershipId != null ? Number(membershipId) : null,
    first_seen_in_feed: createdAt.toISOString(),
    actor_type: 'feed_import'
  };

  const ins = await client.query(
    `INSERT INTO audit_logs (
       created_at, actor_username, actor_role,
       action, entity_type, entity_id, entity_display,
       subject_ioc_id, subject_ioc_type, subject_ioc_value,
       target_type, target_value,
       severity, status, source, metadata
     )
     SELECT
       $1::timestamptz, 'System', 'system',
       $2, $3, $4, $5,
       $6::bigint, $7, $8,
       'feed', $9,
       'info', 'success', 'integration', $10::jsonb
     WHERE NOT EXISTS (
       SELECT 1
       FROM audit_logs a
       WHERE a.action = $2
         AND a.subject_ioc_id = $6::bigint
         AND a.metadata->>'feed_id' = $11
     )
     RETURNING id`,
    [
      createdAt.toISOString(),
      IOC_SOURCE_IMPORTED_ACTION,
      AUDIT_ENTITY.IOC,
      entityId,
      observableValue,
      iocId,
      observableType,
      observableValue,
      resolvedName,
      JSON.stringify(metadata),
      String(feedId)
    ]
  );

  return {
    written: Boolean(ins.rowCount),
    id: ins.rows[0]?.id ?? null,
    feed_name: resolvedName,
    action_label: sourceImportActionLabel(resolvedName)
  };
}

/** Convenience for API row shaping when action labels need the dynamic feed name. */
export function publicSourceImportActionLabel(action, metadata) {
  if (action !== IOC_SOURCE_IMPORTED_ACTION) return auditActionLabel(action);
  const meta = metadata && typeof metadata === 'object' ? metadata : {};
  return sourceImportActionLabel(meta.feed_name || meta.feed_key || 'Unknown feed');
}
