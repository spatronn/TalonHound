/**
 * Per-feed source evidence for multi-source IOCs.
 */

import { FEED_SOURCE_RULES, sourceNameMatchesFeed, resolveFeedIdBySourceName } from './iocExpiration.js';

export const FEED_SOURCE_URL_FALLBACKS = Object.freeze({
  'urlhaus-abusech': 'https://urlhaus-api.abuse.ch/v2/files/exports/***/recent.csv',
  'threatfox-abusech': 'https://threatfox-api.abuse.ch/api/v1/',
  'malwarebazaar-abusech': 'https://bazaar.abuse.ch/export/csv/recent/',
  'usom-trcert': 'https://www.usom.gov.tr/api/address/index'
});

export const MISSING_MEMBERSHIP_EVIDENCE_NOTE =
  'No source evidence metadata stored for this membership.';

export function sourceNameForFeedKey(feedKey) {
  const rule = FEED_SOURCE_RULES.find((r) => r.key === feedKey);
  return rule?.exact || null;
}

export function sourceUrlForFeedKey(feedKey) {
  return FEED_SOURCE_URL_FALLBACKS[feedKey] || null;
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} client
 */
export async function upsertFeedSourceEvidence(client, {
  iocItemId,
  observableType,
  feedId,
  sourceName,
  sourceUrl = null,
  category = null,
  note = null,
  confidence = null
}) {
  if (!iocItemId || !observableType || !feedId || !sourceName) return null;

  const { rows } = await client.query(
    `INSERT INTO ioc_feed_source_evidence (
       ioc_item_id, ioc_observable_type, feed_id,
       source_name, source_url, category, note, confidence
     ) VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8)
     ON CONFLICT (ioc_item_id, ioc_observable_type, feed_id)
     DO UPDATE SET
       source_name = EXCLUDED.source_name,
       source_url = EXCLUDED.source_url,
       category = EXCLUDED.category,
       note = EXCLUDED.note,
       confidence = EXCLUDED.confidence,
       updated_at = NOW()
     RETURNING id`,
    [iocItemId, observableType, feedId, sourceName, sourceUrl, category, note, confidence]
  );
  return rows[0]?.id || null;
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} client
 */
export async function upsertFeedSourceEvidenceForObservable(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl = null,
  category = null,
  note = null,
  confidence = null
}) {
  const feedId = await resolveFeedIdBySourceName(client, sourceName);
  if (!feedId) return null;

  const { rows } = await client.query(
    `SELECT id
     FROM ioc_items
     WHERE observable = $1
       AND observable_type = $2
     ORDER BY created_at ASC
     LIMIT 1`,
    [observable, observableType]
  );
  const row = rows[0];
  if (!row) return null;

  return upsertFeedSourceEvidence(client, {
    iocItemId: row.id,
    observableType,
    feedId,
    sourceName,
    sourceUrl,
    category,
    note,
    confidence
  });
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} client
 */
export async function fetchFeedSourceEvidenceForItems(client, { iocItemIds = [], observableType } = {}) {
  const ids = (iocItemIds || []).filter((id) => Number.isFinite(Number(id)));
  if (!ids.length || !observableType) return [];

  const { rows } = await client.query(
    `SELECT e.id, e.ioc_item_id, e.ioc_observable_type, e.feed_id,
            e.source_name, e.source_url, e.category, e.note, e.confidence,
            e.created_at, e.updated_at,
            f.key AS feed_key, f.name AS feed_name
     FROM ioc_feed_source_evidence e
     JOIN integration_feeds f ON f.integration_id = e.feed_id
     WHERE e.ioc_item_id = ANY($1::bigint[])
       AND e.ioc_observable_type = $2
     ORDER BY e.created_at ASC`,
    [ids, observableType]
  );
  return rows;
}

/**
 * Build Source Evidence rows aligned with active feed/manual memberships.
 * @param {{ iocRows: object[], membershipSummary: object, evidenceRows: object[] }} input
 */
export function buildIocDetailsSourceEvidence({ iocRows = [], membershipSummary = {}, evidenceRows = [] } = {}) {
  const activeSources = membershipSummary.activeSources || [];
  const activeFeedSources = activeSources.filter((s) => s.source_type === 'feed');
  const activeManualSources = activeSources.filter((s) => s.source_type === 'manual');

  const primaryRowsBySource = new Map();
  for (const row of iocRows) {
    if (row?.source_name) primaryRowsBySource.set(String(row.source_name), row);
  }

  const evidenceByFeedKey = new Map();
  for (const row of evidenceRows) {
    if (row?.feed_key) evidenceByFeedKey.set(String(row.feed_key), row);
  }

  const out = [];

  for (const mem of activeFeedSources) {
    const feedKey = String(mem.feed_key || '');
    const sourceName = sourceNameForFeedKey(feedKey) || mem.name || mem.feed_name || feedKey;
    const evidence = evidenceByFeedKey.get(feedKey);
    const primary = primaryRowsBySource.get(sourceName);

    if (evidence) {
      out.push({
        id: evidence.id,
        source_name: evidence.source_name,
        source_url: evidence.source_url,
        confidence: evidence.confidence,
        category: evidence.category,
        note: evidence.note,
        created_at: evidence.created_at,
        feed_key: feedKey,
        evidence_kind: 'stored'
      });
      continue;
    }

    if (primary && sourceNameMatchesFeed(primary.source_name, feedKey)) {
      out.push({
        id: primary.id,
        source_name: primary.source_name,
        source_url: primary.source_url,
        confidence: primary.confidence,
        category: primary.category,
        note: primary.note,
        created_at: primary.created_at,
        feed_key: feedKey,
        evidence_kind: 'primary_ioc_item'
      });
      continue;
    }

    out.push({
      id: `membership:${mem.membership_id || feedKey}`,
      source_name: sourceName,
      source_url: sourceUrlForFeedKey(feedKey),
      confidence: mem.explicit_confidence || null,
      category: null,
      note: MISSING_MEMBERSHIP_EVIDENCE_NOTE,
      created_at: mem.first_seen_at || null,
      feed_key: feedKey,
      evidence_kind: 'membership_fallback'
    });
  }

  for (const mem of activeManualSources) {
    const row = iocRows.find((r) => Number(r.ioc_source_id) === Number(mem.ioc_source_id))
      || iocRows.find((r) => String(r.source_name || '') === String(mem.name || ''));
    if (!row) continue;
    out.push({
      id: row.id,
      source_name: row.source_name || mem.name,
      source_url: row.source_url,
      confidence: row.confidence,
      category: row.category,
      note: row.note,
      created_at: row.created_at,
      evidence_kind: 'manual_ioc_item'
    });
  }

  if (!out.length) {
    return iocRows
      .filter((r) => String(r.status || 'active') === 'active')
      .map((row) => ({
        id: row.id,
        source_name: row.source_name,
        source_url: row.source_url,
        confidence: row.confidence,
        category: row.category,
        note: row.note,
        created_at: row.created_at,
        evidence_kind: 'legacy_ioc_item'
      }));
  }

  return out;
}
