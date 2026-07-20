import { getFeedPolicy } from './iocExpiration.js';
import {
  compareUsomHighwaters,
  USOM_FEED_KEY,
  USOM_SOURCE_NAME
} from './usomNormalizer.js';

export const USOM_ADDRESS_ENDPOINT = 'https://siberguvenlik.gov.tr/api/address/index';
const STAGE_TABLE = 'usom_import_stage';
// Two different vocabularies, deliberately kept apart.
//
// STORED_IOC_TYPES: canonical types as persisted in ioc_items / ioc_feed_memberships.
// Migration 120 renamed 'ip6' -> 'ipv6'. Use these for any lookup against stored rows —
// querying 'ip6' matches zero rows, which silently skipped expiration and absence
// reconciliation for every USOM IPv6 membership.
const STORED_IOC_TYPES = Object.freeze(['domain', 'url', 'ip', 'ipv6']);

// API_TOTAL_TYPES: types as named by the USOM external API, used only to index the
// api_total_* keys in the collected stats (see USOM_SUPPORTED_TOTAL_KEYS and
// usom_import_cursors.ioc_type). The provider still calls IPv6 'ip6', so these must NOT
// be renamed to the canonical form or the totals silently under-count.
const API_TOTAL_TYPES = Object.freeze(['domain', 'url', 'ip', 'ip6']);
const DEFAULT_USOM_STATEMENT_TIMEOUT_MS = 1_800_000;
const DEFAULT_USOM_IDLE_IN_TX_TIMEOUT_MS = 600_000;
const LOOKUP_GROUPS = Object.freeze(['descriptions', 'sources', 'connectionTypes']);

function lookupSourceName(group) {
  if (!LOOKUP_GROUPS.includes(group)) throw new TypeError(`Unknown USOM lookup group: ${group}`);
  return `${USOM_SOURCE_NAME}:lookup:${group}`;
}

function numberFromRow(row, key) {
  return Number(row?.[key] || 0);
}

function positiveTimeoutMs(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 1_000 ? Math.floor(parsed) : fallback;
}

export async function createUsomImportStage(client) {
  await client.query(`DROP TABLE IF EXISTS ${STAGE_TABLE}`);
  await client.query(
    `CREATE TEMP TABLE ${STAGE_TABLE} (
       observable_type TEXT NOT NULL,
       observable TEXT NOT NULL,
       category TEXT NULL,
       note TEXT NULL,
       provider_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
       provider_fingerprint TEXT NOT NULL,
       provider_record_timestamp TIMESTAMPTZ NULL,
       provider_record_id TEXT NULL,
       PRIMARY KEY (observable_type, observable)
     ) ON COMMIT PRESERVE ROWS`
  );
}

export async function stageUsomEntries(client, entries) {
  const incomingEntries = entries || [];
  const deduplicated = new Map();
  for (const entry of incomingEntries) {
    const key = `${entry.observableType}\u0000${entry.observable}`;
    const current = deduplicated.get(key);
    const candidateHighwater = entry.providerMetadata?.provider_date_utc
      && entry.providerMetadata?.provider_record_id != null
      ? {
          timestamp: entry.providerMetadata.provider_date_utc,
          providerId: String(entry.providerMetadata.provider_record_id)
        }
      : null;
    const currentHighwater = current?.providerMetadata?.provider_date_utc
      && current?.providerMetadata?.provider_record_id != null
      ? {
          timestamp: current.providerMetadata.provider_date_utc,
          providerId: String(current.providerMetadata.provider_record_id)
        }
      : null;
    if (!current || compareUsomHighwaters(candidateHighwater, currentHighwater) > 0) {
      deduplicated.set(key, entry);
    }
  }
  const rows = [...deduplicated.values()].map((entry) => ({
    observable_type: entry.observableType,
    observable: entry.observable,
    category: entry.category || 'threat-intel',
    note: entry.note || null,
    provider_metadata: entry.providerMetadata || {},
    provider_fingerprint: entry.providerFingerprint,
    provider_record_timestamp: entry.providerMetadata?.provider_date_utc || null,
    provider_record_id: entry.providerMetadata?.provider_record_id == null
      ? null
      : String(entry.providerMetadata.provider_record_id)
  }));
  if (!rows.length) return { staged: 0, duplicate: 0 };

  const { rows: result } = await client.query(
    `WITH incoming AS (
       SELECT observable_type, observable, category, note, provider_metadata,
              provider_fingerprint, provider_record_timestamp, provider_record_id
       FROM jsonb_to_recordset($1::jsonb) AS x(
         observable_type TEXT,
         observable TEXT,
         category TEXT,
         note TEXT,
         provider_metadata JSONB,
         provider_fingerprint TEXT,
         provider_record_timestamp TIMESTAMPTZ,
         provider_record_id TEXT
       )
     ),
     inserted AS (
       INSERT INTO ${STAGE_TABLE} (
         observable_type, observable, category, note, provider_metadata,
         provider_fingerprint, provider_record_timestamp, provider_record_id
       )
       SELECT observable_type, observable, category, note,
              COALESCE(provider_metadata, '{}'::jsonb), provider_fingerprint,
              provider_record_timestamp, provider_record_id
       FROM incoming
       ON CONFLICT (observable_type, observable) DO UPDATE SET
         category = EXCLUDED.category,
         note = EXCLUDED.note,
         provider_metadata = EXCLUDED.provider_metadata,
         provider_fingerprint = EXCLUDED.provider_fingerprint,
         provider_record_timestamp = EXCLUDED.provider_record_timestamp,
         provider_record_id = EXCLUDED.provider_record_id
       WHERE (
         COALESCE(EXCLUDED.provider_record_timestamp, '-infinity'::timestamptz),
         CASE
           WHEN EXCLUDED.provider_record_id ~ '^[0-9]+$'
             THEN lpad(EXCLUDED.provider_record_id, 128, '0')
           ELSE COALESCE(EXCLUDED.provider_record_id, '')
         END
       ) > (
         COALESCE(${STAGE_TABLE}.provider_record_timestamp, '-infinity'::timestamptz),
         CASE
           WHEN ${STAGE_TABLE}.provider_record_id ~ '^[0-9]+$'
             THEN lpad(${STAGE_TABLE}.provider_record_id, 128, '0')
           ELSE COALESCE(${STAGE_TABLE}.provider_record_id, '')
         END
       )
       RETURNING (xmax = 0) AS inserted
     )
     SELECT COUNT(*) FILTER (WHERE inserted)::int AS staged
     FROM inserted`,
    [JSON.stringify(rows)]
  );
  const staged = numberFromRow(result[0], 'staged');
  return { staged, duplicate: Math.max(0, incomingEntries.length - staged) };
}

async function removeSuppressedStageEntries(client) {
  const { rows } = await client.query(
    `WITH removed AS (
       DELETE FROM ${STAGE_TABLE} s
       USING ioc_suppressions sup
       WHERE sup.active = TRUE
         AND sup.deleted_at IS NULL
         AND (sup.expires_at IS NULL OR sup.expires_at > NOW())
         AND lower(sup.ioc_value) = lower(s.observable)
         AND lower(sup.ioc_type) = lower(s.observable_type)
         AND (
           lower(sup.scope) = 'global'
           OR (
             lower(sup.scope) = 'source'
             AND lower(COALESCE(sup.source_name, '')) = lower($1)
           )
         )
       RETURNING 1
     )
     SELECT COUNT(*)::int AS suppressed FROM removed`,
    [USOM_SOURCE_NAME]
  );
  return numberFromRow(rows[0], 'suppressed');
}

async function loadFeed(client) {
  const { rows } = await client.query(
    `SELECT integration_id, key, name, default_confidence, feed_update_mode
     FROM integration_feeds
     WHERE key = $1
     LIMIT 1`,
    [USOM_FEED_KEY]
  );
  if (!rows[0]) throw new Error(`Integration feed not found: ${USOM_FEED_KEY}`);
  return rows[0];
}

export async function loadUsomImportContext(client) {
  const feed = await loadFeed(client);
  const [cursorResult, stateResult] = await Promise.all([
    client.query(
      `SELECT ioc_type, cursor_timestamp, cursor_provider_id
       FROM usom_import_cursors
       WHERE feed_id = $1::uuid`,
      [feed.integration_id]
    ),
    client.query(
      `SELECT full_snapshot_hash, last_full_reconciliation_at
       FROM usom_import_state
       WHERE feed_id = $1::uuid`,
      [feed.integration_id]
    )
  ]);
  const cursors = {};
  for (const row of cursorResult.rows || []) {
    cursors[row.ioc_type] = {
      timestamp: new Date(row.cursor_timestamp).toISOString(),
      providerId: String(row.cursor_provider_id)
    };
  }
  return {
    feed,
    cursors,
    state: stateResult.rows?.[0] || null
  };
}

export async function loadUsomLookupCache(client) {
  const cache = {};
  for (const group of LOOKUP_GROUPS) {
    const sourceName = lookupSourceName(group);
    const { rows } = await client.query(
      `SELECT s.items_json, s.updated_at, c.last_cursor
       FROM integration_source_state s
       LEFT JOIN integration_checkpoints c ON c.source_name = s.source_name
       WHERE s.source_name = $1`,
      [sourceName]
    );
    const row = rows[0];
    if (!row) continue;
    const payload = row.items_json && typeof row.items_json === 'object'
      ? row.items_json
      : {};
    cache[group] = {
      rows: Array.isArray(payload.rows) ? payload.rows : [],
      updatedAt: payload.checked_at || row.updated_at,
      lastModified: row.last_cursor || null
    };
  }
  return cache;
}

export async function saveUsomLookupCache(client, group, {
  rows = [],
  lastModified = null,
  checkedAt = new Date()
} = {}) {
  const sourceName = lookupSourceName(group);
  await client.query(
    `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
     VALUES ($1, NULL, $2::jsonb, $3)
     ON CONFLICT (source_name)
     DO UPDATE SET items_json = EXCLUDED.items_json, updated_at = EXCLUDED.updated_at`,
    [sourceName, JSON.stringify({ rows, checked_at: new Date(checkedAt).toISOString() }), checkedAt]
  );
  if (lastModified) {
    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = EXCLUDED.updated_at`,
      [sourceName, lastModified, checkedAt]
    );
  }
}

/**
 * Classify every staged row against the current membership state.
 *
 * The five outcomes are mutually exclusive and evaluated in this precedence order:
 *
 *   created     - no membership row exists yet for (ioc, type, feed).
 *   reactivated - membership exists but is not active (expired / purged / missing).
 *                 Wins over `changed` on purpose: a returning IOC is a reactivation
 *                 event even when its payload is byte-identical to what we last saw.
 *   changed     - active membership whose stored canonical fingerprint differs from
 *                 the incoming one. Only this outcome may advance last_changed_in_source.
 *   unchanged   - active membership with an identical fingerprint, OR a NULL stored
 *                 fingerprint (one-time silent adoption after migration 121 — see the
 *                 migration header for why this must not count as `changed`).
 *
 * `removed` is not classified here: absence is only knowable after a successful full
 * snapshot reconciliation, so it is counted by markMissingMemberships().
 *
 * This runs BEFORE any write, so it observes the pre-run state.
 */
async function classifyStageAgainstExisting(client, feedId) {
  const { rows } = await client.query(
    `WITH canonical AS (
       SELECT s.observable_type, s.observable, s.provider_fingerprint,
              i.id AS ioc_item_id
       FROM ${STAGE_TABLE} s
       LEFT JOIN LATERAL (
         SELECT id
         FROM ioc_items
         WHERE observable = s.observable
           AND observable_type = s.observable_type
         ORDER BY created_at ASC, id ASC
         LIMIT 1
       ) i ON TRUE
     ),
     state AS (
       SELECT
         CASE
           WHEN c.ioc_item_id IS NULL OR m.id IS NULL THEN 'created'
           WHEN m.status IS DISTINCT FROM 'active'
             OR m.purged_at IS NOT NULL
             OR m.missing_since IS NOT NULL THEN 'reactivated'
           WHEN m.content_fingerprint IS NOT NULL
             AND m.content_fingerprint IS DISTINCT FROM c.provider_fingerprint THEN 'changed'
           ELSE 'unchanged'
         END AS outcome
       FROM canonical c
       LEFT JOIN ioc_feed_memberships m
         ON m.ioc_item_id = c.ioc_item_id
        AND m.ioc_observable_type = c.observable_type
        AND m.feed_id = $1::uuid
     )
     SELECT
       COUNT(*) FILTER (WHERE outcome = 'created')::int AS created,
       COUNT(*) FILTER (WHERE outcome = 'reactivated')::int AS reactivated,
       COUNT(*) FILTER (WHERE outcome = 'changed')::int AS changed,
       COUNT(*) FILTER (WHERE outcome = 'unchanged')::int AS unchanged
     FROM state`,
    [feedId]
  );
  return {
    created: numberFromRow(rows[0], 'created'),
    reactivated: numberFromRow(rows[0], 'reactivated'),
    changed: numberFromRow(rows[0], 'changed'),
    unchanged: numberFromRow(rows[0], 'unchanged')
  };
}

async function insertNewIocs(client, feed) {
  await client.query(
    `INSERT INTO ioc_items (
       observable, observable_type, source_name, source_url,
       confidence, source_confidence, feed_default_confidence,
       confidence_source, confidence_source_name,
       category, note, threat_classification
     )
     SELECT s.observable,
            s.observable_type,
            $1,
            $2,
            COALESCE($3, 'medium'),
            NULL,
            $3,
            'feed_default',
            $4,
            s.category,
            s.note,
            'unknown'
     FROM ${STAGE_TABLE} s
     WHERE NOT EXISTS (
       SELECT 1
       FROM ioc_items i
       WHERE i.observable = s.observable
         AND i.observable_type = s.observable_type
     )`,
    [USOM_SOURCE_NAME, USOM_ADDRESS_ENDPOINT, feed.default_confidence, feed.name]
  );

  await client.query(
    `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
     SELECT DISTINCT ON (i.public_id, s.observable_type, s.observable)
            i.public_id,
            s.observable_type,
            CASE
              WHEN s.observable_type IN ('domain', 'url') THEN lower(s.observable)
              ELSE s.observable
            END
     FROM ${STAGE_TABLE} s
     JOIN LATERAL (
       SELECT public_id
       FROM ioc_items
       WHERE observable = s.observable
         AND observable_type = s.observable_type
       ORDER BY created_at ASC, id ASC
       LIMIT 1
     ) i ON TRUE
     ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`
  );
}

/**
 * One-time silent adoption of canonical fingerprints (migration 121 baseline).
 *
 * Rows that predate migration 121 have content_fingerprint = NULL. Classification
 * already reported them as `unchanged`, so we must record the fingerprint WITHOUT
 * advancing updated_at, last_changed_in_source or emitting audit — otherwise the
 * first post-deploy run would look like a table-wide change event.
 *
 * This writes exactly one column and converges after a single run: once adopted, the
 * guard in upsertMemberships() can detect genuine changes for these rows. Without
 * this step content_fingerprint would stay NULL forever and real changes would be
 * permanently invisible.
 *
 * Accepted trade-off (documented in migration 121): if such a row ALSO changed in the
 * source during this very run, that one change is absorbed silently. The pre-migration
 * fingerprint does not exist, so it cannot be detected.
 */
async function adoptMissingFingerprints(client, feedId) {
  const { rowCount } = await client.query(
    `UPDATE ioc_feed_memberships m
     SET content_fingerprint = s.provider_fingerprint
     FROM ioc_items i
     JOIN ${STAGE_TABLE} s
       ON s.observable_type = i.observable_type
      AND s.observable = i.observable
     WHERE m.ioc_item_id = i.id
       AND m.ioc_observable_type = i.observable_type
       AND m.feed_id = $1::uuid
       AND m.content_fingerprint IS NULL`,
    [feedId]
  );
  return Number(rowCount || 0);
}

/**
 * Insert new memberships and update ONLY those that genuinely changed or reactivated.
 *
 * The DO UPDATE ... WHERE clause is the DB-level no-op guarantee: when the canonical
 * fingerprint matches and the membership is already active, PostgreSQL produces no
 * physical UPDATE at all — no dead tuple, no updated_at bump, no analyst-visible
 * timestamp movement. Comparing in the application layer alone is not sufficient.
 *
 * last_changed_in_source advances here for both `changed` and `reactivated`, since a
 * reactivation is a real source-side lifecycle event. Analyst override fields
 * (override_*) are never written by this statement, and the expiry/purge resets stay
 * gated on override_enabled exactly as before.
 */
async function upsertMemberships(client, feedId, seenAt) {
  const { rowCount } = await client.query(
    `WITH canonical AS (
       SELECT s.observable_type, s.observable, s.provider_fingerprint, i.id AS ioc_item_id
       FROM ${STAGE_TABLE} s
       JOIN LATERAL (
         SELECT id
         FROM ioc_items
         WHERE observable = s.observable
           AND observable_type = s.observable_type
         ORDER BY created_at ASC, id ASC
         LIMIT 1
       ) i ON TRUE
     )
     INSERT INTO ioc_feed_memberships (
       ioc_item_id, ioc_observable_type, feed_id,
       first_seen_in_feed, last_seen_in_feed,
       last_changed_in_source, content_fingerprint, missing_since, status
     )
     SELECT ioc_item_id, observable_type, $1::uuid, $2, $2, $2, provider_fingerprint, NULL, 'active'
     FROM canonical
     ON CONFLICT (ioc_item_id, ioc_observable_type, feed_id)
     DO UPDATE SET
       content_fingerprint = EXCLUDED.content_fingerprint,
       last_changed_in_source = EXCLUDED.last_changed_in_source,
       last_seen_in_feed = EXCLUDED.last_seen_in_feed,
       missing_since = NULL,
       status = CASE
         WHEN ioc_feed_memberships.override_enabled THEN ioc_feed_memberships.status
         ELSE 'active'
       END,
       expired_at = CASE
         WHEN ioc_feed_memberships.override_enabled THEN ioc_feed_memberships.expired_at
         ELSE NULL
       END,
       expiration_reason = CASE
         WHEN ioc_feed_memberships.override_enabled THEN ioc_feed_memberships.expiration_reason
         ELSE NULL
       END,
       purged_at = CASE
         WHEN ioc_feed_memberships.override_enabled THEN ioc_feed_memberships.purged_at
         ELSE NULL
       END,
       purged_by = CASE
         WHEN ioc_feed_memberships.override_enabled THEN ioc_feed_memberships.purged_by
         ELSE NULL
       END,
       purged_by_username = CASE
         WHEN ioc_feed_memberships.override_enabled THEN ioc_feed_memberships.purged_by_username
         ELSE NULL
       END,
       purge_reason = CASE
         WHEN ioc_feed_memberships.override_enabled THEN ioc_feed_memberships.purge_reason
         ELSE NULL
       END,
       updated_at = NOW()
     WHERE ioc_feed_memberships.content_fingerprint IS DISTINCT FROM EXCLUDED.content_fingerprint
        OR ioc_feed_memberships.status IS DISTINCT FROM 'active'
        OR ioc_feed_memberships.missing_since IS NOT NULL
        OR ioc_feed_memberships.purged_at IS NOT NULL`,
    [feedId, seenAt]
  );
  return Number(rowCount || 0);
}

/**
 * Expiration-driven presence write. Runs ONLY for expiration_mode = 'last_seen_ttl'.
 *
 * Snapshot presence is derived transactionally from the staging-table anti-join (see
 * markMissingMemberships) and needs no per-row write, so in every other configuration
 * unchanged rows are left completely untouched — no statement is even issued.
 *
 * The single exception is last_seen_ttl, where policySql computes expiry as
 * `last_seen_in_feed + ttl`. There, continued presence MUST be recorded or IOCs that
 * are still in the feed would silently expire. Note this deliberately writes
 * last_seen_in_feed itself (the column policySql actually reads) rather than a parallel
 * column: a second "observed at" field would have to be maintained on the same hundreds
 * of thousands of rows while changing no behaviour.
 *
 * Guarantees: touches exactly one column, never updated_at, never
 * last_changed_in_source, never an analyst-visible value, and emits no audit or event.
 */
async function recordExpirationPresence(client, feedId, seenAt) {
  let touched = 0;
  for (const observableType of STORED_IOC_TYPES) {
    const policy = await getFeedPolicy(client, feedId, observableType);
    if (!policy?.enabled || policy.expiration_mode !== 'last_seen_ttl') continue;
    const { rowCount } = await client.query(
      `UPDATE ioc_feed_memberships m
       SET last_seen_in_feed = $3::timestamptz
       FROM ioc_items i
       JOIN ${STAGE_TABLE} s
         ON s.observable_type = i.observable_type
        AND s.observable = i.observable
       WHERE m.ioc_item_id = i.id
         AND m.ioc_observable_type = i.observable_type
         AND m.feed_id = $1::uuid
         AND m.ioc_observable_type = $2
         AND m.last_seen_in_feed IS DISTINCT FROM $3::timestamptz`,
      [feedId, observableType, seenAt]
    );
    touched += Number(rowCount || 0);
  }
  return touched;
}

async function upsertEvidence(client, feedId) {
  await client.query(
    `WITH canonical AS (
       SELECT s.*, i.id AS ioc_item_id
       FROM ${STAGE_TABLE} s
       JOIN LATERAL (
         SELECT id
         FROM ioc_items
         WHERE observable = s.observable
           AND observable_type = s.observable_type
         ORDER BY created_at ASC, id ASC
         LIMIT 1
       ) i ON TRUE
     )
     INSERT INTO ioc_feed_source_evidence (
       ioc_item_id, ioc_observable_type, feed_id,
       source_name, source_url, category, note, confidence,
       provider_metadata, provider_fingerprint
     )
     SELECT ioc_item_id, observable_type, $1::uuid,
            $2, $3, category, note, NULL, provider_metadata, provider_fingerprint
     FROM canonical
     ON CONFLICT (ioc_item_id, ioc_observable_type, feed_id)
     DO UPDATE SET
       source_name = EXCLUDED.source_name,
       source_url = EXCLUDED.source_url,
       category = EXCLUDED.category,
       note = EXCLUDED.note,
       provider_metadata = EXCLUDED.provider_metadata,
       provider_fingerprint = EXCLUDED.provider_fingerprint,
       updated_at = NOW()
     WHERE ioc_feed_source_evidence.source_name IS DISTINCT FROM EXCLUDED.source_name
        OR ioc_feed_source_evidence.source_url IS DISTINCT FROM EXCLUDED.source_url
        OR ioc_feed_source_evidence.category IS DISTINCT FROM EXCLUDED.category
        OR ioc_feed_source_evidence.note IS DISTINCT FROM EXCLUDED.note
        OR ioc_feed_source_evidence.provider_fingerprint IS DISTINCT FROM EXCLUDED.provider_fingerprint`,
    [feedId, USOM_SOURCE_NAME, USOM_ADDRESS_ENDPOINT]
  );
}

function policySql(policy) {
  if (!policy?.enabled || policy.expiration_mode === 'never') return { expression: 'NULL::timestamptz', params: [] };
  const ttl = Number(policy.ttl_days);
  const grace = Number(policy.grace_days ?? policy.ttl_days);
  if (policy.expiration_mode === 'fixed_ttl' && Number.isFinite(ttl) && ttl > 0) {
    return { expression: `m.first_seen_in_feed + ($3::int * INTERVAL '1 day')`, params: [ttl] };
  }
  if (policy.expiration_mode === 'last_seen_ttl' && Number.isFinite(ttl) && ttl > 0) {
    return { expression: `m.last_seen_in_feed + ($3::int * INTERVAL '1 day')`, params: [ttl] };
  }
  if (policy.expiration_mode === 'missing_from_feed_ttl' && Number.isFinite(grace) && grace > 0) {
    return { expression: `m.missing_since + ($3::int * INTERVAL '1 day')`, params: [grace] };
  }
  return { expression: 'NULL::timestamptz', params: [] };
}

async function applyPoliciesForSeenMemberships(client, feedId, seenAt) {
  for (const observableType of STORED_IOC_TYPES) {
    const policy = await getFeedPolicy(client, feedId, observableType);
    const sql = policySql(policy);
    const policyDays = sql.params[0] ?? null;
    await client.query(
      `WITH computed AS (
         SELECT m.id,
                ${sql.expression} AS policy_expiry,
                -- Type anchor for $3. When the policy mode is 'never' (or disabled)
                -- sql.expression is a bare NULL and never references $3, leaving
                -- PostgreSQL unable to infer the parameter's type ("could not determine
                -- data type of parameter $3"). The parameter list is fixed-arity, so
                -- anchor it here instead of reshuffling placeholders per mode.
                $3::int AS policy_days
         FROM ioc_feed_memberships m
         JOIN ioc_items i
           ON i.id = m.ioc_item_id
          AND i.observable_type = m.ioc_observable_type
         JOIN ${STAGE_TABLE} s
           ON s.observable_type = i.observable_type
          AND s.observable = i.observable
         WHERE m.feed_id = $1::uuid
           AND m.ioc_observable_type = $2
       )
       UPDATE ioc_feed_memberships m
       SET policy_expires_at = c.policy_expiry,
           expires_at = CASE
             WHEN m.override_enabled AND m.override_status = 'expired' THEN 'epoch'::timestamptz
             WHEN m.override_enabled AND m.override_status = 'active' THEN NULL
             WHEN m.override_enabled THEN m.override_expires_at
             ELSE c.policy_expiry
           END,
           status = CASE
             WHEN m.override_enabled AND m.override_status IS NOT NULL THEN m.override_status
             WHEN NOT m.override_enabled AND c.policy_expiry IS NOT NULL AND c.policy_expiry <= $4::timestamptz THEN 'expired'
             ELSE m.status
           END,
           expired_at = CASE
             WHEN NOT m.override_enabled AND c.policy_expiry IS NOT NULL AND c.policy_expiry <= $4::timestamptz
               THEN COALESCE(m.expired_at, $4::timestamptz)
             WHEN NOT m.override_enabled THEN NULL
             ELSE m.expired_at
           END,
           expiration_reason = CASE
             WHEN NOT m.override_enabled AND c.policy_expiry IS NOT NULL AND c.policy_expiry <= $4::timestamptz
               THEN $5
             WHEN NOT m.override_enabled THEN NULL
             ELSE m.expiration_reason
           END,
           updated_at = NOW()
       FROM computed c
       WHERE m.id = c.id
         -- Change guard: skip rows whose computed policy state already matches.
         -- Without this every seen membership took a physical UPDATE (and an
         -- updated_at bump) each run even when nothing about expiry changed.
         AND (
           m.policy_expires_at IS DISTINCT FROM c.policy_expiry
           OR m.expires_at IS DISTINCT FROM (CASE
             WHEN m.override_enabled AND m.override_status = 'expired' THEN 'epoch'::timestamptz
             WHEN m.override_enabled AND m.override_status = 'active' THEN NULL
             WHEN m.override_enabled THEN m.override_expires_at
             ELSE c.policy_expiry
           END)
           OR m.status IS DISTINCT FROM (CASE
             WHEN m.override_enabled AND m.override_status IS NOT NULL THEN m.override_status
             WHEN NOT m.override_enabled AND c.policy_expiry IS NOT NULL AND c.policy_expiry <= $4::timestamptz THEN 'expired'
             ELSE m.status
           END)
           OR m.expired_at IS DISTINCT FROM (CASE
             WHEN NOT m.override_enabled AND c.policy_expiry IS NOT NULL AND c.policy_expiry <= $4::timestamptz
               THEN COALESCE(m.expired_at, $4::timestamptz)
             WHEN NOT m.override_enabled THEN NULL
             ELSE m.expired_at
           END)
           OR m.expiration_reason IS DISTINCT FROM (CASE
             WHEN NOT m.override_enabled AND c.policy_expiry IS NOT NULL AND c.policy_expiry <= $4::timestamptz
               THEN $5
             WHEN NOT m.override_enabled THEN NULL
             ELSE m.expiration_reason
           END)
         )`,
      [
        feedId,
        observableType,
        policyDays,
        seenAt,
        policy?.expiration_mode || 'never'
      ]
    );
  }
}

/**
 * Mark memberships absent from a successful full snapshot as missing.
 *
 * Scope is intentionally UNCHANGED from the pre-fix behaviour: rows already flagged
 * missing are still re-evaluated every run, so an administrator editing grace_days
 * continues to see it applied to currently-missing memberships. That is existing
 * expiration-policy semantics and deliberately out of scope for the no-op work.
 *
 * Because the UPDATE therefore also touches already-missing rows, rowCount is NOT a
 * valid "removed" counter. `newlyMissing` is counted separately with the same
 * predicate plus `missing_since IS NULL`, so `records_removed` reflects genuine
 * active -> missing transitions only.
 *
 * @returns {Promise<{markedMissing:number,newlyMissing:number}>}
 */
async function markMissingMemberships(client, feedId, seenAt) {
  const { rows: stageRows } = await client.query(`SELECT COUNT(*)::int AS count FROM ${STAGE_TABLE}`);
  if (numberFromRow(stageRows[0], 'count') === 0) return { markedMissing: 0, newlyMissing: 0 };
  let markedMissing = 0;
  let newlyMissing = 0;
  for (const observableType of STORED_IOC_TYPES) {
    const policy = await getFeedPolicy(client, feedId, observableType);
    if (!policy?.enabled || policy.expiration_mode !== 'missing_from_feed_ttl') continue;
    const grace = Number(policy.grace_days ?? policy.ttl_days);
    if (!Number.isFinite(grace) || grace <= 0) continue;

    // Count genuine transitions BEFORE the update, while missing_since is still NULL.
    const { rows: transitionRows } = await client.query(
      `SELECT COUNT(*)::int AS newly_missing
       FROM ioc_feed_memberships m
       WHERE m.feed_id = $1::uuid
         AND m.ioc_observable_type = $2
         AND m.status = 'active'
         AND m.missing_since IS NULL
         AND NOT EXISTS (
           SELECT 1
           FROM ioc_items i
           JOIN ${STAGE_TABLE} s
             ON s.observable_type = i.observable_type
            AND s.observable = i.observable
           WHERE i.id = m.ioc_item_id
             AND i.observable_type = m.ioc_observable_type
         )`,
      [feedId, observableType]
    );
    newlyMissing += numberFromRow(transitionRows[0], 'newly_missing');

    const { rowCount } = await client.query(
      `UPDATE ioc_feed_memberships m
       SET missing_since = COALESCE(m.missing_since, $3::timestamptz),
           policy_expires_at = COALESCE(m.missing_since, $3::timestamptz) + ($4::int * INTERVAL '1 day'),
           expires_at = CASE
             WHEN m.override_enabled AND m.override_status = 'expired' THEN 'epoch'::timestamptz
             WHEN m.override_enabled AND m.override_status = 'active' THEN NULL
             WHEN m.override_enabled THEN m.override_expires_at
             ELSE COALESCE(m.missing_since, $3::timestamptz) + ($4::int * INTERVAL '1 day')
           END,
           updated_at = NOW()
       WHERE m.feed_id = $1::uuid
         AND m.ioc_observable_type = $2
         AND m.status = 'active'
         AND NOT EXISTS (
           SELECT 1
           FROM ioc_items i
           JOIN ${STAGE_TABLE} s
             ON s.observable_type = i.observable_type
            AND s.observable = i.observable
           WHERE i.id = m.ioc_item_id
             AND i.observable_type = m.ioc_observable_type
         )`,
      [feedId, observableType, seenAt, grace]
    );
    markedMissing += Number(rowCount || 0);
  }
  return { markedMissing, newlyMissing };
}

async function refreshGlobalIocStatus(client, seenAt) {
  await client.query(
    `WITH touched AS (
       SELECT DISTINCT i.observable, i.observable_type
       FROM ioc_items i
       JOIN ${STAGE_TABLE} s
         ON s.observable_type = i.observable_type
        AND s.observable = i.observable
     ),
     state AS (
       SELECT t.observable, t.observable_type,
              EXISTS (
                SELECT 1
                FROM ioc_items i2
                JOIN ioc_feed_memberships m
                  ON m.ioc_item_id = i2.id
                 AND m.ioc_observable_type = i2.observable_type
                WHERE i2.observable = t.observable
                  AND i2.observable_type = t.observable_type
                  AND m.status = 'active'
                  AND m.purged_at IS NULL
              ) AS has_active_membership,
              (
                SELECT MIN(m.expires_at)
                FROM ioc_items i2
                JOIN ioc_feed_memberships m
                  ON m.ioc_item_id = i2.id
                 AND m.ioc_observable_type = i2.observable_type
                WHERE i2.observable = t.observable
                  AND i2.observable_type = t.observable_type
                  AND m.status = 'active'
                  AND m.purged_at IS NULL
                  AND m.expires_at IS NOT NULL
              ) AS next_expires_at
       FROM touched t
     )
     UPDATE ioc_items i
     SET status = CASE WHEN s.has_active_membership THEN 'active' ELSE 'expired' END,
         expires_at = CASE WHEN s.has_active_membership THEN s.next_expires_at ELSE i.expires_at END,
         expired_at = CASE WHEN s.has_active_membership THEN NULL ELSE COALESCE(i.expired_at, $1::timestamptz) END,
         expiration_reason = CASE WHEN s.has_active_membership THEN NULL ELSE COALESCE(i.expiration_reason, 'all_memberships_expired') END
     FROM state s
     WHERE i.observable = s.observable
       AND i.observable_type = s.observable_type
       AND COALESCE(i.manual_status_override, FALSE) = FALSE
       AND COALESCE(i.status, 'active') NOT IN ('disabled', 'suppressed')
       -- Change guard: only rewrite ioc_items when the derived status actually moves.
       -- Previously every touched IOC took a physical UPDATE on every run.
       AND (
         i.status IS DISTINCT FROM (CASE WHEN s.has_active_membership THEN 'active' ELSE 'expired' END)
         OR i.expires_at IS DISTINCT FROM (CASE WHEN s.has_active_membership THEN s.next_expires_at ELSE i.expires_at END)
         OR i.expired_at IS DISTINCT FROM (CASE WHEN s.has_active_membership THEN NULL ELSE COALESCE(i.expired_at, $1::timestamptz) END)
         OR i.expiration_reason IS DISTINCT FROM (CASE WHEN s.has_active_membership THEN NULL ELSE COALESCE(i.expiration_reason, 'all_memberships_expired') END)
       )`,
    [seenAt]
  );
}

async function saveSuccessfulState(client, {
  feedId,
  stats,
  seenAt,
  mode,
  highwaters,
  snapshotHash,
  snapshotStable = true
}) {
  const total = API_TOTAL_TYPES.reduce((sum, type) => sum + Number(stats?.[`api_total_${type}`] || 0), 0)
    + Number(stats?.api_total_ip6net || 0);
  await client.query(
    `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
     VALUES ($1, $2, $3::jsonb, NOW())
     ON CONFLICT (source_name)
     DO UPDATE SET
       content_hash = COALESCE(EXCLUDED.content_hash, integration_source_state.content_hash),
       items_json = EXCLUDED.items_json,
       updated_at = NOW()`,
    [USOM_SOURCE_NAME, mode === 'full_reconciliation' && snapshotStable ? snapshotHash : null, JSON.stringify({
      provider: 'siberguvenlik.gov.tr',
      total,
      mode,
      reconciliation_complete: mode !== 'full_reconciliation' || snapshotStable,
      completed_at: seenAt.toISOString(),
      totals: Object.fromEntries(USOM_SUPPORTED_TOTAL_KEYS.map((key) => [key, Number(stats?.[key] || 0)]))
    })]
  );
  for (const [iocType, highwater] of Object.entries(highwaters || {})) {
    if (!USOM_SUPPORTED_TOTAL_KEYS.includes(`api_total_${iocType}`) || !highwater?.timestamp || !highwater?.providerId) {
      continue;
    }
    await client.query(
      `INSERT INTO usom_import_cursors (
         feed_id, ioc_type, cursor_timestamp, cursor_provider_id,
         last_incremental_started_at, last_incremental_completed_at,
         cursor_version, updated_at
       )
       VALUES (
         $1::uuid, $2, $3::timestamptz, $4,
         CASE WHEN $5 = 'incremental' THEN $6::timestamptz ELSE NULL END,
         CASE WHEN $5 = 'incremental' THEN NOW() ELSE NULL END,
         1, NOW()
       )
       ON CONFLICT (feed_id, ioc_type)
       DO UPDATE SET
         cursor_timestamp = EXCLUDED.cursor_timestamp,
         cursor_provider_id = EXCLUDED.cursor_provider_id,
         last_incremental_started_at = CASE
           WHEN $5 = 'incremental' THEN EXCLUDED.last_incremental_started_at
           ELSE usom_import_cursors.last_incremental_started_at
         END,
         last_incremental_completed_at = CASE
           WHEN $5 = 'incremental' THEN EXCLUDED.last_incremental_completed_at
           ELSE usom_import_cursors.last_incremental_completed_at
         END,
         cursor_version = 1,
         updated_at = NOW()`,
      [feedId, iocType, highwater.timestamp, highwater.providerId, mode, seenAt]
    );
  }
  if (mode === 'full_reconciliation' && snapshotStable) {
    await client.query(
      `INSERT INTO usom_import_state (
         feed_id, full_snapshot_hash, full_type_highwaters,
         last_full_reconciliation_at, updated_at
       )
       VALUES ($1::uuid, $2, $3::jsonb, $4, NOW())
       ON CONFLICT (feed_id)
       DO UPDATE SET
         full_snapshot_hash = EXCLUDED.full_snapshot_hash,
         full_type_highwaters = EXCLUDED.full_type_highwaters,
         last_full_reconciliation_at = EXCLUDED.last_full_reconciliation_at,
         updated_at = NOW()`,
      [feedId, snapshotHash, JSON.stringify(highwaters || {}), seenAt]
    );
  }
}

const USOM_SUPPORTED_TOTAL_KEYS = Object.freeze([
  'api_total_domain',
  'api_total_url',
  'api_total_ip',
  'api_total_ip6',
  'api_total_ip6net'
]);

export async function finalizeUsomImport(client, {
  stats,
  seenAt = new Date(),
  mode = 'full_reconciliation',
  highwaters = {},
  snapshotHash = null,
  snapshotStable = true,
  priorSnapshotHash = null,
  runId = null,
  runDetails = {},
  inRunDuplicates = 0,
  statementTimeoutMs = DEFAULT_USOM_STATEMENT_TIMEOUT_MS,
  idleInTxTimeoutMs = DEFAULT_USOM_IDLE_IN_TX_TIMEOUT_MS
} = {}) {
  await client.query('BEGIN');
  try {
    await client.query(
      `SELECT
         set_config('statement_timeout', $1, TRUE),
         set_config('idle_in_transaction_session_timeout', $2, TRUE)`,
      [
        `${positiveTimeoutMs(statementTimeoutMs, DEFAULT_USOM_STATEMENT_TIMEOUT_MS)}ms`,
        `${positiveTimeoutMs(idleInTxTimeoutMs, DEFAULT_USOM_IDLE_IN_TX_TIMEOUT_MS)}ms`
      ]
    );
    const feed = await loadFeed(client);
    const suppressed = await removeSuppressedStageEntries(client);
    // Classification must observe pre-run state, so it runs before any write.
    const classified = await classifyStageAgainstExisting(client, feed.integration_id);
    await insertNewIocs(client, feed);
    // Adoption runs after classification (so NULL fingerprints were already counted as
    // unchanged) and before the guarded upsert (so the guard sees a populated value).
    await adoptMissingFingerprints(client, feed.integration_id);
    await upsertMemberships(client, feed.integration_id, seenAt);
    await upsertEvidence(client, feed.integration_id);
    await recordExpirationPresence(client, feed.integration_id, seenAt);
    await applyPoliciesForSeenMemberships(client, feed.integration_id, seenAt);
    const snapshotUnchanged = mode === 'full_reconciliation'
      && Boolean(snapshotHash)
      && Boolean(priorSnapshotHash)
      && snapshotHash === priorSnapshotHash;
    const canSkipAbsentReconciliation = snapshotUnchanged && suppressed === 0;
    // markedMissing = every row the absence UPDATE touched (includes rows that were
    // already missing, so grace_days edits keep applying to them).
    // newlyMissing  = genuine active -> missing transitions, the only valid `removed`.
    const { markedMissing, newlyMissing } = mode === 'full_reconciliation'
      && snapshotStable
      && !canSkipAbsentReconciliation
      ? await markMissingMemberships(client, feed.integration_id, seenAt)
      : { markedMissing: 0, newlyMissing: 0 };
    await refreshGlobalIocStatus(client, seenAt);
    await saveSuccessfulState(client, {
      feedId: feed.integration_id,
      stats,
      seenAt,
      mode,
      highwaters,
      snapshotHash,
      snapshotStable
    });
    // Run counters. created / changed / unchanged / reactivated / removed are mutually
    // exclusive; a row seen again with identical content lands in `unchanged` ONLY and
    // is deliberately absent from changed/updated/reactivated/removed.
    //
    // records_duplicate is DEPRECATED. It is retained as a backward-compatible alias so
    // existing API consumers keep working, and now mirrors records_unchanged instead of
    // its old meaning. New consumers must read records_unchanged. In-run duplicates
    // (the same observable appearing twice inside one payload) are counted as unchanged
    // because they too result in no additional persisted state.
    const unchanged = classified.unchanged + Number(inRunDuplicates || 0);
    const metrics = {
      records_processed: classified.created
        + classified.changed
        + classified.reactivated
        + unchanged
        + Number(stats?.skipped_invalid || 0)
        + Number(stats?.skipped_unsupported_ip_network || 0)
        + suppressed,
      records_inserted: classified.created,
      records_updated: classified.changed,
      records_unchanged: unchanged,
      records_reactivated: classified.reactivated,
      records_removed: newlyMissing,
      records_duplicate: unchanged,
      records_skipped: Number(stats?.skipped_invalid || 0)
        + Number(stats?.skipped_unsupported_ip_network || 0),
      records_suppressed: suppressed,
      records_failed: 0
    };
    const completedRunDetails = {
      ...runDetails,
      mode,
      run_mode: mode,
      duration_ms: Math.max(0, Date.now() - new Date(seenAt).getTime()),
      api_filtered_total: mode === 'incremental'
        ? Number(stats?.api_filtered_total || 0)
        : null,
      pages_fetched: Number(stats?.pages_fetched || 0),
      normalized: Number(stats?.normalized || 0),
      cursor_advanced: Object.keys(highwaters || {}).length > 0,
      in_run_duplicates: Number(inRunDuplicates || 0),
      snapshot_hash: snapshotHash,
      previous_snapshot_hash: priorSnapshotHash,
      snapshot_hash_unchanged: snapshotUnchanged,
      pagination_stable: snapshotStable,
      reconciliation_complete: mode !== 'full_reconciliation' || snapshotStable,
      absent_reconciliation_skipped: mode === 'full_reconciliation'
        && (!snapshotStable || canSkipAbsentReconciliation),
      absent_reconciliation_skip_reason: mode === 'full_reconciliation' && !snapshotStable
        ? 'pagination_changed'
        : canSkipAbsentReconciliation
          ? 'snapshot_unchanged'
          : null,
      snapshot_missing_marked: markedMissing
    };
    if (runId) {
      await client.query(
        `UPDATE integration_runs
         SET status = 'success',
             run_mode = $2,
             finished_at = clock_timestamp(),
             records_processed = $3,
             records_inserted = $4,
             records_updated = $5,
             records_duplicate = $6,
             records_unchanged = $6,
             records_reactivated = $7,
             records_removed = $8,
             records_skipped = $9,
             records_suppressed = $10,
             records_failed = 0,
             error_message = NULL,
             run_details = $11::jsonb
         WHERE id = $1`,
        [
          runId,
          mode,
          metrics.records_processed,
          metrics.records_inserted,
          metrics.records_updated,
          // $6 feeds both records_unchanged (canonical) and records_duplicate (deprecated alias).
          metrics.records_unchanged,
          metrics.records_reactivated,
          metrics.records_removed,
          metrics.records_skipped,
          metrics.records_suppressed,
          JSON.stringify(completedRunDetails)
        ]
      );
    }
    await client.query('COMMIT');
    return {
      ...classified,
      // Deprecated aliases of the classification counters, retained so existing
      // callers/tests keep working. Prefer created/changed/unchanged/reactivated.
      inserted: classified.created,
      updated: classified.changed,
      duplicate: unchanged,
      suppressed,
      markedMissing,
      snapshotUnchanged,
      metrics,
      runDetails: completedRunDetails
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  }
}

export async function dropUsomImportStage(client) {
  await client.query(`DROP TABLE IF EXISTS ${STAGE_TABLE}`);
}
