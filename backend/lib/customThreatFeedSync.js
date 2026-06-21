import { fetchFeedUrl } from './customThreatFeedFetch.js';
import { parseFeedContent } from './customThreatFeedParser.js';
import { sanitizeUrlForDisplay } from './customThreatFeedUtils.js';
import {
  upsertMembershipOnImport,
  recomputeIocGlobalStatus,
  finalizeSnapshotFeedRun,
  withImportOptimizationContext
} from './iocExpiration.js';
import { normalizeConfidence, resolveImportConfidenceFields } from './iocConfidence.js';

const OBSERVABLE_INDEX_TYPES = new Set(['md5', 'sha1', 'sha256', 'hash', 'ip', 'ip6', 'domain', 'url']);

async function insertObservablesIndex(client, iocPublicId, observableType, observable) {
  const t = String(observableType || '').toLowerCase();
  if (!OBSERVABLE_INDEX_TYPES.has(t)) return;
  await client.query(
    `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
     VALUES ($1, $2, $3)
     ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
    [iocPublicId, t, observable]
  );
}

function resolveRowConfidence(rowConfidence, feedDefaultConfidence) {
  const parsed = normalizeConfidence(rowConfidence);
  if (parsed) return parsed;
  return normalizeConfidence(feedDefaultConfidence) || 'medium';
}

async function upsertIocRow(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl,
  defaultConfidence,
  rowConfidence,
  feedId,
  seenAt
}) {
  const explicitConfidence = resolveRowConfidence(rowConfidence, defaultConfidence);
  const confFields = resolveImportConfidenceFields({ parsedSourceConfidence: explicitConfidence });
  const category = 'custom-threat-feed';
  const note = `Imported from Custom Threat Feed: ${sourceName}`;

  const existing = await client.query(
    `SELECT id, public_id, observable_type
     FROM ioc_items
     WHERE observable = $1 AND observable_type = $2
     ORDER BY created_at ASC
     LIMIT 1`,
    [observable, observableType]
  );

  let iocItemId;
  let inserted = false;
  let updated = false;
  let duplicate = false;
  let refreshed = false;

  if (!existing.rowCount) {
    const ins = await client.query(
      `INSERT INTO ioc_items (
         observable, observable_type, source_name, source_url,
         confidence, source_confidence, feed_default_confidence,
         category, note, last_seen_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, public_id`,
      [
        observable,
        observableType,
        sourceName,
        sourceUrl,
        confFields.confidence,
        confFields.source_confidence,
        defaultConfidence,
        category,
        note,
        seenAt
      ]
    );
    iocItemId = ins.rows[0].id;
    await insertObservablesIndex(client, ins.rows[0].public_id, observableType, observable);
    inserted = true;
  } else {
    iocItemId = existing.rows[0].id;
    const upd = await client.query(
      `UPDATE ioc_items
       SET last_seen_at = GREATEST(COALESCE(last_seen_at, $3::timestamptz), $3::timestamptz),
           note = COALESCE(note, $4),
           category = COALESCE(category, $5)
       WHERE id = $1 AND observable_type = $2
       RETURNING public_id`,
      [iocItemId, observableType, seenAt, note, category]
    );
    if (upd.rowCount) {
      updated = true;
      await insertObservablesIndex(client, upd.rows[0].public_id, observableType, observable);
    } else {
      duplicate = true;
    }
  }

  const membershipBefore = await client.query(
    `SELECT id, status FROM ioc_feed_memberships
     WHERE ioc_item_id = $1 AND ioc_observable_type = $2 AND feed_id = $3::uuid`,
    [iocItemId, observableType, feedId]
  );
  const prev = membershipBefore.rows[0];

  await upsertMembershipOnImport(client, {
    iocItemId,
    observableType,
    feedId,
    seenAt,
    explicitConfidence
  });

  if (prev && prev.status === 'active') {
    refreshed = !inserted && !updated;
  } else if (prev && prev.status !== 'active') {
    refreshed = true;
  }

  return {
    iocItemId,
    observableType,
    inserted,
    updated,
    duplicate: duplicate && !refreshed,
    refreshed: refreshed && !inserted && !updated
  };
}

async function expireMissingFromSnapshot(client, integrationFeedId, seenKeys, audit = null) {
  const { marked } = await finalizeSnapshotFeedRun(client, {
    feedId: integrationFeedId,
    seenKeys,
    audit
  });
  return marked;
}

export async function runCustomThreatFeedSync(client, feedRow, options = {}) {
  const startedAt = Date.now();
  const seenAt = new Date();
  const { signal, triggeredBy = 'scheduler', runId = null, queueJobId = null } = options;

  const sourceName = feedRow.feed_name;
  const sourceUrl = sanitizeUrlForDisplay(feedRow.url);
  const integrationFeedId = feedRow.integration_feed_id;
  const feedId = feedRow.id;

  let customRunId = runId;
  if (!customRunId) {
    const ins = await client.query(
      `INSERT INTO custom_threat_feed_runs (
         feed_id, integration_feed_id, queue_job_id, status, triggered_by
       ) VALUES ($1::uuid, $2::uuid, $3, 'running', $4)
       RETURNING id`,
      [feedId, integrationFeedId, queueJobId, triggeredBy]
    );
    customRunId = ins.rows[0].id;
  }

  const counters = {
    total_rows: 0,
    valid_rows: 0,
    invalid_rows: 0,
    inserted: 0,
    updated: 0,
    refreshed: 0,
    duplicate_rows: 0,
    expired_missing: 0,
    fetched_bytes: 0,
    http_status: null
  };
  let invalidSamples = [];
  let errorMessage = null;
  let status = 'success';

  try {
    if (signal?.aborted) throw new Error('Sync aborted');

    const fetchResult = await fetchFeedUrl(feedRow.url, { timeoutMs: feedRow.timeout_ms });
    counters.http_status = fetchResult.httpStatus;
    counters.fetched_bytes = fetchResult.fetchedBytes;

    if (!fetchResult.ok) {
      throw new Error(`HTTP ${fetchResult.httpStatus}: fetch failed`);
    }

    const parsed = parseFeedContent(fetchResult.bodyText, {
      format: feedRow.format,
      contentType: fetchResult.contentType,
      url: feedRow.url,
      iocTypeMode: feedRow.ioc_type_mode,
      fixedIocType: feedRow.fixed_ioc_type
    });

    counters.total_rows = parsed.totalRows;
    counters.valid_rows = parsed.valid.length;
    counters.invalid_rows = parsed.invalidRows.length;
    invalidSamples = parsed.invalidRows;

    await withImportOptimizationContext(client, async () => {
      const seenKeys = new Set();
      for (const row of parsed.valid) {
        if (signal?.aborted) throw new Error('Sync aborted');
        const result = await upsertIocRow(client, {
          observable: row.observable,
          observableType: row.observableType,
          sourceName,
          sourceUrl,
          defaultConfidence: feedRow.default_confidence,
          rowConfidence: row.confidence,
          feedId: integrationFeedId,
          seenAt
        });
        if (result.inserted) counters.inserted += 1;
        else if (result.updated) counters.updated += 1;
        else if (result.refreshed) counters.refreshed += 1;
        else if (result.duplicate) counters.duplicate_rows += 1;
        seenKeys.add(`${result.observableType}|${result.iocItemId}`);
      }

      counters.expired_missing = await expireMissingFromSnapshot(client, integrationFeedId, seenKeys);
    });

    if (counters.invalid_rows > 0 && counters.valid_rows > 0) status = 'partial_success';
    else if (counters.valid_rows === 0 && counters.total_rows > 0) status = 'failed';
    else status = 'success';
  } catch (err) {
    status = 'failed';
    errorMessage = String(err?.message || err).slice(0, 4000);
  }

  const durationMs = Date.now() - startedAt;
  await client.query(
    `UPDATE custom_threat_feed_runs
     SET status = $2,
         finished_at = NOW(),
         duration_ms = $3,
         fetched_bytes = $4,
         http_status = $5,
         total_rows = $6,
         valid_rows = $7,
         invalid_rows = $8,
         inserted = $9,
         updated = $10,
         refreshed = $11,
         expired_missing = $12,
         duplicate_rows = $13,
         error_message = $14,
         invalid_samples = $15::jsonb
     WHERE id = $1::uuid`,
    [
      customRunId,
      status,
      durationMs,
      counters.fetched_bytes,
      counters.http_status,
      counters.total_rows,
      counters.valid_rows,
      counters.invalid_rows,
      counters.inserted,
      counters.updated,
      counters.refreshed,
      counters.expired_missing,
      counters.duplicate_rows,
      errorMessage,
      JSON.stringify(invalidSamples.slice(0, 20))
    ]
  );

  await client.query(
    `INSERT INTO integration_runs (
       job_type, status, started_at, finished_at, triggered_by,
       records_processed, records_inserted, records_updated,
       records_duplicate, records_skipped, records_failed, error_message
     ) VALUES (
       'custom_threat_feed_sync', $1, to_timestamp($2 / 1000.0), NOW(), $3,
       $4, $5, $6, $7, $8, $9, $10
     )`,
    [
      status === 'failed' ? 'failed' : 'success',
      startedAt,
      triggeredBy,
      counters.total_rows,
      counters.inserted,
      counters.updated + counters.refreshed,
      counters.duplicate_rows,
      counters.invalid_rows,
      status === 'failed' ? 1 : 0,
      errorMessage
    ]
  );

  return {
    run_id: customRunId,
    status,
    duration_ms: durationMs,
    ...counters,
    error_message: errorMessage,
    invalid_samples: invalidSamples.slice(0, 20),
    feed_id: feedId,
    feed_name: sourceName
  };
}

export async function loadCustomFeedForSync(client, customFeedId) {
  const { rows } = await client.query(
    `SELECT c.*,
            f.integration_id AS integration_feed_id,
            f.key AS integration_key,
            f.name AS feed_name,
            f.default_confidence,
            f.active AS integration_active
     FROM custom_threat_feeds c
     JOIN integration_feeds f ON f.integration_id = c.feed_id
     WHERE c.id = $1::uuid
     LIMIT 1`,
    [customFeedId]
  );
  return rows[0] || null;
}

export async function loadCustomFeedByIntegrationKey(client, integrationKey) {
  const { rows } = await client.query(
    `SELECT c.*,
            f.integration_id AS integration_feed_id,
            f.key AS integration_key,
            f.name AS feed_name,
            f.schedule_cron AS schedule,
            f.default_confidence,
            f.active AS integration_active
     FROM custom_threat_feeds c
     JOIN integration_feeds f ON f.integration_id = c.feed_id
     WHERE f.key = $1
     LIMIT 1`,
    [integrationKey]
  );
  return rows[0] || null;
}
