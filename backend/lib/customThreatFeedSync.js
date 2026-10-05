import { fetchFeedUrl } from './customThreatFeedFetch.js';
import { parseFeedContent } from './customThreatFeedParser.js';
import { sanitizeUrlForDisplay } from './customThreatFeedUtils.js';
import { redactCustomFeedSecrets } from './customThreatFeedAuth.js';
import { computeCustomThreatFeedContentFingerprint } from './customThreatFeedFingerprint.js';
import {
  upsertMembershipOnImport,
  finalizeSnapshotFeedRun,
  withImportOptimizationContext
} from './iocExpiration.js';
import { normalizeConfidence, resolveImportConfidenceFields } from './iocConfidence.js';
import { QUEUE_HARDENING } from './integrationQueueConfig.js';

const OBSERVABLE_INDEX_TYPES = new Set(['md5', 'sha1', 'sha256', 'hash', 'ip', 'ipv6', 'domain', 'url']);

const DUAL_WRITE_LOG = '[custom-threat-feed]';
const DUAL_WRITE_MESSAGE_MAX = 300;
const DUAL_WRITE_MAX_ERROR_CODES = 5;

const loadFileArtifactDualWrite = () => import('./fileArtifacts/dualWrite.js');

/**
 * Per-run aggregation of best-effort file-artifact dual-write failures.
 *
 * Dual-write never fails the feed import, but must never be silent either: the
 * first failure of a run is logged immediately and flush() logs one summary, so a
 * broken module/DB path yields 2 lines per run, not one per feed row. Lines carry
 * feed ids, observable type and error code/class, never the observable itself
 * or feed credentials.
 *
 * @param {{ feedId?: string|null, integrationKey?: string|null, runId?: string|null,
 *   credentials?: object|null, logger?: { warn: Function } }} ctx
 */
export function createFileArtifactDualWriteFailureTracker({
  feedId = null,
  integrationKey = null,
  runId = null,
  credentials = null,
  logger = console
} = {}) {
  let attempted = 0;
  let failed = 0;
  let firstError = null;
  const byType = new Map();
  const byCode = new Map();
  const ids = `feed=${feedId || '-'} integration_key=${integrationKey || '-'} run=${runId || '-'}`;

  const safeMessage = (message, observable) => {
    let msg = String(message || '');
    if (observable) msg = msg.split(String(observable)).join('<observable>');
    msg = redactCustomFeedSecrets(msg, credentials) || '';
    return msg.replace(/\s+/g, ' ').trim().slice(0, DUAL_WRITE_MESSAGE_MAX);
  };

  return {
    noteAttempt() {
      attempted += 1;
    },
    /**
     * @param {any} err - thrown error, or a dual-write `{ ok: false }` result
     * @param {{ observableType?: string|null, observable?: string|null }} row
     */
    record(err, { observableType = null, observable = null } = {}) {
      failed += 1;
      const type = String(observableType || 'unknown').toLowerCase();
      byType.set(type, (byType.get(type) || 0) + 1);
      const code = String(err?.code || err?.name || 'unknown');
      if (byCode.has(code) || byCode.size < DUAL_WRITE_MAX_ERROR_CODES) {
        byCode.set(code, (byCode.get(code) || 0) + 1);
      }
      if (firstError) return;
      firstError = {
        code,
        error_class: err instanceof Error ? err.constructor.name : 'DualWriteResult',
        message: safeMessage(err instanceof Error ? err.message : (err?.error ?? err), observable)
      };
      logger.warn(
        `${DUAL_WRITE_LOG} file_artifact_dual_write_failed ${ids} observable_type=${type}`
        + ` error_code=${firstError.code} error_class=${firstError.error_class}`
        + ` message=${JSON.stringify(firstError.message)} (further failures this run are aggregated)`
      );
    },
    summary() {
      return {
        attempted,
        failed,
        by_type: Object.fromEntries(byType),
        error_codes: Object.fromEntries(byCode),
        first_error: firstError
      };
    },
    flush() {
      if (!failed) return;
      const fmt = (m) => [...m].map(([k, v]) => `${k}:${v}`).join(',');
      logger.warn(
        `${DUAL_WRITE_LOG} file_artifact_dual_write_failures ${ids} failed=${failed} attempted=${attempted}`
        + ` by_type=${fmt(byType)} error_codes=${fmt(byCode)} first_error=${firstError?.code || 'unknown'}`
      );
    }
  };
}

/**
 * Best-effort file-artifact dual-write for one imported feed row. Never throws;
 * failures (module load, thrown errors, `{ ok: false }` results) go to the tracker.
 */
async function dualWriteRowFileArtifact(client, {
  iocItemId,
  existingPublicId,
  observable,
  observableType,
  sourceName,
  feedId,
  note,
  confidence,
  seenAt
}, { tracker = null, loadDualWrite = loadFileArtifactDualWrite } = {}) {
  try {
    const { dualWriteFileArtifactForObservable } = await loadDualWrite();
    const publicId = existingPublicId
      || (await client.query(
        `SELECT public_id FROM ioc_items WHERE id = $1 AND observable_type = $2`,
        [iocItemId, observableType]
      )).rows[0]?.public_id;
    if (!publicId) return;
    tracker?.noteAttempt();
    const result = await dualWriteFileArtifactForObservable(client, {
      observable,
      observableType,
      sourceName,
      feedId,
      note,
      confidence,
      firstSeenAt: seenAt,
      lastSeenAt: seenAt,
      attachNoteSiblings: false,
      providerMapping: false
    });
    if (result?.ok === false) tracker?.record(result, { observableType, observable });
  } catch (err) {
    // dual-write must never fail custom feed sync, and must never be silent
    tracker?.record(err, { observableType, observable });
  }
}

/** Error stamped onto custom_threat_feed_runs left `running` past the stale window. */
export const STALE_CUSTOM_THREAT_FEED_RUN_MESSAGE = 'interrupted: stale running run reconciled';

/**
 * Mark custom_threat_feed_runs still `running` with started_at older than the
 * threshold as failed. Mirrors recoverStaleRunningJobs / integration_runs reconcile.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {{ staleAfterMs?: number, dryRun?: boolean, logPrefix?: string }} [opts]
 */
export async function reconcileStaleCustomThreatFeedRuns(pool, {
  staleAfterMs = QUEUE_HARDENING.staleAfterMs,
  dryRun = false,
  logPrefix = '[integration-worker]'
} = {}) {
  const ms = Math.max(Number(staleAfterMs) || QUEUE_HARDENING.staleAfterMs, 60_000);

  if (dryRun) {
    const q = await pool.query(
      `SELECT id
         FROM custom_threat_feed_runs
        WHERE status = 'running'
          AND started_at < NOW() - ($1::text || ' milliseconds')::interval`,
      [String(ms)]
    );
    return { fixedCount: q.rowCount || 0, dryRun: true };
  }

  const res = await pool.query(
    `UPDATE custom_threat_feed_runs
        SET status = 'failed',
            finished_at = COALESCE(finished_at, NOW()),
            error_message = COALESCE(error_message, $1)
      WHERE status = 'running'
        AND started_at < NOW() - ($2::text || ' milliseconds')::interval
      RETURNING id`,
    [STALE_CUSTOM_THREAT_FEED_RUN_MESSAGE, String(ms)]
  );

  const fixedCount = res.rowCount || 0;
  if (fixedCount > 0) {
    console.log(`${logPrefix} Reconciled stale custom_threat_feed_runs count=${fixedCount}`);
  }
  return { fixedCount, dryRun: false };
}

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

/**
 * Import one normalized custom-feed row.
 *
 * Uses membership content_fingerprint (migration 121) so unchanged re-imports do not
 * bump last_seen_in_feed / updated_at / last_changed_in_source — same semantics as USOM.
 */
async function upsertIocRow(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl,
  defaultConfidence,
  rowConfidence,
  feedId,
  seenAt
}, dualWrite = {}) {
  const explicitConfidence = resolveRowConfidence(rowConfidence, defaultConfidence);
  const confFields = resolveImportConfidenceFields({ parsedSourceConfidence: explicitConfidence });
  const contentFingerprint = computeCustomThreatFeedContentFingerprint({
    observable,
    observableType,
    confidence: explicitConfidence
  });
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
  let iocCreated = false;

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
    iocCreated = true;
  } else {
    iocItemId = existing.rows[0].id;
  }

  const membershipResult = await upsertMembershipOnImport(client, {
    iocItemId,
    observableType,
    feedId,
    seenAt,
    explicitConfidence,
    contentFingerprint
  });

  const outcome = membershipResult?.outcome || 'unchanged';

  // Fill sparse note/category only when membership content actually changed or is new.
  // Never advance ioc_items.last_seen_at on unchanged/adopted rows — list Timestamp is
  // driven by membership last_seen_in_feed, which the fingerprint guard already protects.
  if (!iocCreated && (outcome === 'changed' || outcome === 'reactivated' || outcome === 'created')) {
    await client.query(
      `UPDATE ioc_items
       SET note = COALESCE(note, $3),
           category = COALESCE(category, $4)
       WHERE id = $1 AND observable_type = $2
         AND (
           note IS NULL
           OR category IS NULL
         )`,
      [iocItemId, observableType, note, category]
    );
    if (existing.rowCount) {
      await insertObservablesIndex(client, existing.rows[0].public_id, observableType, observable);
    }
  }

  // File artifact dual-write: Custom Feed observed-as = the hash type it actually sent.
  await dualWriteRowFileArtifact(client, {
    iocItemId,
    existingPublicId: existing.rowCount ? existing.rows[0].public_id : null,
    observable,
    observableType,
    sourceName,
    feedId,
    note,
    confidence: confFields.confidence,
    seenAt
  }, dualWrite);

  return {
    iocItemId,
    observableType,
    outcome,
    inserted: outcome === 'created' || iocCreated,
    updated: outcome === 'changed',
    refreshed: outcome === 'reactivated',
    unchanged: outcome === 'unchanged' || outcome === 'adopted',
    adopted: outcome === 'adopted',
    duplicate: false
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
  const {
    signal,
    triggeredBy = 'scheduler',
    runId = null,
    queueJobId = null,
    fetchFeed = fetchFeedUrl,
    loadDualWrite = loadFileArtifactDualWrite,
    logger = console
  } = options;

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

  const dualWriteTracker = createFileArtifactDualWriteFailureTracker({
    feedId,
    integrationKey: feedRow.integration_key || null,
    runId: customRunId,
    credentials: feedRow.credentials || null,
    logger
  });

  const counters = {
    total_rows: 0,
    valid_rows: 0,
    invalid_rows: 0,
    inserted: 0,
    updated: 0,
    refreshed: 0,
    unchanged: 0,
    adopted: 0,
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

    const fetchResult = await fetchFeed(feedRow.url, {
      timeoutMs: feedRow.timeout_ms,
      credentials: feedRow.credentials || null
    });
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
      const seenObservables = new Set();
      for (const row of parsed.valid) {
        if (signal?.aborted) throw new Error('Sync aborted');
        const obsKey = `${row.observableType}|${row.observable}`;
        if (seenObservables.has(obsKey)) {
          counters.duplicate_rows += 1;
          continue;
        }
        seenObservables.add(obsKey);

        const result = await upsertIocRow(client, {
          observable: row.observable,
          observableType: row.observableType,
          sourceName,
          sourceUrl,
          defaultConfidence: feedRow.default_confidence,
          rowConfidence: row.confidence,
          feedId: integrationFeedId,
          seenAt
        }, { tracker: dualWriteTracker, loadDualWrite });
        if (result.inserted) counters.inserted += 1;
        else if (result.updated) counters.updated += 1;
        else if (result.refreshed) counters.refreshed += 1;
        else if (result.adopted) {
          counters.adopted += 1;
          counters.unchanged += 1;
          counters.duplicate_rows += 1;
        } else if (result.unchanged) {
          counters.unchanged += 1;
          counters.duplicate_rows += 1;
        }
        seenKeys.add(`${result.observableType}|${result.iocItemId}`);
      }

      counters.expired_missing = await expireMissingFromSnapshot(client, integrationFeedId, seenKeys);
    });

    if (counters.invalid_rows > 0 && counters.valid_rows > 0) status = 'partial_success';
    else if (counters.valid_rows === 0 && counters.total_rows > 0) status = 'failed';
    else status = 'success';
  } catch (err) {
    status = 'failed';
    const rawMessage = String(err?.message || err).slice(0, 4000);
    errorMessage = redactCustomFeedSecrets(rawMessage, feedRow.credentials || null);
  }

  dualWriteTracker.flush();
  const fileArtifactDualWrite = dualWriteTracker.summary();

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
       records_duplicate, records_unchanged, records_reactivated, records_removed,
       records_skipped, records_failed, error_message
     ) VALUES (
       'custom_threat_feed_sync', $1, to_timestamp($2 / 1000.0), NOW(), $3,
       $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
     )`,
    [
      status === 'failed' ? 'failed' : 'success',
      startedAt,
      triggeredBy,
      counters.total_rows,
      counters.inserted,
      counters.updated,
      counters.duplicate_rows,
      counters.unchanged,
      counters.refreshed,
      counters.expired_missing,
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
    file_artifact_dual_write_failures: fileArtifactDualWrite.failed,
    file_artifact_dual_write_first_error: fileArtifactDualWrite.first_error?.code || null,
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
            f.active AS integration_active,
            f.credentials,
            ls.finished_at AS last_success_at
     FROM custom_threat_feeds c
     JOIN integration_feeds f ON f.integration_id = c.feed_id
     LEFT JOIN LATERAL (
       SELECT finished_at
       FROM custom_threat_feed_runs r
       WHERE r.feed_id = c.id AND r.status IN ('success', 'partial_success')
       ORDER BY finished_at DESC NULLS LAST
       LIMIT 1
     ) ls ON TRUE
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
            f.active AS integration_active,
            f.credentials,
            ls.finished_at AS last_success_at
     FROM custom_threat_feeds c
     JOIN integration_feeds f ON f.integration_id = c.feed_id
     LEFT JOIN LATERAL (
       SELECT finished_at
       FROM custom_threat_feed_runs r
       WHERE r.feed_id = c.id AND r.status IN ('success', 'partial_success')
       ORDER BY finished_at DESC NULLS LAST
       LIMIT 1
     ) ls ON TRUE
     WHERE f.key = $1
     LIMIT 1`,
    [integrationKey]
  );
  return rows[0] || null;
}
