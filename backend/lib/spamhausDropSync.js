import crypto from 'node:crypto';

export const SPAMHAUS_DROP_PROVIDER = 'spamhaus_drop';
export const SPAMHAUS_DROP_LIST_TYPES = Object.freeze(['drop_v4', 'drop_v6']);
export const ALLOWED_SYNC_INTERVALS = Object.freeze([6, 12, 24]);

export const SPAMHAUS_DROP_URLS = Object.freeze({
  drop_v4: 'https://www.spamhaus.org/drop/drop_v4.json',
  drop_v6: 'https://www.spamhaus.org/drop/drop_v6.json'
});

// Suspicious-drop guard: if prev count > MIN and new count < prev * RATIO → abort
const SUSPICIOUS_MIN_PREVIOUS_COUNT = Number(process.env.SPAMHAUS_DROP_SUSPICIOUS_MIN_COUNT || 50);
const SUSPICIOUS_RATIO = Number(process.env.SPAMHAUS_DROP_SUSPICIOUS_RATIO || 0.5);

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

export async function getSpamhausDropConfig(pool) {
  const { rows } = await pool.query(
    `SELECT enabled, timeout_ms, config FROM threat_intel_provider_configs WHERE provider = $1`,
    [SPAMHAUS_DROP_PROVIDER]
  );
  if (!rows.length) {
    return { enabled: false, sync_interval_hours: 24, timeout_ms: 30000 };
  }
  const row = rows[0];
  const cfg = row.config || {};
  const sync_interval_hours = ALLOWED_SYNC_INTERVALS.includes(Number(cfg.sync_interval_hours))
    ? Number(cfg.sync_interval_hours)
    : 24;
  return {
    enabled: Boolean(row.enabled),
    sync_interval_hours,
    timeout_ms: Number(row.timeout_ms || 30000)
  };
}

export async function getSpamhausDropSyncState(pool) {
  const { rows } = await pool.query(
    `SELECT * FROM spamhaus_drop_sync_state ORDER BY list_type`
  );
  return rows;
}

export function validateSyncIntervalHours(value) {
  const n = Number(value);
  if (!ALLOWED_SYNC_INTERVALS.includes(n)) {
    return { ok: false, error: 'Invalid sync interval. Allowed values are 6, 12, 24 hours.' };
  }
  return { ok: true, value: n };
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/**
 * Local CIDR lookup — no external call.
 * @returns {{ found: boolean, cidr?: string, sblid?: string, rir?: string, list_type?: string, synced_at?: Date } | null}
 */
export async function lookupIpInSpamhausDrop(pool, ip) {
  if (!ip || typeof ip !== 'string') return null;
  const cleanIp = String(ip).trim().split('/')[0].trim();
  if (!cleanIp) return null;

  try {
    const { rows } = await pool.query(
      `SELECT cidr::text AS cidr, sblid, rir, list_type, synced_at
       FROM spamhaus_drop_entries
       WHERE $1::inet << cidr
       ORDER BY masklen(cidr) DESC
       LIMIT 1`,
      [cleanIp]
    );
    if (!rows.length) return { found: false };
    const row = rows[0];
    return {
      found: true,
      cidr: row.cidr,
      sblid: row.sblid,
      rir: row.rir,
      list_type: row.list_type,
      synced_at: row.synced_at
    };
  } catch (err) {
    const msg = String(err?.message || err);
    if (msg.includes('invalid input syntax') || msg.includes('invalid_text_representation')) {
      const e = new Error(`Invalid IP address: ${cleanIp}`);
      e.code = 'invalid_ip';
      throw e;
    }
    throw err;
  }
}

/**
 * Build the canonical API response for a Spamhaus DROP lookup.
 */
export function buildSpamhausLookupResponse({ lookup, syncState, config, targetIp, notApplicable = false }) {
  const provider = SPAMHAUS_DROP_PROVIDER;

  if (!config.enabled) {
    return { provider, status: 'disabled', listed: null, reason: 'Spamhaus DROP provider is disabled.' };
  }
  if (notApplicable) {
    return {
      provider,
      status: 'not_applicable',
      listed: null,
      reason: 'Spamhaus DROP only supports IP IOCs or URL IOCs with an IP host.'
    };
  }

  const v4State = syncState?.find((s) => s.list_type === 'drop_v4');
  const v6State = syncState?.find((s) => s.list_type === 'drop_v6');
  const lastSyncAt = laterDate(v4State?.last_success_at, v6State?.last_success_at);

  if (!lastSyncAt) {
    return { provider, status: 'dataset_not_synced', listed: null };
  }

  const datasetStatus = computeDatasetStatus(v4State, v6State);

  if (!lookup?.found) {
    return {
      provider,
      status: 'not_listed',
      listed: false,
      target_ip: targetIp,
      last_sync_at: lastSyncAt,
      dataset_status: datasetStatus
    };
  }

  return {
    provider,
    status: 'listed',
    listed: true,
    target_ip: targetIp,
    matched_cidr: lookup.cidr,
    sblid: lookup.sblid,
    rir: lookup.rir,
    list_type: lookup.list_type,
    last_sync_at: lastSyncAt,
    dataset_status: datasetStatus
  };
}

function laterDate(a, b) {
  if (!a && !b) return null;
  if (!a) return b;
  if (!b) return a;
  return new Date(a) > new Date(b) ? a : b;
}

function computeDatasetStatus(v4State, v6State) {
  const statuses = [v4State?.status, v6State?.status].filter(Boolean);
  if (!statuses.length) return 'never_synced';
  if (statuses.every((s) => s === 'healthy')) return 'healthy';
  if (statuses.some((s) => s === 'failed')) return 'failed';
  if (statuses.some((s) => s === 'running')) return 'running';
  if (statuses.some((s) => s === 'suspicious')) return 'suspicious';
  return 'never_synced';
}

// ---------------------------------------------------------------------------
// JSON parsing (exported for tests)
// ---------------------------------------------------------------------------

export function parseDropJson(text, listType) {
  const trimmed = String(text || '').trim();

  // If the payload starts with '[', treat as a JSON array (legacy/future format).
  if (trimmed.startsWith('[')) {
    let data;
    try {
      data = JSON.parse(trimmed);
    } catch (err) {
      const e = new Error(`Invalid JSON from ${listType}: ${err.message}`);
      e.code = 'parse_error';
      throw e;
    }
    if (!Array.isArray(data)) {
      const e = new Error(`Expected JSON array for ${listType}, got ${typeof data}`);
      e.code = 'parse_error';
      throw e;
    }
    return data;
  }

  // NDJSON: one JSON object per line (current Spamhaus format).
  const lines = trimmed.split('\n');
  const items = [];
  let parseErrors = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith(';') || line.startsWith('#')) continue;
    try {
      const obj = JSON.parse(line);
      if (obj !== null && typeof obj === 'object' && !Array.isArray(obj)) {
        items.push(obj);
      } else {
        parseErrors++;
      }
    } catch {
      parseErrors++;
    }
  }

  if (items.length === 0) {
    const detail = parseErrors > 0 ? `all ${parseErrors} lines failed to parse as JSON objects` : 'no data lines found';
    const e = new Error(`Invalid JSON from ${listType}: ${detail}`);
    e.code = 'parse_error';
    throw e;
  }

  return items;
}

export function parseCidrItem(item) {
  if (!item || typeof item !== 'object') return null;
  const cidr = String(item.cidr || '').trim();
  if (!cidr || !cidr.includes('/')) return null;
  return {
    cidr,
    sblid: typeof item.sblid === 'string' ? item.sblid.trim().slice(0, 64) : null,
    rir: typeof item.rir === 'string' ? item.rir.trim().slice(0, 32) : null,
    raw_json: item
  };
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

async function fetchListJson(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status} fetching ${url}`);
      err.code = 'http_error';
      err.httpStatus = res.status;
      throw err;
    }
    return await res.text();
  } catch (err) {
    if (err?.name === 'AbortError') {
      const e = new Error(`Fetch timed out after ${timeoutMs}ms for ${url}`);
      e.code = 'timeout';
      throw e;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function computeNextRunAt(syncIntervalHours) {
  const h = ALLOWED_SYNC_INTERVALS.includes(Number(syncIntervalHours)) ? Number(syncIntervalHours) : 24;
  return new Date(Date.now() + h * 60 * 60 * 1000);
}

/**
 * Sync a single list type. Fetches, validates, and atomically replaces the dataset.
 * On any failure before the transaction, existing data is untouched.
 */
export async function runSpamhausDropListSync(pool, listType, options = {}) {
  const { timeoutMs = 30000, syncIntervalHours = 24, signal } = options;
  const url = SPAMHAUS_DROP_URLS[listType];
  if (!url) throw new Error(`Unknown list_type: ${listType}`);

  const startedAt = Date.now();

  // Mark attempt
  await pool.query(
    `UPDATE spamhaus_drop_sync_state
     SET status = 'running', last_attempt_at = NOW(), error_message = NULL, updated_at = NOW()
     WHERE list_type = $1`,
    [listType]
  );

  // --- Phase 1: fetch (outside transaction, failure safe) ---
  let text;
  try {
    if (signal?.aborted) throw new Error('Sync aborted before fetch');
    text = await fetchListJson(url, timeoutMs);
  } catch (err) {
    const msg = String(err?.message || err).slice(0, 2000);
    await pool.query(
      `UPDATE spamhaus_drop_sync_state SET status = 'failed', error_message = $2, updated_at = NOW() WHERE list_type = $1`,
      [listType, msg]
    );
    return { ok: false, error: msg, list_type: listType, duration_ms: Date.now() - startedAt };
  }

  const sha256 = crypto.createHash('sha256').update(text).digest('hex');

  // --- Phase 2: parse (outside transaction, failure safe) ---
  let rawItems;
  try {
    rawItems = parseDropJson(text, listType);
  } catch (err) {
    const msg = String(err?.message || err).slice(0, 2000);
    await pool.query(
      `UPDATE spamhaus_drop_sync_state SET status = 'failed', error_message = $2, updated_at = NOW() WHERE list_type = $1`,
      [listType, msg]
    );
    return { ok: false, error: msg, list_type: listType, duration_ms: Date.now() - startedAt };
  }

  // Empty dataset guard
  if (rawItems.length === 0) {
    const msg = `Empty dataset received for ${listType} — aborting to protect existing data`;
    await pool.query(
      `UPDATE spamhaus_drop_sync_state SET status = 'suspicious', error_message = $2, updated_at = NOW() WHERE list_type = $1`,
      [listType, msg]
    );
    return { ok: false, error: msg, list_type: listType, suspicious: true, duration_ms: Date.now() - startedAt };
  }

  // Parse individual items
  let invalidCount = 0;
  const parsedItems = [];
  for (const item of rawItems) {
    const parsed = parseCidrItem(item);
    if (parsed) parsedItems.push(parsed);
    else invalidCount++;
  }

  if (parsedItems.length === 0) {
    const msg = `All ${rawItems.length} items failed CIDR parsing for ${listType}`;
    await pool.query(
      `UPDATE spamhaus_drop_sync_state SET status = 'failed', error_message = $2, updated_at = NOW() WHERE list_type = $1`,
      [listType, msg]
    );
    return { ok: false, error: msg, list_type: listType, duration_ms: Date.now() - startedAt };
  }

  // Suspicious drop guard
  const prevStateRes = await pool.query(
    `SELECT entry_count FROM spamhaus_drop_sync_state WHERE list_type = $1`,
    [listType]
  );
  const prevCount = Number(prevStateRes.rows[0]?.entry_count || 0);
  const newCount = parsedItems.length;

  if (prevCount > SUSPICIOUS_MIN_PREVIOUS_COUNT && newCount < prevCount * SUSPICIOUS_RATIO) {
    const msg = `Suspicious size drop for ${listType}: previous=${prevCount} new=${newCount} (threshold=${SUSPICIOUS_RATIO * 100}%) — aborting`;
    await pool.query(
      `UPDATE spamhaus_drop_sync_state SET status = 'suspicious', error_message = $2, updated_at = NOW() WHERE list_type = $1`,
      [listType, msg]
    );
    return { ok: false, error: msg, list_type: listType, suspicious: true, duration_ms: Date.now() - startedAt };
  }

  if (signal?.aborted) {
    const msg = 'Sync aborted before database write';
    await pool.query(
      `UPDATE spamhaus_drop_sync_state SET status = 'failed', error_message = $2, updated_at = NOW() WHERE list_type = $1`,
      [listType, msg]
    );
    return { ok: false, error: msg, list_type: listType, duration_ms: Date.now() - startedAt };
  }

  // --- Phase 3: atomic replace (inside transaction) ---
  const client = await pool.connect();
  let removedCount = 0;
  try {
    await client.query('BEGIN');

    // Count existing before delete for removed_count
    const existingRes = await client.query(
      `SELECT COUNT(*)::int AS cnt FROM spamhaus_drop_entries WHERE list_type = $1`,
      [listType]
    );
    removedCount = Number(existingRes.rows[0]?.cnt || 0);

    // Hard delete old entries
    await client.query(`DELETE FROM spamhaus_drop_entries WHERE list_type = $1`, [listType]);

    // Bulk insert new entries
    const now = new Date();
    for (const item of parsedItems) {
      await client.query(
        `INSERT INTO spamhaus_drop_entries (list_type, cidr, sblid, rir, raw_json, synced_at, created_at)
         VALUES ($1, $2::cidr, $3, $4, $5::jsonb, $6, $6)
         ON CONFLICT (list_type, cidr) DO NOTHING`,
        [listType, item.cidr, item.sblid, item.rir, JSON.stringify(item.raw_json), now]
      );
    }

    const nextRunAt = computeNextRunAt(syncIntervalHours);

    await client.query(
      `UPDATE spamhaus_drop_sync_state SET
         status          = 'healthy',
         last_success_at = NOW(),
         last_attempt_at = NOW(),
         next_run_at     = $2,
         entry_count     = $3,
         added_count     = $4,
         removed_count   = $5,
         source_url      = $6,
         dataset_sha256  = $7,
         error_message   = NULL,
         updated_at      = NOW()
       WHERE list_type = $1`,
      [listType, nextRunAt, newCount, newCount, removedCount, url, sha256]
    );

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    const msg = String(err?.message || err).slice(0, 2000);
    await pool.query(
      `UPDATE spamhaus_drop_sync_state SET status = 'failed', error_message = $2, updated_at = NOW() WHERE list_type = $1`,
      [listType, msg]
    );
    return { ok: false, error: msg, list_type: listType, duration_ms: Date.now() - startedAt };
  } finally {
    client.release();
  }

  return {
    ok: true,
    list_type: listType,
    entry_count: newCount,
    added_count: newCount,
    removed_count: removedCount,
    invalid_count: invalidCount,
    dataset_sha256: sha256,
    duration_ms: Date.now() - startedAt
  };
}

/**
 * Sync both DROP v4 and v6 list types sequentially.
 */
export async function runSpamhausDropSync(pool, options = {}) {
  const { signal, triggeredBy = 'scheduler' } = options;
  const config = await getSpamhausDropConfig(pool);

  // Worker-side re-check: the provider may have been disabled after this job was
  // enqueued. Complete cleanly as skipped without any external fetch and without
  // creating a retry. Terminal-success keeps existing queue metrics/run-history
  // semantics intact.
  if (!config.enabled) {
    return {
      ok: true,
      skipped: true,
      reason: 'Spamhaus DROP provider is disabled',
      triggered_by: triggeredBy,
      results: {}
    };
  }

  const results = {};

  for (const listType of SPAMHAUS_DROP_LIST_TYPES) {
    if (signal?.aborted) break;
    results[listType] = await runSpamhausDropListSync(pool, listType, {
      timeoutMs: config.timeout_ms,
      syncIntervalHours: config.sync_interval_hours,
      signal
    });
  }

  const allOk = Object.values(results).every((r) => r.ok);
  return { ok: allOk, triggered_by: triggeredBy, results };
}
