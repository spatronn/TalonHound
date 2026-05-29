import { createHash } from 'node:crypto';
import { strFromU8, unzipSync } from 'fflate';
import { config } from './config.js';
import {
  createSuppressionStats,
  fetchActiveSuppressionIndex,
  filterSuppressedPairs,
  isPairSuppressed
} from './lib/ioc-suppression.js';
import {
  createImportMetrics,
  finalizeIntegrationRun,
  failIntegrationRun
} from './lib/import-metrics.js';
import {
  syncMembershipAfterIocImport,
  syncSnapshotFeedFromEntries
} from './lib/iocExpiration.js';
import {
  resolveImportConfidenceFields,
  applyIocImportConfidence,
  resolveParsedSourceConfidence
} from './lib/iocConfidence.js';
import {
  URLHAUS_EXPORT_URL_MASKED,
  URLHAUS_AUTH_REQUIRED_MSG,
  assertUrlhausMinFetchInterval,
  buildUrlhausNote,
  buildUrlhausRecentCsvUrl,
  parseUrlhausRecentCsv,
  resolveUrlhausAuthKey,
  sanitizeUrlhausErrorMessage
} from './lib/urlhaus.js';
import {
  MALWAREBAZAAR_EXPORT_URL_MASKED,
  MALWAREBAZAAR_AUTH_REQUIRED_MSG,
  assertMalwareBazaarMinFetchInterval,
  buildMalwareBazaarNote,
  buildMalwareBazaarRecentCsvUrl,
  parseMalwareBazaarRecentCsv,
  resolveMalwareBazaarAuthKey,
  sanitizeMalwareBazaarErrorMessage
} from './lib/malwarebazaar.js';
import { createIntegrationPool } from './lib/pg-pool.js';
import { withPgTransaction } from './lib/pg-transaction.js';
import { throwIfAborted, fetchWithSignal, isJobAbortedError } from './lib/job-cancellation.js';

const pool = createIntegrationPool();

function parseLinks(html) {
  const links = [...html.matchAll(/href="\.\/([^"]+)"/g)].map((m) => m[1]);
  return links.filter((name) => {
    if (!/\.(rules|txt)$/i.test(name)) return false;
    if (/\.suricata\.rules$/i.test(name)) return false;
    return true;
  });
}

function isIPv4(value) {
  const m = value.match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/);
  if (!m) return false;
  return value.split('.').every((x) => Number(x) >= 0 && Number(x) <= 255);
}

function isCIDR(value) {
  const [ip, mask] = value.split('/');
  if (!ip || mask == null || mask === '') return false;
  if (!/^\d{1,2}$/.test(mask)) return false;
  const n = Number(mask);
  return isIPv4(ip) && Number.isInteger(n) && n >= 0 && n <= 32;
}

function extractIPs(text) {
  const found = new Set();
  const ipv4Like = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g) || [];
  for (const token of ipv4Like) {
    if (isIPv4(token) || isCIDR(token)) found.add(token);
  }
  return [...found];
}

function inferCategory(fileName) {
  const f = fileName.toLowerCase();
  if (f.includes('threatview') || f.includes('_c2')) return 'c2';
  if (f.includes('botcc')) return 'botnet-c2';
  if (f.includes('tor')) return 'tor';
  if (f.includes('compromised')) return 'compromised-host';
  if (f.includes('drop')) return 'known-malicious';
  if (f.includes('dshield')) return 'scanner';
  if (f.includes('ciarmy')) return 'bruteforce';
  return 'malicious-ip';
}

function inferConfidence(fileName) {
  const f = fileName.toLowerCase();
  if (f.includes('threatview') || f.includes('high-confidence')) return 'high';
  if (f.includes('drop') || f.includes('compromised') || f.includes('botcc') || f.includes('ciarmy')) return 'high';
  return 'medium';
}

function mapUsomConfidence(level) {
  const n = Number(level);
  if (Number.isNaN(n)) return 'medium';
  if (n <= 3) return 'high';
  if (n <= 6) return 'medium';
  return 'low';
}

function classifyUsomObservable(rawObservable) {
  const observable = String(rawObservable || '').trim();
  if (!observable || observable.startsWith('#')) return null;

  const normalizedIp = observable.endsWith('/') ? observable.slice(0, -1) : observable;

  let observableType = 'domain';
  if (/^https?:\/\//i.test(observable) || observable.includes('/')) observableType = 'url';
  else if (isIPv4(normalizedIp) || isCIDR(normalizedIp)) observableType = 'ip';
  else if (observable.includes(':')) observableType = 'ip6';

  return {
    observable: observableType === 'ip' ? normalizedIp : observable,
    observableType
  };
}

/** Allowed observable_type values for ioc_observables index (source-agnostic). */
const OBSERVABLE_INDEX_TYPES = new Set([
  'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh',
  'ip', 'ip6', 'domain', 'url'
]);

function parseNoteKeyValues(note) {
  const out = {};
  const raw = String(note || '').trim();
  if (!raw) return out;
  const parts = raw.split('|').map((p) => p.trim()).filter(Boolean);
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim().toLowerCase();
    const value = part.slice(idx + 1).trim();
    if (!key || !value) continue;
    out[key] = value;
  }
  return out;
}

function normalizeObservableValue(observableType, value) {
  if (!value || typeof value !== 'string') return '';
  const v = value.trim();
  const t = String(observableType || '').toLowerCase();
  if (['md5', 'sha1', 'sha256', 'imphash', 'tlsh', 'domain', 'url'].includes(t)) return v.toLowerCase();
  if (t === 'ssdeep') return v.toLowerCase();
  return v;
}

/**
 * Extract all searchable observables from primary observable + note (key=value).
 * Returns deduplicated list of { observable_type, observable_value } (normalized).
 * Used to populate ioc_observables index so any hash/ip/domain/url is searchable.
 */
export function extractObservablesFromNote(primaryType, primaryValue, note) {
  const seen = new Set();
  const out = [];
  const add = (type, value) => {
    if (!OBSERVABLE_INDEX_TYPES.has(type)) return;
    const normalized = normalizeObservableValue(type, value);
    if (!normalized) return;
    const key = `${type}:${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ observable_type: type, observable_value: normalized });
  };

  add(primaryType, primaryValue);
  const kv = parseNoteKeyValues(note);
  for (const [k, v] of Object.entries(kv)) {
    if (OBSERVABLE_INDEX_TYPES.has(k)) add(k, v);
  }
  return out;
}

async function insertObservablesIndex(client, iocPublicId, observables) {
  if (!observables.length) return;
  for (const { observable_type, observable_value } of observables) {
    await client.query(
      `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
       VALUES ($1, $2, $3)
       ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
      [iocPublicId, observable_type, observable_value]
    );
  }
}

function splitCsvLine(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === ',' && !inQuotes) {
      out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function mapThreatFoxConfidence(level) {
  const n = Number(level);
  if (Number.isNaN(n)) return 'medium';
  if (n >= 80) return 'high';
  if (n >= 50) return 'medium';
  return 'low';
}

async function readThreatFoxCsvText(response) {
  const bytes = new Uint8Array(await response.arrayBuffer());
  const looksZip = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;

  if (!looksZip) {
    return new TextDecoder('utf-8').decode(bytes);
  }

  const files = unzipSync(bytes);
  const names = Object.keys(files);
  if (!names.length) return '';

  const csvName = names.find((n) => n.toLowerCase().endsWith('.csv')) || names[0];
  return strFromU8(files[csvName]);
}

function classifyThreatFoxObservable(iocValue, iocType) {
  const raw = String(iocValue || '').trim();
  const type = String(iocType || '').trim().toLowerCase();
  if (!raw) return null;

  if (type === 'ip:port') {
    const [host] = raw.split(':');
    if (!host) return null;
    if (isIPv4(host)) return { observable: host, observableType: 'ip' };
    return null;
  }

  if (type === 'ip') {
    if (isIPv4(raw) || isCIDR(raw)) return { observable: raw, observableType: 'ip' };
    return null;
  }

  if (type === 'url') return { observable: raw, observableType: 'url' };
  if (type === 'domain') return { observable: raw, observableType: 'domain' };

  return null;
}

function hashEntries(entries) {
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

const BATCH_INSERT_CHUNK = Math.min(Math.max(Number(process.env.IOC_BATCH_INSERT_CHUNK || 150), 50), 500);

function withSuppressionStats(result, suppressionStats, metrics = null) {
  const stats = suppressionStats?.toJSON?.() || null;
  const payload = { ...result };
  if (metrics) {
    const m = metrics.toJSON();
    payload.metrics = m;
    payload.recordsProcessed = m.records_processed;
    payload.records_inserted = m.records_inserted;
    payload.records_duplicate = m.records_duplicate;
    payload.records_skipped = m.records_skipped;
    payload.records_suppressed = m.records_suppressed;
    payload.records_failed = m.records_failed;
  }
  if (!stats || Number(stats.suppressed_count || 0) <= 0) return payload;
  return { ...payload, ...stats };
}

function trackInsertResult(metrics, result) {
  if (result === 'suppressed') {
    metrics.noteSuppressed(1);
    return;
  }
  if (result === true || result === 'inserted') {
    metrics.noteInsert();
    return;
  }
  if (result === 'duplicate' || result === false) {
    metrics.noteDuplicate();
    return;
  }
}

async function updateUrlhausObservableBySource(client, entry, sourceName, note, category) {
  const lastSeen = entry.lastOnline || entry.dateAdded || null;
  const res = await client.query(
    `UPDATE ioc_items
     SET note = $4,
         category = $5,
         last_seen_at = CASE
           WHEN $7::timestamptz IS NULL THEN last_seen_at
           ELSE GREATEST(COALESCE(last_seen_at, $7::timestamptz), $7::timestamptz)
         END,
         first_seen_at = CASE
           WHEN $6::timestamptz IS NULL THEN first_seen_at
           ELSE LEAST(first_seen_at, $6::timestamptz)
         END
     WHERE observable = $1
       AND observable_type = $2
       AND source_name = $3
     RETURNING public_id`,
    [
      entry.observable,
      entry.observableType,
      sourceName,
      note,
      category,
      entry.dateAdded,
      lastSeen
    ]
  );

  if (!res.rowCount) return false;

  const publicId = res.rows[0].public_id;
  const observables = extractObservablesFromNote(entry.observableType, entry.observable, note);
  await insertObservablesIndex(client, publicId, observables);
  await applyIocImportConfidence(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    parsedSourceConfidence: null
  }).catch(() => {});
  await syncMembershipAfterIocImport(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl: URLHAUS_EXPORT_URL_MASKED,
    category
  }).catch(() => {});
  return true;
}

async function upsertUrlhausObservable(client, entry, sourceName, suppressionStats, metrics) {
  const note = buildUrlhausNote(entry);
  const category = entry.threat || 'malware-url';
  const sourceUrl = URLHAUS_EXPORT_URL_MASKED;

  const updated = await updateUrlhausObservableBySource(client, entry, sourceName, note, category);
  if (updated) {
    metrics.noteUpdated();
    return;
  }

  const insertResult = await insertObservable(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl,
    sourceConfidence: null,
    category,
    note
  }, suppressionStats);

  if (insertResult === 'suppressed') {
    metrics.noteSuppressed(1);
    return;
  }
  if (insertResult === true || insertResult === 'inserted') {
    metrics.noteInsert();
    if (entry.dateAdded || entry.lastOnline) {
      await updateUrlhausObservableBySource(client, entry, sourceName, note, category);
    }
    return;
  }

  metrics.noteDuplicate();
}

async function updateMalwareBazaarObservableBySource(client, entry, sourceName, note, category) {
  const res = await client.query(
    `UPDATE ioc_items
     SET note = $4,
         category = $5,
         last_seen_at = CASE
           WHEN $6::timestamptz IS NULL THEN last_seen_at
           ELSE GREATEST(COALESCE(last_seen_at, $6::timestamptz), $6::timestamptz)
         END,
         first_seen_at = CASE
           WHEN $6::timestamptz IS NULL THEN first_seen_at
           ELSE LEAST(first_seen_at, $6::timestamptz)
         END
     WHERE observable = $1
       AND observable_type = $2
       AND source_name = $3
     RETURNING public_id`,
    [
      entry.observable,
      entry.observableType,
      sourceName,
      note,
      category,
      entry.firstSeenUtc
    ]
  );

  if (!res.rowCount) return false;

  const publicId = res.rows[0].public_id;
  const observables = extractObservablesFromNote(entry.observableType, entry.observable, note);
  await insertObservablesIndex(client, publicId, observables);
  await applyIocImportConfidence(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    parsedSourceConfidence: entry.confidence
  }).catch(() => {});
  await syncMembershipAfterIocImport(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl: MALWAREBAZAAR_EXPORT_URL_MASKED,
    confidence: entry.confidence,
    category
  }).catch(() => {});
  return true;
}

async function upsertMalwareBazaarObservable(client, entry, sourceName, suppressionStats, metrics) {
  const note = buildMalwareBazaarNote(entry);
  const category = entry.category || 'malware';
  const sourceUrl = MALWAREBAZAAR_EXPORT_URL_MASKED;

  const updated = await updateMalwareBazaarObservableBySource(client, entry, sourceName, note, category);
  if (updated) {
    metrics.noteUpdated();
    return;
  }

  const insertResult = await insertObservable(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl,
    confidence: entry.confidence,
    sourceConfidence: entry.confidence,
    category,
    note
  }, suppressionStats);

  if (insertResult === 'suppressed') {
    metrics.noteSuppressed(1);
    return;
  }
  if (insertResult === true || insertResult === 'inserted') {
    metrics.noteInsert();
    if (entry.firstSeenUtc) {
      await updateMalwareBazaarObservableBySource(client, entry, sourceName, note, category);
    }
    return;
  }

  metrics.noteDuplicate();
}

function mergeBatchInsertMetrics(metrics, batchResult) {
  metrics.records_inserted += Number(batchResult?.inserted || 0);
  metrics.records_duplicate += Number(batchResult?.duplicate || 0);
  metrics.records_suppressed += Number(batchResult?.suppressed || 0);
}

function logImportSuppressionSummary(jobType, runId, suppressionStats, extra = {}) {
  const stats = suppressionStats?.toJSON?.() || {};
  if (Number(stats.suppressed_count || 0) <= 0) return;
  console.log(
    `[integration-import] job=${jobType} runId=${runId} suppressed_count=${stats.suppressed_count} suppressed_by_global_count=${stats.suppressed_by_global_count} skipped_suppressed_iocs=${stats.skipped_suppressed_iocs} ${JSON.stringify(extra)}`
  );
}

/**
 * ET feed gibi tek tip (ip) toplu ekleme: tek sorguda chunk kadar satır, WHERE NOT EXISTS ile dedup.
 * idempotent ekleme: aynı feed tekrar çalışırsa INSERT no-op (WHERE NOT EXISTS).
 */
async function batchInsertIocs(client, entries, observableType = 'ip', suppressionStats = null, signal = null) {
  const out = { inserted: 0, duplicate: 0, suppressed: 0 };
  if (!entries.length) return out;
  const now = new Date();

  for (let i = 0; i < entries.length; i += BATCH_INSERT_CHUNK) {
    throwIfAborted(signal);
    const chunk = entries.slice(i, i + BATCH_INSERT_CHUNK);
    const pairs = chunk.map((e) => ({
      iocValue: e.observable ?? e.ip,
      iocType: observableType,
      sourceName: e.sourceName ?? null
    }));
    const index = await fetchActiveSuppressionIndex(client, pairs, { logTag: 'integration-import' });
    const { kept, stats } = filterSuppressedPairs(index, chunk, (e) => ({
      iocValue: e.observable ?? e.ip,
      iocType: observableType,
      sourceName: e.sourceName ?? null
    }));
    out.suppressed += chunk.length - kept.length;
    if (suppressionStats) suppressionStats.merge(stats);
    if (!kept.length) continue;

    const resolvedKept = kept.map((e) => ({
      ...e,
      confFields: resolveImportConfidenceFields({
        parsedSourceConfidence: resolveParsedSourceConfidence(e.sourceConfidence, e.confidence)
      })
    }));

    const placeholders = [];
    const params = [];
    resolvedKept.forEach((e, idx) => {
      const off = idx * 10;
      placeholders.push(
        `($${off + 1}::text, $${off + 2}::text, $${off + 3}::text, $${off + 4}::text, $${off + 5}::text, $${off + 6}::text, $${off + 7}::text, $${off + 8}::text, $${off + 9}::timestamptz, $${off + 10}::timestamptz)`
      );
      params.push(
        e.observable ?? e.ip,
        e.sourceName,
        e.sourceUrl ?? null,
        e.confFields.confidence,
        e.confFields.source_confidence,
        e.confFields.feed_default_confidence,
        e.category ?? null,
        e.note ?? null,
        now,
        now
      );
    });
    const typeParam = resolvedKept.length * 10 + 1;
    const valuesList = placeholders.join(',\n');
    const ins = await client.query(
      `INSERT INTO ioc_items (
         observable, observable_type, source_name, source_url,
         confidence, source_confidence, feed_default_confidence,
         category, note, first_seen_at, last_seen_at
       )
       SELECT v.observable, $${typeParam}::text, v.source_name, v.source_url,
              v.confidence, v.source_confidence, v.feed_default_confidence,
              v.category, v.note, v.first_seen_at, v.last_seen_at
       FROM (VALUES ${valuesList}) AS v(
         observable, source_name, source_url, confidence, source_confidence,
         feed_default_confidence, category, note, first_seen_at, last_seen_at
       )
       WHERE NOT EXISTS (
         SELECT 1 FROM ioc_items i
         WHERE i.observable = v.observable AND i.observable_type = $${typeParam}
           AND i.source_name = v.source_name
           AND COALESCE(i.category, '') = COALESCE(v.category, '')
           AND COALESCE(i.source_url, '') = COALESCE(v.source_url, '')
       )
       RETURNING public_id, observable, note`,
      [...params.flat(), observableType]
    );
    const rows = ins.rows ?? [];
    out.inserted += rows.length;
    out.duplicate += resolvedKept.length - rows.length;
    const insertedObs = new Set(rows.map((r) => r.observable));
    for (const e of resolvedKept) {
      throwIfAborted(signal);
      const obs = e.observable ?? e.ip;
      if (!insertedObs.has(obs)) {
        await applyIocImportConfidence(client, {
          observable: obs,
          observableType,
          sourceName: e.sourceName,
          parsedSourceConfidence: resolveParsedSourceConfidence(e.sourceConfidence, e.confidence)
        }).catch(() => {});
      }
    }
    for (const row of rows) {
      throwIfAborted(signal);
      const observables = extractObservablesFromNote(observableType, row.observable, row.note);
      await insertObservablesIndex(client, row.public_id, observables);
      const src = resolvedKept.find((e) => (e.observable ?? e.ip) === row.observable);
      if (src) {
        await syncMembershipAfterIocImport(client, {
          observable: row.observable,
          observableType,
          sourceName: src.sourceName,
          sourceUrl: src.sourceUrl ?? null,
          explicitConfidence: src.confFields.source_confidence,
          category: src.category ?? null
        }).catch(() => {});
      }
    }
  }
  return out;
}

async function insertObservable(client, { observable, observableType, sourceName, sourceUrl, confidence, category, note, sourceConfidence = null }, suppressionStats = null, signal = null) {
  throwIfAborted(signal);
  const index = await fetchActiveSuppressionIndex(
    client,
    [{ iocValue: observable, iocType: observableType, sourceName }],
    { logTag: 'integration-import' }
  );
  const hit = isPairSuppressed(index, { iocValue: observable, iocType: observableType, sourceName });
  if (hit?.suppressed) {
    if (suppressionStats) suppressionStats.noteSuppressionSkip({ byGlobal: hit.byGlobal });
    return 'suppressed';
  }

  const confFields = resolveImportConfidenceFields({
    parsedSourceConfidence: resolveParsedSourceConfidence(sourceConfidence, confidence)
  });

  const ins = await client.query(
    `INSERT INTO ioc_items (
       observable, observable_type, source_name, source_url,
       confidence, source_confidence, feed_default_confidence,
       category, note
     )
     SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
     WHERE NOT EXISTS (
       SELECT 1
       FROM ioc_items
       WHERE observable = $1
         AND observable_type = $2
         AND source_name = $3
         AND COALESCE(category, '') = COALESCE($8, '')
         AND COALESCE(source_url, '') = COALESCE($4, '')
     )
     RETURNING public_id`,
    [
      observable,
      observableType,
      sourceName,
      sourceUrl,
      confFields.confidence,
      confFields.source_confidence,
      confFields.feed_default_confidence,
      category,
      note
    ]
  );

  if (!ins.rowCount) {
    await applyIocImportConfidence(client, {
      observable,
      observableType,
      sourceName,
      parsedSourceConfidence: resolveParsedSourceConfidence(sourceConfidence, confidence)
    }).catch(() => {});
    await syncMembershipAfterIocImport(client, {
      observable,
      observableType,
      sourceName,
      sourceUrl,
      explicitConfidence: confFields.source_confidence,
      category
    }).catch(() => {});
    return 'duplicate';
  }

  const publicId = ins.rows[0].public_id;
  const observables = extractObservablesFromNote(observableType, observable, note);
  await insertObservablesIndex(client, publicId, observables);
  await syncMembershipAfterIocImport(client, {
    observable,
    observableType,
    sourceName,
    sourceUrl,
    explicitConfidence: confFields.source_confidence,
    category
  }).catch(() => {});
  return true;
}

export async function runHourlyImport(options = {}) {
  const { signal } = options;
  const client = await pool.connect();
  const startedAt = new Date();
  let runId = null;
  const suppressionStats = createSuppressionStats();
  const metrics = createImportMetrics();
  const txMeta = { source_key: 'et-blockrules', signal };

  try {
    throwIfAborted(signal);
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942001) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('hourly_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;
    txMeta.job_id = runId;

    const indexRes = await fetchWithSignal(config.sourceIndexUrl, {}, signal);
    if (!indexRes.ok) throw new Error(`Failed to fetch source index: ${indexRes.status}`);
    const indexHtml = await indexRes.text();

    const files = parseLinks(indexHtml);

    for (const file of files) {
      throwIfAborted(signal);
      const sourceUrl = new URL(file, config.sourceIndexUrl).toString();
      const response = await fetchWithSignal(sourceUrl, {}, signal);
      if (!response.ok) {
        metrics.noteSkipped(1);
        continue;
      }

      const body = await response.text();
      const ips = extractIPs(body);
      const sourceName = `EmergingThreats:${file}`;
      const confidence = inferConfidence(file);
      const category = inferCategory(file);
      const note = `Auto-imported from ET blockrules (${file})`;

      const entries = ips.map((ip) => ({
        ip,
        sourceName,
        sourceUrl,
        confidence,
        category,
        note
      }));

      await withPgTransaction(client, 'hourly_import_batch', async (tx) => {
        mergeBatchInsertMetrics(metrics, await batchInsertIocs(tx, entries, 'ip', suppressionStats, signal));
      }, { ...txMeta, file });
    }

    await withPgTransaction(client, 'hourly_import_finalize', async (tx) => {
      await tx.query(
        `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (source_name)
         DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
        [config.sourceName, startedAt.toISOString()]
      );
      await finalizeIntegrationRun(tx, runId, metrics);
    }, txMeta);

    logImportSuppressionSummary('hourly_import', runId, suppressionStats, metrics.toJSON());
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
  } catch (err) {
    if (runId) {
      await failIntegrationRun(client, runId, err.message, metrics);
    }

    throw err;
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(942001)');
    } catch {
      // ignore
    }
    client.release();
  }
}

export async function runUsomImport(options = {}) {
  const { signal } = options;
  const client = await pool.connect();
  let runId = null;
  const suppressionStats = createSuppressionStats();
  const metrics = createImportMetrics();
  const txMeta = { source_key: 'usom-trcert', signal };

  try {
    throwIfAborted(signal);
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942002) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('usom_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    const res = await fetchWithSignal(config.usomApiUrl, {}, signal);
    if (!res.ok) throw new Error(`USOM URL list request failed: ${res.status}`);
    const txt = await res.text();

    const rawLines = txt.split(/\r?\n/);
    metrics.noteSkipped(rawLines.filter((line) => {
      const c = classifyUsomObservable(line);
      return !c;
    }).length);

    const entries = rawLines
      .map((line) => classifyUsomObservable(line))
      .filter(Boolean)
      .sort((a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`));

    const currentHash = hashEntries(entries);

    const prevState = await client.query(
      `SELECT content_hash, items_json
       FROM integration_source_state
       WHERE source_name = $1`,
      [config.usomSourceName]
    );

    const previousHash = prevState.rows[0]?.content_hash || null;
    const previousItems = Array.isArray(prevState.rows[0]?.items_json) ? prevState.rows[0].items_json : [];
    const previousSet = new Set(previousItems.map((x) => `${x.observableType}|${x.observable}`));

    if (previousHash === currentHash) {
      // Feed unchanged since last run — count existing entries as skipped (no insert attempts).
      metrics.noteSkipped(entries.length);
      await finalizeIntegrationRun(client, runId, metrics);

      await client.query(
        `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (source_name)
         DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
        [config.usomSourceName, `hash:${currentHash}`]
      );

      return withSuppressionStats({ ok: true, runId, skipped: true, reason: 'same_hash' }, suppressionStats, metrics);
    }

    const addedEntries = entries.filter((e) => !previousSet.has(`${e.observableType}|${e.observable}`));
    // Entries still in feed but already imported in prior runs.
    metrics.noteSkipped(entries.length - addedEntries.length);
    const batchSize = Number(process.env.USOM_BATCH_SIZE || 1000);

    for (let i = 0; i < addedEntries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = addedEntries.slice(i, i + batchSize);
      await withPgTransaction(client, 'usom_import_batch', async (tx) => {
        for (const entry of batch) {
          throwIfAborted(signal);
          const { observable, observableType } = entry;
          const okObs = await insertObservable(tx, {
            observable,
            observableType,
            sourceName: config.usomSourceName,
            sourceUrl: config.usomApiUrl,
            sourceConfidence: null,
            category: 'threat-intel',
            note: 'Auto-imported from USOM URL list'
          }, suppressionStats, signal);
          trackInsertResult(metrics, okObs);
        }
      }, { ...txMeta, job_id: runId, batch: Math.floor(i / batchSize) + 1 });
    }

    throwIfAborted(signal);
    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
      [config.usomSourceName, currentHash, JSON.stringify(entries)]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.usomSourceName, `hash:${currentHash}`]
    );

    await syncSnapshotFeedFromEntries(client, 'usom-trcert', entries, (entry) => ({
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: config.usomSourceName,
      sourceUrl: config.usomApiUrl,
      category: 'threat-intel'
    }), { signal }).catch((err) => {
      if (isJobAbortedError(err)) throw err;
    });

    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('usom_import', runId, suppressionStats, metrics.toJSON());
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
  } catch (err) {
    if (runId) {
      await failIntegrationRun(client, runId, err.message, metrics);
    }

    throw err;
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(942002)');
    } catch {
      // ignore
    }
    client.release();
  }
}


export async function runUrlhausImport(options = {}) {
  const { signal } = options;
  const client = await pool.connect();
  let runId = null;
  const suppressionStats = createSuppressionStats();
  const metrics = createImportMetrics();
  const txMeta = { source_key: 'urlhaus-abusech', signal };

  try {
    throwIfAborted(signal);
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942003) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('urlhaus_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    const authKey = await resolveUrlhausAuthKey(client, config.urlhausAuthKey);
    if (!authKey) {
      throw new Error(URLHAUS_AUTH_REQUIRED_MSG);
    }

    const interval = await assertUrlhausMinFetchInterval(client, config.urlhausSourceName);
    if (!interval.ok) {
      metrics.noteSkipped(0);
      await finalizeIntegrationRun(client, runId, metrics);
      return withSuppressionStats(
        { ok: true, runId, skipped: true, reason: interval.reason },
        suppressionStats,
        metrics
      );
    }

    const exportUrl = buildUrlhausRecentCsvUrl(authKey);
    const res = await fetchWithSignal(exportUrl, {}, signal);
    if (!res.ok) {
      throw new Error(`URLhaus CSV export request failed: ${res.status}`);
    }
    const txt = await res.text();

    const { entries, fetched, parsed, skipped } = parseUrlhausRecentCsv(txt);
    metrics.noteSkipped(skipped + Math.max(0, fetched - parsed));

    const currentHash = hashEntries(entries.map((e) => ({
      o: e.observable,
      t: e.observableType,
      id: e.externalId,
      status: e.urlStatus
    })));

    const batchSize = Number(process.env.URLHAUS_BATCH_SIZE || 1000);

    for (let i = 0; i < entries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = entries.slice(i, i + batchSize);
      await withPgTransaction(client, 'urlhaus_import_batch', async (tx) => {
        for (const entry of batch) {
          throwIfAborted(signal);
          await upsertUrlhausObservable(tx, entry, config.urlhausSourceName, suppressionStats, metrics);
        }
      }, { ...txMeta, job_id: runId, batch: Math.floor(i / batchSize) + 1 });
    }

    throwIfAborted(signal);
    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
      [
        config.urlhausSourceName,
        currentHash,
        JSON.stringify(entries.map((e) => ({ observable: e.observable, observableType: e.observableType })))
      ]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.urlhausSourceName, `hash:${currentHash}`]
    );

    await syncSnapshotFeedFromEntries(client, 'urlhaus-abusech', entries, (entry) => ({
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: config.urlhausSourceName,
      sourceUrl: URLHAUS_EXPORT_URL_MASKED,
      category: entry.threat || 'malware-url'
    }), { signal }).catch((err) => {
      if (isJobAbortedError(err)) throw err;
    });

    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('urlhaus_import', runId, suppressionStats, metrics.toJSON());
    console.log(
      `[integration-import] job=urlhaus_import runId=${runId} export=${URLHAUS_EXPORT_URL_MASKED} fetched=${fetched} parsed=${parsed} skipped=${skipped}`
    );
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
  } catch (err) {
    const safeMessage = sanitizeUrlhausErrorMessage(err?.message || err);
    if (runId) {
      await failIntegrationRun(client, runId, safeMessage, metrics);
    }
    const wrapped = new Error(safeMessage);
    wrapped.cause = err;
    throw wrapped;
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(942003)');
    } catch {
      // ignore
    }
    client.release();
  }
}

export async function runThreatfoxImport(options = {}) {
  const { signal } = options;
  const client = await pool.connect();
  let runId = null;
  const suppressionStats = createSuppressionStats();
  const metrics = createImportMetrics();
  const txMeta = { source_key: 'threatfox-abusech', signal };

  try {
    throwIfAborted(signal);
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942004) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('threatfox_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    const res = await fetchWithSignal(config.threatfoxCsvUrl, {}, signal);
    if (!res.ok) throw new Error(`ThreatFox CSV request failed: ${res.status}`);
    const txt = await readThreatFoxCsvText(res);

    const parsedRows = txt
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => splitCsvLine(line));

    metrics.noteSkipped(parsedRows.filter((cols) => cols.length < 15).length);

    const entries = parsedRows
      .filter((cols) => cols.length >= 15)
      .map((cols) => {
        const observable = classifyThreatFoxObservable(cols[2], cols[3]);
        if (!observable) return null;
        return {
          ...observable,
          iocId: cols[1],
          threatType: cols[4],
          malwarePrintable: cols[7],
          confidence: mapThreatFoxConfidence(cols[9]),
          reference: cols[11],
          tags: cols[12],
          reporter: cols[14]
        };
      })
      .filter(Boolean)
      .sort((a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`));

    metrics.noteSkipped(parsedRows.filter((cols) => cols.length >= 15 && !classifyThreatFoxObservable(cols[2], cols[3])).length);

    const currentHash = hashEntries(entries.map((e) => ({ o: e.observable, t: e.observableType, id: e.iocId })));

    const prevState = await client.query(
      `SELECT content_hash, items_json
       FROM integration_source_state
       WHERE source_name = $1`,
      [config.threatfoxSourceName]
    );

    const previousHash = prevState.rows[0]?.content_hash || null;
    const previousItems = Array.isArray(prevState.rows[0]?.items_json) ? prevState.rows[0].items_json : [];
    const previousSet = new Set(previousItems.map((x) => `${x.observableType}|${x.observable}`));

    if (previousHash === currentHash) {
      metrics.noteSkipped(entries.length);
      await finalizeIntegrationRun(client, runId, metrics);

      await client.query(
        `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (source_name)
         DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
        [config.threatfoxSourceName, `hash:${currentHash}`]
      );

      return withSuppressionStats({ ok: true, runId, skipped: true, reason: 'same_hash' }, suppressionStats, metrics);
    }

    const addedEntries = entries.filter((e) => !previousSet.has(`${e.observableType}|${e.observable}`));
    metrics.noteSkipped(entries.length - addedEntries.length);
    const batchSize = Number(process.env.THREATFOX_BATCH_SIZE || 1000);

    for (let i = 0; i < addedEntries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = addedEntries.slice(i, i + batchSize);
      await withPgTransaction(client, 'threatfox_import_batch', async (tx) => {
        for (const entry of batch) {
          throwIfAborted(signal);
          const noteParts = [
            'Auto-imported from ThreatFox CSV',
            entry.iocId ? `ioc_id=${entry.iocId}` : null,
            entry.malwarePrintable ? `malware=${entry.malwarePrintable}` : null,
            entry.reporter ? `reporter=${entry.reporter}` : null,
            entry.tags ? `tags=${entry.tags}` : null
          ].filter(Boolean);

          const okObs = await insertObservable(tx, {
            observable: entry.observable,
            observableType: entry.observableType,
            sourceName: config.threatfoxSourceName,
            sourceUrl: config.threatfoxCsvUrl,
            confidence: entry.confidence,
            sourceConfidence: entry.confidence,
            category: entry.threatType || 'threat-intel',
            note: noteParts.join(' | ')
          }, suppressionStats, signal);
          trackInsertResult(metrics, okObs);
        }
      }, { ...txMeta, job_id: runId, batch: Math.floor(i / batchSize) + 1 });
    }

    throwIfAborted(signal);
    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
      [config.threatfoxSourceName, currentHash, JSON.stringify(entries.map((e) => ({ observable: e.observable, observableType: e.observableType })))]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.threatfoxSourceName, `hash:${currentHash}`]
    );

    await syncSnapshotFeedFromEntries(client, 'threatfox-abusech', entries, (entry) => ({
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: config.threatfoxSourceName,
      sourceUrl: config.threatfoxCsvUrl,
      confidence: entry.confidence,
      category: entry.threatType || 'threat-intel'
    }), { signal }).catch((err) => {
      if (isJobAbortedError(err)) throw err;
    });

    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('threatfox_import', runId, suppressionStats, metrics.toJSON());
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
  } catch (err) {
    if (runId) {
      await failIntegrationRun(client, runId, err.message, metrics);
    }

    throw err;
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(942004)');
    } catch {
      // ignore
    }
    client.release();
  }
}

export async function runMalwareBazaarImport(options = {}) {
  const { signal } = options;
  const client = await pool.connect();
  let runId = null;
  const suppressionStats = createSuppressionStats();
  const metrics = createImportMetrics();
  const txMeta = { source_key: 'malwarebazaar-abusech', signal };

  try {
    throwIfAborted(signal);
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942005) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('malwarebazaar_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    const authKey = await resolveMalwareBazaarAuthKey(client, config.malwareBazaarAuthKey);
    if (!authKey) {
      throw new Error(MALWAREBAZAAR_AUTH_REQUIRED_MSG);
    }

    const interval = await assertMalwareBazaarMinFetchInterval(client, config.malwareBazaarSourceName);
    if (!interval.ok) {
      metrics.noteSkipped(0);
      await finalizeIntegrationRun(client, runId, metrics);
      return withSuppressionStats(
        { ok: true, runId, skipped: true, reason: interval.reason },
        suppressionStats,
        metrics
      );
    }

    const exportUrl = buildMalwareBazaarRecentCsvUrl(authKey);
    const res = await fetchWithSignal(exportUrl, {}, signal);
    if (!res.ok) {
      throw new Error(`MalwareBazaar export fetch failed: HTTP ${res.status}`);
    }
    const txt = await res.text();

    const { entries, fetched, parsed, skipped } = parseMalwareBazaarRecentCsv(txt);
    metrics.noteSkipped(skipped + Math.max(0, fetched - parsed));

    const currentHash = hashEntries(entries.map((e) => ({
      o: e.observable,
      t: e.observableType,
      sig: e.signature,
      fs: e.firstSeenUtc?.toISOString?.() || null
    })));

    const batchSize = Number(process.env.MALWARE_BAZAAR_BATCH_SIZE || 1000);

    for (let i = 0; i < entries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = entries.slice(i, i + batchSize);
      await withPgTransaction(client, 'malwarebazaar_import_batch', async (tx) => {
        for (const entry of batch) {
          throwIfAborted(signal);
          await upsertMalwareBazaarObservable(tx, entry, config.malwareBazaarSourceName, suppressionStats, metrics);
        }
      }, { ...txMeta, job_id: runId, batch: Math.floor(i / batchSize) + 1 });
    }

    throwIfAborted(signal);
    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
      [
        config.malwareBazaarSourceName,
        currentHash,
        JSON.stringify(entries.map((e) => ({ observable: e.observable, observableType: e.observableType })))
      ]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.malwareBazaarSourceName, `hash:${currentHash}`]
    );

    await syncSnapshotFeedFromEntries(client, 'malwarebazaar-abusech', entries, (entry) => ({
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: config.malwareBazaarSourceName,
      sourceUrl: MALWAREBAZAAR_EXPORT_URL_MASKED,
      confidence: entry.confidence,
      category: entry.category || 'malware'
    }), { signal }).catch((err) => {
      if (isJobAbortedError(err)) throw err;
    });

    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('malwarebazaar_import', runId, suppressionStats, metrics.toJSON());
    console.log(
      `[integration-import] job=malwarebazaar_import runId=${runId} export=${MALWAREBAZAAR_EXPORT_URL_MASKED} fetched=${fetched} parsed=${parsed} skipped=${skipped}`
    );
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
  } catch (err) {
    const safeMessage = sanitizeMalwareBazaarErrorMessage(err?.message || err);
    if (runId) {
      await failIntegrationRun(client, runId, safeMessage, metrics);
    }

    throw Object.assign(new Error(safeMessage), { cause: err });
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(942005)');
    } catch {
      // ignore
    }
    client.release();
  }
}

export async function runPhishtankImport(options = {}) {
  const { signal } = options;
  const client = await pool.connect();
  let runId = null;
  const suppressionStats = createSuppressionStats();
  const metrics = createImportMetrics();
  const txMeta = { source_key: 'phishtank-opendnsrr', signal };

  try {
    throwIfAborted(signal);
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942006) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('phishtank_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;
    txMeta.job_id = runId;

    const response = await fetchWithSignal(config.phishTankCsvUrl, {
      headers: { 'User-Agent': 'demo-runbook-integration/1.0' }
    }, signal);
    if (!response.ok) throw new Error(`Failed to fetch PhishTank CSV: ${response.status}`);

    const text = await response.text();
    const lines = text.split(/\r?\n/).filter(Boolean);
    if (lines.length <= 1) {
      await withPgTransaction(client, 'phishtank_import_finalize', async (tx) => {
        await finalizeIntegrationRun(tx, runId, metrics);
      }, txMeta);
      return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    }

    const sourceName = config.phishTankSourceName;
    const sourceUrl = config.phishTankCsvUrl;
    const parsedEntries = [];

    for (let i = 1; i < lines.length; i += 1) {
      if (i % 500 === 1) throwIfAborted(signal);
      const cols = splitCsvLine(lines[i]);
      if (!cols.length) { metrics.noteSkipped(1); continue; }
      const url = String(cols[1] || '').trim();
      if (!url || !/^https?:\/\//i.test(url) || url.length > 1800) { metrics.noteSkipped(1); continue; }
      parsedEntries.push({
        observable: url,
        observableType: 'url',
        sourceName,
        sourceUrl,
        category: 'phishing',
        note: 'Auto-imported from PhishTank online-valid.csv'
      });
    }

    const batchSize = Math.max(Number(process.env.PHISHTANK_BATCH_SIZE || 1000), 100);
    for (let i = 0; i < parsedEntries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = parsedEntries.slice(i, i + batchSize);
      await withPgTransaction(client, 'phishtank_import_batch', async (tx) => {
        for (const entry of batch) {
          throwIfAborted(signal);
          const ok = await insertObservable(tx, entry, suppressionStats, signal);
          trackInsertResult(metrics, ok);
        }
      }, { ...txMeta, batch: Math.floor(i / batchSize) + 1 });
    }

    await withPgTransaction(client, 'phishtank_import_finalize', async (tx) => {
      await finalizeIntegrationRun(tx, runId, metrics);
    }, txMeta);

    logImportSuppressionSummary('phishtank_import', runId, suppressionStats, metrics.toJSON());
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
  } catch (err) {
    if (runId) {
      await failIntegrationRun(client, runId, err.message, metrics);
    }
    throw err;
  } finally {
    try { await client.query('SELECT pg_advisory_unlock(942006)'); } catch {}
    client.release();
  }
}
