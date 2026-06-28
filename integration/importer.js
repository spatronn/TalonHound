import { createHash } from 'node:crypto';
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
  syncSnapshotFeedFromEntries,
  withImportOptimizationContext
} from './lib/iocExpiration.js';
import { upsertFeedSourceEvidenceForObservable } from './lib/iocFeedSourceEvidence.js';
import {
  resolveImportConfidenceFields,
  applyIocImportConfidence,
  resolveParsedSourceConfidence,
  fetchFeedDefaultConfidence
} from './lib/iocConfidence.js';
import {
  URLHAUS_FEED_KEY,
  URLHAUS_EXPORT_URL_MASKED,
  URLHAUS_AUTH_REQUIRED_MSG,
  assertUrlhausMinFetchInterval,
  buildUrlhausCanonicalIocHash,
  buildUrlhausNote,
  urlhausNotesSemanticallyEqual,
  evaluateUrlhausExportSkip,
  fetchUrlhausExport,
  loadUrlhausCheckpoint,
  parseUrlhausRecentCsv,
  resolveUrlhausAuthKey,
  sanitizeUrlhausErrorMessage,
  saveUrlhausCheckpoint
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
import {
  THREATFOX_AUTH_REQUIRED_MSG,
  THREATFOX_SOURCE_URL_MASKED,
  buildThreatFoxNote,
  threatFoxNotesSemanticallyEqual,
  fetchThreatFoxRecentIocs,
  resolveThreatFoxAuthKey,
  resolveThreatFoxRecentDays,
  sanitizeThreatFoxErrorMessage
} from './lib/threatfox.js';
import { createIntegrationPool } from './lib/pg-pool.js';
import { withPgTransaction } from './lib/pg-transaction.js';
import { throwIfAborted, fetchWithSignal, isJobAbortedError } from './lib/job-cancellation.js';

const pool = createIntegrationPool();
const IMPORT_LOG = '[integration-import]';

function resolveTriggeredBy(options) {
  return String(options?.triggeredBy || 'scheduler').trim() || 'scheduler';
}

async function runSnapshotSync(client, feedKey, entries, mapEntry, options = {}) {
  return syncSnapshotFeedFromEntries(client, feedKey, entries, mapEntry, options);
}

async function importSideEffect(label, metrics, fn) {
  try {
    await fn();
  } catch (err) {
    if (isJobAbortedError(err)) throw err;
    console.error(`${IMPORT_LOG} side_effect_failed label=${label} message=${err?.message || err}`);
    metrics?.noteFailed(1);
  }
}

async function storeFeedSourceEvidence(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl = null,
  category = null,
  note = null,
  confidence = null
}) {
  await importSideEffect('feed_source_evidence', null, () => upsertFeedSourceEvidenceForObservable(client, {
    observable,
    observableType,
    sourceName,
    sourceUrl,
    category,
    note,
    confidence
  }));
}

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

function isIPv6(value) {
  const v = String(value || '').trim();
  if (!v.includes(':')) return false;
  const core = v.split('%')[0];
  if (!/^[0-9a-f:.]+$/i.test(core)) return false;
  return core.includes(':');
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
  else if (isIPv6(normalizedIp)) observableType = 'ip6';

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

function hashEntries(entries) {
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

function hashContent(text) {
  return createHash('sha256').update(String(text || '')).digest('hex');
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
  if (result === 'unchanged') {
    metrics.noteSkipped(1);
    return;
  }
  if (result === true || result === 'inserted') {
    metrics.noteInsert();
    return;
  }
  if (result === 'duplicate' || result === false) {
    metrics.noteDuplicate();
  }
}

async function updateExistingIocBySourceIfChanged(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl = null,
  note = null,
  category = null,
  firstSeenAt = null,
  lastSeenAt = null,
  matchSourceUrl = false
}) {
  const sourceUrlPredicate = matchSourceUrl ? "AND COALESCE(source_url, '') = COALESCE($4, '')" : '';
  const res = await client.query(
    `WITH existing AS (
       SELECT public_id,
              first_seen_at,
              last_seen_at,
              CASE
                WHEN $7::timestamptz IS NULL THEN first_seen_at
                WHEN first_seen_at IS NULL THEN $7::timestamptz
                ELSE LEAST(first_seen_at, $7::timestamptz)
              END AS next_first_seen_at,
              CASE
                WHEN $8::timestamptz IS NULL THEN last_seen_at
                ELSE GREATEST(COALESCE(last_seen_at, $8::timestamptz), $8::timestamptz)
              END AS next_last_seen_at
       FROM ioc_items
       WHERE observable = $1
         AND observable_type = $2
         AND source_name = $3
         ${sourceUrlPredicate}
       ORDER BY created_at ASC
       LIMIT 1
     ), updated AS (
       UPDATE ioc_items i
       SET source_url = CASE WHEN $9::boolean THEN $4 ELSE i.source_url END,
           category = $5,
           note = $6,
           first_seen_at = existing.next_first_seen_at,
           last_seen_at = existing.next_last_seen_at
       FROM existing
       WHERE i.public_id = existing.public_id
         AND (
           (CASE WHEN $9::boolean THEN i.source_url IS DISTINCT FROM $4 ELSE FALSE END)
           OR i.category IS DISTINCT FROM $5
           OR i.note IS DISTINCT FROM $6
           OR i.first_seen_at IS DISTINCT FROM existing.next_first_seen_at
           OR i.last_seen_at IS DISTINCT FROM existing.next_last_seen_at
         )
       RETURNING i.public_id
     )
     SELECT 'updated' AS status, public_id FROM updated
     UNION ALL
     SELECT 'unchanged' AS status, public_id FROM existing
     WHERE NOT EXISTS (SELECT 1 FROM updated)`,
    [
      observable,
      observableType,
      sourceName,
      sourceUrl,
      category,
      note,
      firstSeenAt,
      lastSeenAt,
      Boolean(matchSourceUrl)
    ]
  );
  if (!res.rowCount) return { status: 'not_found' };
  const row = res.rows[0];
  return { status: row.status, publicId: row.public_id };
}

export async function updateUrlhausExistingIocBySource(client, {
  observable,
  observableType,
  sourceName,
  fullNote,
  category,
  dateAddedAt = null,
  lastOnlineAt = null
}) {
  const { rows } = await client.query(
    `SELECT public_id, note, category, first_seen_at, last_seen_at
     FROM ioc_items
     WHERE observable = $1
       AND observable_type = $2
       AND source_name = $3
     ORDER BY created_at ASC
     LIMIT 1`,
    [observable, observableType, sourceName]
  );
  const row = rows[0];
  if (!row) return { status: 'not_found' };

  const nextFirstSeenAt = mergeUrlhausFirstSeenAt(row.first_seen_at, dateAddedAt);
  const nextLastSeenAt = mergeUrlhausLastSeenAt(row.last_seen_at, lastOnlineAt);
  const semanticChanged = String(row.category || '') !== String(category || '')
    || !urlhausNotesSemanticallyEqual(row.note, fullNote);
  const observationChanged = urlhausObservationChanged(row, {
    fullNote,
    nextFirstSeenAt,
    nextLastSeenAt
  });

  if (!semanticChanged && !observationChanged) {
    return { status: 'unchanged', publicId: row.public_id };
  }

  if (semanticChanged) {
    const upd = await client.query(
      `UPDATE ioc_items
       SET category = $2,
           note = $3,
           first_seen_at = $4,
           last_seen_at = $5
       WHERE public_id = $1
       RETURNING public_id`,
      [row.public_id, category, fullNote, nextFirstSeenAt, nextLastSeenAt]
    );
    return { status: 'updated', publicId: upd.rows[0]?.public_id || row.public_id };
  }

  const upd = await client.query(
    `UPDATE ioc_items
     SET note = $2,
         first_seen_at = $3,
         last_seen_at = $4
     WHERE public_id = $1
     RETURNING public_id`,
    [row.public_id, fullNote, nextFirstSeenAt, nextLastSeenAt]
  );
  return { status: 'observation_updated', publicId: upd.rows[0]?.public_id || row.public_id };
}

async function maybeReactivateUrlhausMembership(client, entry, sourceName, category) {
  await importSideEffect('urlhaus_membership_reactivate', null, () => syncMembershipAfterIocImport(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl: URLHAUS_EXPORT_URL_MASKED,
    category,
    reactivateOnly: true
  }));
}

export async function updateUrlhausObservableBySource(client, entry, sourceName, note, category) {
  const fullNote = note || buildUrlhausNote(entry);
  const lastOnlineAt = entry.lastOnline || null;
  const existing = await updateUrlhausExistingIocBySource(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    fullNote,
    category,
    dateAddedAt: entry.dateAdded,
    lastOnlineAt
  });

  if (existing.status === 'unchanged' || existing.status === 'observation_updated') {
    await maybeReactivateUrlhausMembership(client, entry, sourceName, category);
    return existing;
  }
  if (existing.status !== 'updated') return existing;

  const publicId = existing.publicId;
  const observables = extractObservablesFromNote(entry.observableType, entry.observable, note);
  await insertObservablesIndex(client, publicId, observables);
  await importSideEffect('urlhaus_confidence', null, () => applyIocImportConfidence(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    parsedSourceConfidence: null
  }));
  await importSideEffect('urlhaus_membership', null, () => syncMembershipAfterIocImport(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl: URLHAUS_EXPORT_URL_MASKED,
    category
  }));
  return existing;
}

function mergeUrlhausFirstSeenAt(stored, incoming) {
  if (!incoming) return stored ?? null;
  if (!stored) return incoming;
  return new Date(incoming) < new Date(stored) ? incoming : stored;
}

function mergeUrlhausLastSeenAt(stored, incoming) {
  if (!incoming) return stored ?? null;
  if (!stored) return incoming;
  return new Date(incoming) > new Date(stored) ? incoming : stored;
}

function urlhausObservationChanged(row, { fullNote, nextFirstSeenAt, nextLastSeenAt }) {
  const storedFirst = row.first_seen_at ? new Date(row.first_seen_at).toISOString() : null;
  const storedLast = row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null;
  const nextFirst = nextFirstSeenAt ? new Date(nextFirstSeenAt).toISOString() : null;
  const nextLast = nextLastSeenAt ? new Date(nextLastSeenAt).toISOString() : null;
  return storedFirst !== nextFirst
    || storedLast !== nextLast
    || String(row.note || '') !== String(fullNote || '');
}

export async function upsertUrlhausObservable(client, entry, sourceName, suppressionStats, metrics, feedDefaultConfidence = null) {
  const note = buildUrlhausNote(entry);
  const category = entry.threat || 'malware-url';
  const sourceUrl = URLHAUS_EXPORT_URL_MASKED;

  const existing = await updateUrlhausObservableBySource(client, entry, sourceName, note, category);
  if (existing.status === 'updated') {
    metrics.noteUpdated();
    await storeFeedSourceEvidence(client, {
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName,
      sourceUrl,
      category,
      note,
      confidence: null
    });
    return;
  }
  if (existing.status === 'unchanged' || existing.status === 'observation_updated') {
    if (existing.status === 'observation_updated') {
      await storeFeedSourceEvidence(client, {
        observable: entry.observable,
        observableType: entry.observableType,
        sourceName,
        sourceUrl,
        category,
        note,
        confidence: null
      });
    }
    metrics.noteSkipped();
    return;
  }

  const insertResult = await insertObservable(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl,
    sourceConfidence: null,
    feedDefaultConfidence,
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

  if (insertResult === 'duplicate') {
    const existingAfterDuplicate = await updateUrlhausObservableBySource(client, entry, sourceName, note, category);
    if (existingAfterDuplicate.status === 'updated') {
      metrics.noteUpdated();
    } else if (existingAfterDuplicate.status === 'unchanged' || existingAfterDuplicate.status === 'observation_updated') {
      metrics.noteSkipped();
    } else {
      metrics.noteDuplicate();
    }
    return;
  }

  metrics.noteDuplicate();
}

export async function updateMalwareBazaarObservableBySource(client, entry, sourceName, note, category) {
  const existing = await updateExistingIocBySourceIfChanged(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    note,
    category,
    firstSeenAt: entry.firstSeenUtc,
    lastSeenAt: entry.firstSeenUtc
  });

  if (existing.status === 'unchanged') {
    // Active membership: intentional no-op — skip all DB writes.
    // Inactive/expired membership: reactivate without updating ioc_items metadata,
    // because feed re-appearance is semantically meaningful regardless of metadata change.
    await importSideEffect('malwarebazaar_membership_reactivate', null, () => syncMembershipAfterIocImport(client, {
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName,
      sourceUrl: MALWAREBAZAAR_EXPORT_URL_MASKED,
      explicitConfidence: entry.confidence,
      category,
      reactivateOnly: true
    }));
    return existing;
  }
  if (existing.status !== 'updated') return existing;

  const publicId = existing.publicId;
  const observables = extractObservablesFromNote(entry.observableType, entry.observable, note);
  await insertObservablesIndex(client, publicId, observables);
  await importSideEffect('malwarebazaar_confidence', null, () => applyIocImportConfidence(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    parsedSourceConfidence: entry.confidence
  }));
  await importSideEffect('malwarebazaar_membership', null, () => syncMembershipAfterIocImport(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl: MALWAREBAZAAR_EXPORT_URL_MASKED,
    explicitConfidence: entry.confidence,
    category
  }));
  return existing;
}

async function upsertMalwareBazaarObservable(client, entry, sourceName, suppressionStats, metrics) {
  const note = buildMalwareBazaarNote(entry);
  const category = entry.category || 'malware';
  const sourceUrl = MALWAREBAZAAR_EXPORT_URL_MASKED;

  const existing = await updateMalwareBazaarObservableBySource(client, entry, sourceName, note, category);
  if (existing.status === 'updated') {
    metrics.noteUpdated();
    await storeFeedSourceEvidence(client, {
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName,
      sourceUrl,
      category,
      note,
      confidence: entry.confidence
    });
    return;
  }
  if (existing.status === 'unchanged') {
    metrics.noteSkipped();
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

  if (insertResult === 'duplicate') {
    const existingAfterDuplicate = await updateMalwareBazaarObservableBySource(client, entry, sourceName, note, category);
    if (existingAfterDuplicate.status === 'updated') {
      metrics.noteUpdated();
    } else if (existingAfterDuplicate.status === 'unchanged') {
      metrics.noteSkipped();
    } else {
      metrics.noteDuplicate();
    }
    return;
  }

  metrics.noteDuplicate();
}

function mergeThreatFoxFirstSeenAt(stored, incoming) {
  if (!incoming) return stored ?? null;
  if (!stored) return incoming;
  return new Date(incoming) < new Date(stored) ? incoming : stored;
}

function mergeThreatFoxLastSeenAt(stored, incoming) {
  if (!incoming) return stored ?? null;
  if (!stored) return incoming;
  return new Date(incoming) > new Date(stored) ? incoming : stored;
}

function threatFoxObservationChanged(row, { fullNote, nextFirstSeenAt, nextLastSeenAt }) {
  const storedFirst = row.first_seen_at ? new Date(row.first_seen_at).toISOString() : null;
  const storedLast = row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null;
  const nextFirst = nextFirstSeenAt ? new Date(nextFirstSeenAt).toISOString() : null;
  const nextLast = nextLastSeenAt ? new Date(nextLastSeenAt).toISOString() : null;
  return storedFirst !== nextFirst
    || storedLast !== nextLast
    || String(row.note || '') !== String(fullNote || '');
}

/**
 * ThreatFox update: separates volatile provider last_seen from semantic metadata.
 * Returns status: not_found | unchanged | observation_updated | updated
 */
export async function updateThreatFoxExistingIocBySource(client, {
  observable,
  observableType,
  sourceName,
  fullNote,
  category,
  firstSeenAt = null,
  lastSeenAt = null
}) {
  const { rows } = await client.query(
    `SELECT public_id, note, category, first_seen_at, last_seen_at
     FROM ioc_items
     WHERE observable = $1
       AND observable_type = $2
       AND source_name = $3
     ORDER BY created_at ASC
     LIMIT 1`,
    [observable, observableType, sourceName]
  );
  const row = rows[0];
  if (!row) return { status: 'not_found' };

  const nextFirstSeenAt = mergeThreatFoxFirstSeenAt(row.first_seen_at, firstSeenAt);
  const nextLastSeenAt = mergeThreatFoxLastSeenAt(row.last_seen_at, lastSeenAt);
  const semanticChanged = String(row.category || '') !== String(category || '')
    || !threatFoxNotesSemanticallyEqual(row.note, fullNote);
  const observationChanged = threatFoxObservationChanged(row, {
    fullNote,
    nextFirstSeenAt,
    nextLastSeenAt
  });

  if (!semanticChanged && !observationChanged) {
    return { status: 'unchanged', publicId: row.public_id };
  }

  if (semanticChanged) {
    const upd = await client.query(
      `UPDATE ioc_items
       SET category = $2,
           note = $3,
           first_seen_at = $4,
           last_seen_at = $5
       WHERE public_id = $1
       RETURNING public_id`,
      [row.public_id, category, fullNote, nextFirstSeenAt, nextLastSeenAt]
    );
    return { status: 'updated', publicId: upd.rows[0]?.public_id || row.public_id };
  }

  const upd = await client.query(
    `UPDATE ioc_items
     SET note = $2,
         first_seen_at = $3,
         last_seen_at = $4
     WHERE public_id = $1
     RETURNING public_id`,
    [row.public_id, fullNote, nextFirstSeenAt, nextLastSeenAt]
  );
  return { status: 'observation_updated', publicId: upd.rows[0]?.public_id || row.public_id };
}

async function maybeReactivateThreatFoxMembership(client, entry, sourceName, category) {
  await importSideEffect('threatfox_membership_reactivate', null, () => syncMembershipAfterIocImport(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl: THREATFOX_SOURCE_URL_MASKED,
    explicitConfidence: entry.confidence,
    category,
    reactivateOnly: true
  }));
}

export async function updateThreatFoxObservableBySource(client, entry, sourceName, note, category) {
  const fullNote = note || buildThreatFoxNote(entry);
  const existing = await updateThreatFoxExistingIocBySource(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    fullNote,
    category,
    firstSeenAt: entry.firstSeen,
    lastSeenAt: entry.lastSeen || entry.firstSeen
  });

  if (existing.status === 'unchanged' || existing.status === 'observation_updated') {
    // Active membership: skip last_seen_in_feed refresh on unchanged/observation-only rows.
    // Inactive/expired membership: reactivate (updates last_seen_in_feed by design).
    await maybeReactivateThreatFoxMembership(client, entry, sourceName, category);
    return existing;
  }
  if (existing.status !== 'updated') return existing;

  const publicId = existing.publicId;
  const observables = extractObservablesFromNote(entry.observableType, entry.observable, note);
  await insertObservablesIndex(client, publicId, observables);
  await importSideEffect('threatfox_confidence', null, () => applyIocImportConfidence(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    parsedSourceConfidence: entry.confidence
  }));
  await importSideEffect('threatfox_membership', null, () => syncMembershipAfterIocImport(client, {
    observable: entry.observable,
    observableType: entry.observableType,
    sourceName,
    sourceUrl: THREATFOX_SOURCE_URL_MASKED,
    explicitConfidence: entry.confidence,
    category
  }));
  return existing;
}

async function upsertThreatFoxObservable(client, entry, sourceName, suppressionStats, metrics) {
  const note = buildThreatFoxNote(entry);
  const category = entry.threatType || 'threat-intel';
  const sourceUrl = THREATFOX_SOURCE_URL_MASKED;

  const existing = await updateThreatFoxObservableBySource(client, entry, sourceName, note, category);
  if (existing.status === 'updated') {
    metrics.noteUpdated();
    await storeFeedSourceEvidence(client, {
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName,
      sourceUrl,
      category,
      note,
      confidence: entry.confidence
    });
    return;
  }
  if (existing.status === 'unchanged' || existing.status === 'observation_updated') {
    if (existing.status === 'observation_updated') {
      await storeFeedSourceEvidence(client, {
        observable: entry.observable,
        observableType: entry.observableType,
        sourceName,
        sourceUrl,
        category,
        note,
        confidence: entry.confidence
      });
    }
    metrics.noteSkipped();
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
    if (entry.firstSeen || entry.lastSeen) {
      await updateThreatFoxObservableBySource(client, entry, sourceName, note, category);
    }
    return;
  }

  if (insertResult === 'duplicate') {
    const existingAfterDuplicate = await updateThreatFoxObservableBySource(client, entry, sourceName, note, category);
    if (existingAfterDuplicate.status === 'updated') {
      metrics.noteUpdated();
    } else if (existingAfterDuplicate.status === 'unchanged' || existingAfterDuplicate.status === 'observation_updated') {
      metrics.noteSkipped();
    } else {
      metrics.noteDuplicate();
    }
    return;
  }

  metrics.noteDuplicate();
}

function mergeBatchInsertMetrics(metrics, batchResult) {
  metrics.records_inserted += Number(batchResult?.inserted || 0);
  metrics.records_updated += Number(batchResult?.updated || 0);
  metrics.records_duplicate += Number(batchResult?.duplicate || 0);
  metrics.records_suppressed += Number(batchResult?.suppressed || 0);
  metrics.records_skipped += Number(batchResult?.skipped || 0);
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
export async function batchInsertIocs(client, entries, observableType = 'ip', suppressionStats = null, signal = null, options = {}) {
  const duplicateHandling = String(options.duplicateHandling || 'full').trim();
  const out = { inserted: 0, updated: 0, duplicate: 0, suppressed: 0, skipped: 0 };
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
         WHERE i.observable = v.observable
           AND i.observable_type = $${typeParam}
       )
       RETURNING public_id, observable, note`,
      [...params.flat(), observableType]
    );
    const rows = ins.rows ?? [];
    out.inserted += rows.length;
    const duplicateCount = resolvedKept.length - rows.length;
    if (duplicateHandling !== 'count_only') {
      out.duplicate += duplicateCount;
    }
    const insertedObs = new Set(rows.map((r) => r.observable));

    if (duplicateHandling === 'count_only') {
      const duplicateEntries = resolvedKept.filter((e) => !insertedObs.has(e.observable ?? e.ip));
      for (const e of duplicateEntries) {
        throwIfAborted(signal);
        const obs = e.observable ?? e.ip;
        const existing = await updateObservableBySourceOnImport(client, {
          observable: obs,
          observableType,
          sourceName: e.sourceName,
          sourceUrl: e.sourceUrl ?? null,
          category: e.category ?? null,
          note: e.note ?? null
        }).catch(() => ({ status: 'not_found' }));
        if (existing.status === 'unchanged') {
          out.skipped += 1;
        } else if (existing.status === 'updated') {
          out.updated += 1;
          await importSideEffect('batch_count_only_membership', null, () => syncMembershipAfterIocImport(client, {
            observable: obs,
            observableType,
            sourceName: e.sourceName,
            sourceUrl: e.sourceUrl ?? null,
            explicitConfidence: e.confFields?.source_confidence ?? null,
            category: e.category ?? null
          }));
        } else {
          out.duplicate += 1;
          await importSideEffect('batch_count_only_cross_source_membership', null, () => syncMembershipAfterIocImport(client, {
            observable: obs,
            observableType,
            sourceName: e.sourceName,
            sourceUrl: e.sourceUrl ?? null,
            explicitConfidence: e.confFields?.source_confidence ?? null,
            category: e.category ?? null
          }));
        }
      }
    } else for (const e of resolvedKept) {
      throwIfAborted(signal);
      const obs = e.observable ?? e.ip;
      if (!insertedObs.has(obs)) {
        const existing = await updateObservableBySourceOnImport(client, {
          observable: obs,
          observableType,
          sourceName: e.sourceName,
          sourceUrl: e.sourceUrl ?? null,
          category: e.category ?? null,
          note: e.note ?? null
        }).catch(() => ({ status: 'not_found' }));
        if (existing.status === 'unchanged') {
          out.skipped += 1;
          continue;
        }
        if (existing.status === 'updated') {
          await importSideEffect('batch_duplicate_confidence', null, () => applyIocImportConfidence(client, {
            observable: obs,
            observableType,
            sourceName: e.sourceName,
            parsedSourceConfidence: resolveParsedSourceConfidence(e.sourceConfidence, e.confidence)
          }));
        }
        await importSideEffect('batch_duplicate_membership', null, () => syncMembershipAfterIocImport(client, {
          observable: obs,
          observableType,
          sourceName: e.sourceName,
          sourceUrl: e.sourceUrl ?? null,
          explicitConfidence: e.confFields?.source_confidence ?? null,
          category: e.category ?? null
        }));
      }
    }
    for (const row of rows) {
      throwIfAborted(signal);
      const observables = extractObservablesFromNote(observableType, row.observable, row.note);
      await insertObservablesIndex(client, row.public_id, observables);
      const src = resolvedKept.find((e) => (e.observable ?? e.ip) === row.observable);
      if (src) {
        await importSideEffect('batch_insert_membership', null, () => syncMembershipAfterIocImport(client, {
          observable: row.observable,
          observableType,
          sourceName: src.sourceName,
          sourceUrl: src.sourceUrl ?? null,
          explicitConfidence: src.confFields.source_confidence,
          category: src.category ?? null
        }));
      }
    }
  }
  return out;
}

export async function updateObservableBySourceOnImport(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl,
  category,
  note
}) {
  const existing = await updateExistingIocBySourceIfChanged(client, {
    observable,
    observableType,
    sourceName,
    sourceUrl,
    category,
    note,
    matchSourceUrl: true
  });
  if (existing.status !== 'updated') return existing;

  const publicId = existing.publicId;
  const observables = extractObservablesFromNote(observableType, observable, note);
  await insertObservablesIndex(client, publicId, observables);
  return existing;
}

async function insertObservable(client, { observable, observableType, sourceName, sourceUrl, confidence, category, note, sourceConfidence = null, feedDefaultConfidence = null }, suppressionStats = null, signal = null) {
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
    parsedSourceConfidence: resolveParsedSourceConfidence(sourceConfidence, confidence),
    feedDefaultConfidence
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
    const existing = await updateObservableBySourceOnImport(client, {
      observable,
      observableType,
      sourceName,
      sourceUrl,
      category,
      note
    }).catch(() => ({ status: 'not_found' }));
    if (existing.status === 'unchanged') {
      await storeFeedSourceEvidence(client, {
        observable,
        observableType,
        sourceName,
        sourceUrl,
        category,
        note,
        confidence: confFields.confidence
      });
      return 'unchanged';
    }
    if (existing.status === 'updated') {
      await importSideEffect('duplicate_confidence', null, () => applyIocImportConfidence(client, {
        observable,
        observableType,
        sourceName,
        parsedSourceConfidence: resolveParsedSourceConfidence(sourceConfidence, confidence)
      }));
    }
    await storeFeedSourceEvidence(client, {
      observable,
      observableType,
      sourceName,
      sourceUrl,
      category,
      note,
      confidence: confFields.confidence
    });
    await importSideEffect('duplicate_membership', null, () => syncMembershipAfterIocImport(client, {
      observable,
      observableType,
      sourceName,
      sourceUrl,
      explicitConfidence: confFields.source_confidence,
      category
    }));
    return 'duplicate';
  }

  const publicId = ins.rows[0].public_id;
  const observables = extractObservablesFromNote(observableType, observable, note);
  await insertObservablesIndex(client, publicId, observables);
  await storeFeedSourceEvidence(client, {
    observable,
    observableType,
    sourceName,
    sourceUrl,
    category,
    note,
    confidence: confFields.confidence
  });
  await importSideEffect('insert_membership', null, () => syncMembershipAfterIocImport(client, {
    observable,
    observableType,
    sourceName,
    sourceUrl,
    explicitConfidence: confFields.source_confidence,
    category
  }));
  return true;
}

export async function runHourlyImport(options = {}) {
  const { signal } = options;
  const triggeredBy = resolveTriggeredBy(options);
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

    return await withImportOptimizationContext(client, async () => {
    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('hourly_import', 'running', clock_timestamp(), $1)
       RETURNING id`,
      [triggeredBy]
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
      const contentHash = hashContent(body);
      const sourceName = `EmergingThreats:${file}`;

      const prevState = await client.query(
        `SELECT content_hash, items_json FROM integration_source_state WHERE source_name = $1`,
        [sourceName]
      );
      if (prevState.rows[0]?.content_hash === contentHash) {
        const ipCount = Number(prevState.rows[0]?.items_json?.ip_count || 0);
        metrics.noteSkipped(ipCount > 0 ? ipCount : 1);
        console.log(
          `[integration-import] job=hourly_import runId=${runId} file=${file} unchanged_hash skipped_ips=${ipCount || 1}`
        );
        continue;
      }

      const ips = extractIPs(body);
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
        mergeBatchInsertMetrics(
          metrics,
          await batchInsertIocs(tx, entries, 'ip', suppressionStats, signal, { duplicateHandling: 'count_only' })
        );
        await tx.query(
          `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
           VALUES ($1, $2, $3::jsonb, NOW())
           ON CONFLICT (source_name)
           DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
          [sourceName, contentHash, JSON.stringify({ ip_count: ips.length, file })]
        );
      }, { ...txMeta, file });
    }

    throwIfAborted(signal);
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
    console.log(
      `[integration-import] job=hourly_import runId=${runId} files=${files.length} processed=${metrics.recordsProcessed()} inserted=${metrics.records_inserted} duplicate=${metrics.records_duplicate} skipped=${metrics.records_skipped}`
    );
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    });
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
  const triggeredBy = resolveTriggeredBy(options);
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

    return await withImportOptimizationContext(client, async () => {
    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('usom_import', 'running', clock_timestamp(), $1)
       RETURNING id`,
      [triggeredBy]
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

    const mapUsomSnapshotEntry = (entry) => ({
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: config.usomSourceName,
      sourceUrl: config.usomApiUrl,
      category: 'threat-intel'
    });

    if (previousHash === currentHash) {
      metrics.noteSkipped(entries.length);
      throwIfAborted(signal);

      await client.query(
        `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (source_name)
         DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
        [config.usomSourceName, `hash:${currentHash}`]
      );

      await finalizeIntegrationRun(client, runId, metrics);
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
    await runSnapshotSync(client, 'usom-trcert', entries, mapUsomSnapshotEntry, { signal });
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

    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('usom_import', runId, suppressionStats, metrics.toJSON());
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    });
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
  const triggeredBy = resolveTriggeredBy(options);
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

    return await withImportOptimizationContext(client, async () => {
    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('urlhaus_import', 'running', clock_timestamp(), $1)
       RETURNING id`,
      [triggeredBy]
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

    const priorCheckpoint = await loadUrlhausCheckpoint(client, config.urlhausSourceName);
    const exportFetch = await fetchUrlhausExport(authKey, {
      signal,
      checkpoint: priorCheckpoint,
      fetchImpl: (url, init) => fetchWithSignal(url, init, signal)
    });

    const etagSkip = evaluateUrlhausExportSkip({
      checkpoint: priorCheckpoint,
      statusCode: exportFetch.status,
      responseEtag: exportFetch.etag,
      responseLastModified: exportFetch.lastModified,
      canonicalIocHash: null
    });

    if (etagSkip.skip) {
      await saveUrlhausCheckpoint(client, config.urlhausSourceName, {
        etag: exportFetch.etag ?? priorCheckpoint?.etag ?? null,
        last_modified: exportFetch.lastModified ?? priorCheckpoint?.last_modified ?? null,
        raw_content_hash: priorCheckpoint?.raw_content_hash ?? exportFetch.rawContentHash ?? null,
        canonical_ioc_hash: priorCheckpoint?.canonical_ioc_hash ?? null
      });
      await finalizeIntegrationRun(client, runId, metrics, 'skipped_unchanged');
      console.log(
        `[integration-import] job=urlhaus_import runId=${runId} skipped unchanged reason=${etagSkip.reason} export=${URLHAUS_EXPORT_URL_MASKED}`
      );
      return withSuppressionStats(
        { ok: true, runId, skipped: true, reason: 'unchanged', skipReason: etagSkip.reason },
        suppressionStats,
        metrics
      );
    }

    const txt = exportFetch.text;
    const { entries, fetched, parsed, skipped } = parseUrlhausRecentCsv(txt);
    const canonicalIocHash = buildUrlhausCanonicalIocHash(entries);

    const canonicalSkip = evaluateUrlhausExportSkip({
      checkpoint: priorCheckpoint,
      statusCode: exportFetch.status,
      responseEtag: exportFetch.etag,
      responseLastModified: exportFetch.lastModified,
      canonicalIocHash
    });

    if (canonicalSkip.skip) {
      await saveUrlhausCheckpoint(client, config.urlhausSourceName, {
        etag: exportFetch.etag ?? null,
        last_modified: exportFetch.lastModified ?? null,
        raw_content_hash: exportFetch.rawContentHash ?? null,
        canonical_ioc_hash: canonicalIocHash
      });
      metrics.noteSkipped(parsed);
      await finalizeIntegrationRun(client, runId, metrics, 'skipped_unchanged');
      console.log(
        `[integration-import] job=urlhaus_import runId=${runId} skipped unchanged reason=${canonicalSkip.reason} export=${URLHAUS_EXPORT_URL_MASKED} parsed=${parsed}`
      );
      return withSuppressionStats(
        { ok: true, runId, skipped: true, reason: 'unchanged', skipReason: canonicalSkip.reason },
        suppressionStats,
        metrics
      );
    }

    metrics.noteSkipped(skipped + Math.max(0, fetched - parsed));

    const urlhausFeedDefault = await fetchFeedDefaultConfidence(client, URLHAUS_FEED_KEY);
    const batchSize = Number(process.env.URLHAUS_BATCH_SIZE || 1000);

    for (let i = 0; i < entries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = entries.slice(i, i + batchSize);
      await withPgTransaction(client, 'urlhaus_import_batch', async (tx) => {
        for (const entry of batch) {
          throwIfAborted(signal);
          await upsertUrlhausObservable(
            tx,
            entry,
            config.urlhausSourceName,
            suppressionStats,
            metrics,
            urlhausFeedDefault
          );
        }
      }, { ...txMeta, job_id: runId, batch: Math.floor(i / batchSize) + 1 });
    }

    throwIfAborted(signal);
    await saveUrlhausCheckpoint(
      client,
      config.urlhausSourceName,
      {
        etag: exportFetch.etag ?? null,
        last_modified: exportFetch.lastModified ?? null,
        raw_content_hash: exportFetch.rawContentHash ?? null,
        canonical_ioc_hash: canonicalIocHash
      },
      { entries }
    );

    throwIfAborted(signal);
    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('urlhaus_import', runId, suppressionStats, metrics.toJSON());
    console.log(
      `[integration-import] job=urlhaus_import runId=${runId} export=${URLHAUS_EXPORT_URL_MASKED} fetched=${fetched} parsed=${parsed} skipped=${skipped}`
    );
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    });
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
  const triggeredBy = resolveTriggeredBy(options);
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

    return await withImportOptimizationContext(client, async () => {
    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('threatfox_import', 'running', clock_timestamp(), $1)
       RETURNING id`,
      [triggeredBy]
    );
    runId = runInsert.rows[0].id;

    const authKey = await resolveThreatFoxAuthKey(client, config.threatfoxAuthKey);
    if (!authKey) {
      metrics.noteSkipped(0);
      await finalizeIntegrationRun(client, runId, metrics);
      return withSuppressionStats(
        { ok: true, runId, skipped: true, reason: THREATFOX_AUTH_REQUIRED_MSG },
        suppressionStats,
        metrics
      );
    }

    const recentDays = await resolveThreatFoxRecentDays(client, config.threatfoxRecentDays);
    const { entries, fetched, parsed, skipped, queryStatus } = await fetchThreatFoxRecentIocs({
      authKey,
      apiUrl: config.threatfoxApiUrl,
      days: recentDays,
      signal,
      fetchFn: (url, init) => fetchWithSignal(url, init, signal)
    });
    metrics.noteSkipped(skipped + Math.max(0, fetched - parsed));

    const currentHash = hashEntries(entries.map((e) => ({
      o: e.observable,
      t: e.observableType,
      id: e.iocId
    })));

    const batchSize = Number(process.env.THREATFOX_BATCH_SIZE || 1000);

    for (let i = 0; i < entries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = entries.slice(i, i + batchSize);
      await withPgTransaction(client, 'threatfox_import_batch', async (tx) => {
        for (const entry of batch) {
          throwIfAborted(signal);
          await upsertThreatFoxObservable(tx, entry, config.threatfoxSourceName, suppressionStats, metrics);
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
        config.threatfoxSourceName,
        currentHash,
        JSON.stringify(entries.map((e) => ({ observable: e.observable, observableType: e.observableType })))
      ]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.threatfoxSourceName, `recent:${recentDays}:${currentHash}`]
    );

    throwIfAborted(signal);
    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('threatfox_import', runId, suppressionStats, metrics.toJSON());
    console.log(
      `[integration-import] job=threatfox_import runId=${runId} api=${THREATFOX_SOURCE_URL_MASKED} days=${recentDays} query_status=${queryStatus || 'ok'} fetched=${fetched} parsed=${parsed} skipped=${skipped}`
    );
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    });
  } catch (err) {
    const safeMessage = sanitizeThreatFoxErrorMessage(err?.message || err);
    if (runId) {
      await failIntegrationRun(client, runId, safeMessage, metrics);
    }
    const wrapped = new Error(safeMessage);
    wrapped.cause = err;
    throw wrapped;
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
  const triggeredBy = resolveTriggeredBy(options);
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

    return await withImportOptimizationContext(client, async () => {
    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('malwarebazaar_import', 'running', clock_timestamp(), $1)
       RETURNING id`,
      [triggeredBy]
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

    throwIfAborted(signal);
    await finalizeIntegrationRun(client, runId, metrics);
    logImportSuppressionSummary('malwarebazaar_import', runId, suppressionStats, metrics.toJSON());
    console.log(
      `[integration-import] job=malwarebazaar_import runId=${runId} export=${MALWAREBAZAAR_EXPORT_URL_MASKED} fetched=${fetched} parsed=${parsed} skipped=${skipped}`
    );
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    });
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
  const triggeredBy = resolveTriggeredBy(options);
  const client = await pool.connect();
  let runId = null;
  const suppressionStats = createSuppressionStats();
  const metrics = createImportMetrics();
  const txMeta = { source_key: 'phishtank-opendnsrr', signal };
  const t0 = Date.now();
  const phase = {
    fetch_ms: 0,
    parse_ms: 0,
    build_entries_ms: 0,
    db_write_total_ms: 0,
    finalize_ms: 0,
    total_ms: 0
  };
  const batchStats = { count: 0, max_ms: 0, total_ms: 0, slowest: [] };
  let currentPhase = 'init';
  let currentBatchNo = 0;
  let rowCount = 0;
  let validCount = 0;

  try {
    throwIfAborted(signal);
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942006) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    return await withImportOptimizationContext(client, async () => {
    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('phishtank_import', 'running', clock_timestamp(), $1)
       RETURNING id`,
      [triggeredBy]
    );
    runId = runInsert.rows[0].id;
    txMeta.job_id = runId;

    currentPhase = 'fetch';
    const tfetch = Date.now();
    const response = await fetchWithSignal(config.phishTankCsvUrl, {
      headers: { 'User-Agent': 'demo-runbook-integration/1.0' }
    }, signal);
    if (!response.ok) throw new Error(`Failed to fetch PhishTank CSV: ${response.status}`);

    const text = await response.text();
    phase.fetch_ms = Date.now() - tfetch;

    currentPhase = 'parse';
    const tparse = Date.now();
    const lines = text.split(/\r?\n/).filter(Boolean);
    phase.parse_ms = Date.now() - tparse;
    rowCount = Math.max(0, lines.length - 1);
    if (lines.length <= 1) {
      await withPgTransaction(client, 'phishtank_import_finalize', async (tx) => {
        await finalizeIntegrationRun(tx, runId, metrics);
      }, txMeta);
      return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    }

    const sourceName = config.phishTankSourceName;
    const sourceUrl = config.phishTankCsvUrl;
    const parsedEntries = [];

    currentPhase = 'build_entries';
    const tbuild = Date.now();
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
    phase.build_entries_ms = Date.now() - tbuild;
    validCount = parsedEntries.length;

    const entries = parsedEntries.sort(
      (a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`)
    );
    const currentHash = hashEntries(entries.map((e) => ({ o: e.observable, t: e.observableType })));

    const prevState = await client.query(
      `SELECT content_hash, items_json FROM integration_source_state WHERE source_name = $1`,
      [config.phishTankSourceName]
    );
    const previousHash = prevState.rows[0]?.content_hash || null;
    const previousItems = Array.isArray(prevState.rows[0]?.items_json) ? prevState.rows[0].items_json : [];
    const previousSet = new Set(previousItems.map((x) => `${x.observableType}|${x.observable}`));

    if (previousHash === currentHash) {
      metrics.noteSkipped(entries.length);
      throwIfAborted(signal);
      await withPgTransaction(client, 'phishtank_import_finalize', async (tx) => {
        await finalizeIntegrationRun(tx, runId, metrics);
      }, txMeta);
      return withSuppressionStats({ ok: true, runId, skipped: true, reason: 'same_hash' }, suppressionStats, metrics);
    }

    const addedEntries = entries.filter((e) => !previousSet.has(`${e.observableType}|${e.observable}`));
    metrics.noteSkipped(entries.length - addedEntries.length);

    const batchSize = Math.max(Number(process.env.PHISHTANK_BATCH_SIZE || 2000), 100);
    currentPhase = 'db_write';
    for (let i = 0; i < addedEntries.length; i += batchSize) {
      throwIfAborted(signal);
      const batch = addedEntries.slice(i, i + batchSize);
      const batchNo = Math.floor(i / batchSize) + 1;
      currentBatchNo = batchNo;
      const tb = Date.now();
      await withPgTransaction(client, 'phishtank_import_batch', async (tx) => {
        mergeBatchInsertMetrics(
          metrics,
          await batchInsertIocs(tx, batch, 'url', suppressionStats, signal, { duplicateHandling: 'count_only' })
        );
      }, { ...txMeta, batch: batchNo });
      const bms = Date.now() - tb;
      phase.db_write_total_ms += bms;
      batchStats.count += 1;
      batchStats.total_ms += bms;
      batchStats.max_ms = Math.max(batchStats.max_ms, bms);
      batchStats.slowest.push({ batch_no: batchNo, batch_ms: bms, batch_size: batch.length });
      batchStats.slowest.sort((a, b) => b.batch_ms - a.batch_ms);
      if (batchStats.slowest.length > 5) batchStats.slowest.length = 5;

      const timeoutMs = Math.max(Number(process.env.PHISHTANK_JOB_TIMEOUT_MS || process.env.INTEGRATION_JOB_TIMEOUT_MS || 600000), 10000);
      const remaining = Math.max(0, timeoutMs - (Date.now() - t0));
      if (bms >= 10000) {
        console.warn(`[integration-import][phishtank][slow-batch] run_id=${runId || '-'} batch_no=${batchNo} batch_size=${batch.length} batch_ms=${bms} remaining_timeout_ms=${remaining}`);
      } else if (batchNo % 5 === 0) {
        console.log(`[integration-import][phishtank][progress] run_id=${runId || '-'} batch_no=${batchNo} batch_ms=${bms} remaining_timeout_ms=${remaining}`);
      }
    }

    currentPhase = 'finalize';
    const tfinal = Date.now();
    throwIfAborted(signal);
    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
      [config.phishTankSourceName, currentHash, JSON.stringify(entries.map((e) => ({ observable: e.observable, observableType: e.observableType })))]
    );
    await withPgTransaction(client, 'phishtank_import_finalize', async (tx) => {
      await finalizeIntegrationRun(tx, runId, metrics);
    }, txMeta);

    phase.finalize_ms = Date.now() - tfinal;
    phase.total_ms = Date.now() - t0;
    const m = metrics.toJSON();
    const avgBatch = batchStats.count ? Math.round(batchStats.total_ms / batchStats.count) : 0;
    console.log(`[integration-import][phishtank][summary] run_id=${runId} source=phishtank-opendnsrr timeout_ms=${process.env.PHISHTANK_JOB_TIMEOUT_MS || process.env.INTEGRATION_JOB_TIMEOUT_MS || 600000} fetch_ms=${phase.fetch_ms} parse_ms=${phase.parse_ms} build_entries_ms=${phase.build_entries_ms} db_write_total_ms=${phase.db_write_total_ms} finalize_ms=${phase.finalize_ms} total_ms=${phase.total_ms} row_count=${rowCount} valid_count=${validCount} skipped_count=${m.records_skipped} inserted_count=${m.records_inserted} updated_count=${m.records_updated} batch_count=${batchStats.count} avg_batch_ms=${avgBatch} max_batch_ms=${batchStats.max_ms} slowest_batches='${JSON.stringify(batchStats.slowest)}' failure_phase=none`);
    logImportSuppressionSummary('phishtank_import', runId, suppressionStats, metrics.toJSON());
    return withSuppressionStats({ ok: true, runId }, suppressionStats, metrics);
    });
  } catch (err) {
    phase.total_ms = Date.now() - t0;
    const m = metrics.toJSON();
    const avgBatch = batchStats.count ? Math.round(batchStats.total_ms / batchStats.count) : 0;
    console.warn(`[integration-import][phishtank][summary] run_id=${runId || '-'} source=phishtank-opendnsrr timeout_ms=${process.env.PHISHTANK_JOB_TIMEOUT_MS || process.env.INTEGRATION_JOB_TIMEOUT_MS || 600000} fetch_ms=${phase.fetch_ms} parse_ms=${phase.parse_ms} build_entries_ms=${phase.build_entries_ms} db_write_total_ms=${phase.db_write_total_ms} finalize_ms=${phase.finalize_ms} total_ms=${phase.total_ms} row_count=${rowCount} valid_count=${validCount} skipped_count=${m.records_skipped} inserted_count=${m.records_inserted} updated_count=${m.records_updated} batch_count=${batchStats.count} avg_batch_ms=${avgBatch} max_batch_ms=${batchStats.max_ms} slowest_batches='${JSON.stringify(batchStats.slowest)}' failure_phase=${currentPhase} current_batch_no=${currentBatchNo} error=${String(err?.message || err).replace(/\s+/g,' ').slice(0,260)}`);
    if (runId) {
      await failIntegrationRun(client, runId, err.message, metrics);
    }
    throw err;
  } finally {
    try { await client.query('SELECT pg_advisory_unlock(942006)'); } catch {}
    client.release();
  }
}
