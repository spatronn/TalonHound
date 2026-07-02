/**
 * URLhaus recent CSV export (abuse.ch) — auth, parsing, and safe logging.
 */

import { createHash } from 'node:crypto';

export const URLHAUS_FEED_KEY = 'urlhaus-abusech';
export const URLHAUS_EXPORT_BASE = 'https://urlhaus-api.abuse.ch/v2/files/exports';
export const URLHAUS_EXPORT_URL_MASKED = `${URLHAUS_EXPORT_BASE}/***/recent.csv`;
export const URLHAUS_AUTH_REQUIRED_MSG =
  'URLHaus Auth-Key is required. Configure it in integration settings or URLHAUS_AUTH_KEY env.';

export const URLHAUS_CSV_COLUMNS = [
  'id',
  'dateadded',
  'url',
  'url_status',
  'last_online',
  'threat',
  'tags',
  'urlhaus_link',
  'reporter'
];

const MIN_FETCH_INTERVAL_MS = 5 * 60 * 1000;

export function splitCsvLine(line) {
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

export function toNullable(value) {
  const v = String(value ?? '').trim();
  if (!v) return null;
  if (v.toLowerCase() === 'n/a') return null;
  return v;
}

export function parseUtcTimestamp(value) {
  const raw = toNullable(value);
  if (!raw) return null;
  const normalized = raw.replace(' ', 'T');
  const dt = new Date(`${normalized}Z`);
  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

export function normalizeUrlhausTags(raw) {
  const v = toNullable(raw);
  if (!v) return [];
  if (v.toLowerCase() === 'none') return [];
  return v.split(',').map((t) => t.trim()).filter(Boolean);
}

export function buildUrlhausRecentCsvUrl(authKey) {
  const key = String(authKey || '').trim();
  if (!key) throw new Error(URLHAUS_AUTH_REQUIRED_MSG);
  return `${URLHAUS_EXPORT_BASE}/${encodeURIComponent(key)}/recent.csv`;
}

export function maskUrlhausAuthKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `************${s.slice(-4)}`;
}

/** Redact auth keys embedded in export URLs from errors/logs/UI. */
export function sanitizeUrlhausErrorMessage(message) {
  let out = String(message || '');
  out = out.replace(
    /https?:\/\/urlhaus-api\.abuse\.ch\/v2\/files\/exports\/[^/\s]+\/recent\.csv/gi,
    URLHAUS_EXPORT_URL_MASKED
  );
  out = out.replace(/\/exports\/[^/\s]+\/recent\.csv/gi, '/exports/***/recent.csv');
  return out;
}

export function isUrlhausCsvHeaderLine(line) {
  const trimmed = String(line || '').trim().toLowerCase();
  if (!trimmed || trimmed.startsWith('#')) return false;
  const cols = splitCsvLine(trimmed).map((c) => c.toLowerCase());
  return cols[0] === 'id' && cols.includes('url') && cols.includes('dateadded');
}

export function mapUrlhausRow(cols) {
  if (!Array.isArray(cols) || cols.length < 9) return null;

  const externalId = toNullable(cols[0]);
  const url = toNullable(cols[2]);
  if (!externalId || !url) return null;

  const dateAdded = parseUtcTimestamp(cols[1]);
  const urlStatus = toNullable(cols[3]);
  const lastOnline = parseUtcTimestamp(cols[4]);
  const threat = toNullable(cols[5]) || 'malware-url';
  const tags = normalizeUrlhausTags(cols[6]);
  const referenceUrl = toNullable(cols[7]);
  const reporter = toNullable(cols[8]);

  const tagSet = new Set(tags);
  if (threat) tagSet.add(threat);

  return {
    observable: url,
    observableType: 'url',
    externalId,
    dateAdded,
    urlStatus,
    lastOnline,
    threat,
    tags: [...tagSet],
    referenceUrl,
    reporter
  };
}

export function buildUrlhausNote(entry) {
  const parts = [
    'Auto-imported from URLhaus CSV',
    entry.externalId ? `external_id=${entry.externalId}` : null,
    entry.referenceUrl ? `reference_url=${entry.referenceUrl}` : null,
    entry.urlStatus ? `url_status=${entry.urlStatus}` : null,
    entry.reporter ? `reporter=${entry.reporter}` : null,
    entry.tags?.length ? `tags=${entry.tags.join(',')}` : null,
    entry.lastOnline ? `last_online=${entry.lastOnline.toISOString()}` : null,
    entry.dateAdded ? `date_added=${entry.dateAdded.toISOString()}` : null
  ].filter(Boolean);
  return parts.join(' | ');
}

/** Note key for semantic metadata comparison — excludes volatile provider last_online. */
export function stripUrlhausVolatileNoteParts(note) {
  return String(note || '')
    .split(' | ')
    .map((part) => part.trim())
    .filter((part) => part && !/^last_online=/i.test(part))
    .join(' | ');
}

export function urlhausNotesSemanticallyEqual(storedNote, incomingNote) {
  return stripUrlhausVolatileNoteParts(storedNote) === stripUrlhausVolatileNoteParts(incomingNote);
}

/**
 * Stable SHA-256 fingerprint of provider-supplied metadata that is meaningful
 * and unlikely to change unless the IOC record genuinely changed.
 * Excludes last_online (volatile, updated on every poll by URLHaus).
 */
export function computeUrlhausProviderFingerprint(entry) {
  const payload = JSON.stringify({
    provider: 'urlhaus',
    external_id: String(entry.externalId ?? ''),
    observable: String(entry.observable ?? ''),
    url_status: String(entry.urlStatus ?? ''),
    threat: String(entry.threat ?? ''),
    tags: [...(entry.tags ?? [])].sort(),
    reporter: String(entry.reporter ?? ''),
    reference_url: String(entry.referenceUrl ?? ''),
    date_added: entry.dateAdded ? new Date(entry.dateAdded).toISOString() : null
  });
  return createHash('sha256').update(payload).digest('hex');
}

/**
 * Parse URLhaus recent.csv text. Returns entries and line stats.
 */
export function parseUrlhausRecentCsv(text) {
  const lines = String(text || '').split(/\r?\n/);
  let fetched = 0;
  let skipped = 0;
  const entries = [];
  let headerSeen = false;

  for (const rawLine of lines) {
    const line = String(rawLine || '').trim();
    if (!line) continue;
    if (line.startsWith('#')) continue;

    if (!headerSeen && isUrlhausCsvHeaderLine(line)) {
      headerSeen = true;
      continue;
    }

    fetched += 1;
    const cols = splitCsvLine(line);
    const entry = mapUrlhausRow(cols);
    if (!entry) {
      skipped += 1;
      continue;
    }
    entries.push(entry);
  }

  entries.sort((a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`));

  return {
    entries,
    fetched,
    parsed: entries.length,
    skipped
  };
}

export async function resolveUrlhausAuthKey(client, envAuthKey = process.env.URLHAUS_AUTH_KEY) {
  const res = await client.query(
    `SELECT credentials FROM integration_feeds WHERE key = $1`,
    [URLHAUS_FEED_KEY]
  );
  const creds = res.rows[0]?.credentials;
  const fromDb = creds && typeof creds === 'object' ? String(creds.auth_key || '').trim() : '';
  if (fromDb) return fromDb;

  const fromEnv = String(envAuthKey || '').trim();
  if (fromEnv) return fromEnv;

  return null;
}

export function formatFeedCredentialsSummary(key, credentials) {
  if (key !== URLHAUS_FEED_KEY) return null;
  const authKey = credentials && typeof credentials === 'object' ? credentials.auth_key : null;
  const configured = Boolean(String(authKey || '').trim());
  return {
    auth_key_configured: configured,
    masked_auth_key: maskUrlhausAuthKey(authKey)
  };
}

export async function assertUrlhausMinFetchInterval(client, sourceName) {
  const res = await client.query(
    `SELECT updated_at FROM integration_source_state WHERE source_name = $1`,
    [sourceName]
  );
  const updatedAt = res.rows[0]?.updated_at;
  if (!updatedAt) return { ok: true };

  const elapsed = Date.now() - new Date(updatedAt).getTime();
  if (elapsed < MIN_FETCH_INTERVAL_MS) {
    return {
      ok: false,
      reason: 'min_interval',
      waitMs: MIN_FETCH_INTERVAL_MS - elapsed
    };
  }
  return { ok: true };
}

/** Trim observable for stable canonical IOC identity (URL path case preserved). */
export function normalizeUrlhausObservable(value) {
  return String(value ?? '').trim();
}

/** Stable sha256 over sorted unique type|observable keys (ignores CSV comments/order/metadata). */
export function buildUrlhausCanonicalIocHash(entries = []) {
  const keys = new Set();
  for (const entry of entries) {
    const observable = normalizeUrlhausObservable(entry?.observable);
    const type = String(entry?.observableType || 'url').trim() || 'url';
    if (!observable) continue;
    keys.add(`${type}|${observable}`);
  }
  const sorted = [...keys].sort((a, b) => a.localeCompare(b));
  return createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
}

export function hashUrlhausRawContent(text) {
  return createHash('sha256').update(String(text ?? '')).digest('hex');
}

/** @typedef {{ v?: number, etag?: string|null, last_modified?: string|null, raw_content_hash?: string|null, canonical_ioc_hash?: string|null, last_success_at?: string|null }} UrlhausCheckpoint */

/** @returns {UrlhausCheckpoint|null} */
export function parseUrlhausCheckpoint(lastCursor, contentHash = null) {
  if (lastCursor) {
    const raw = String(lastCursor).trim();
    if (raw.startsWith('{')) {
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') return parsed;
      } catch {
        // fall through
      }
    }
    if (raw.startsWith('hash:')) {
      return { v: 0, canonical_ioc_hash: raw.slice(5) };
    }
  }
  if (contentHash) {
    return { v: 0, canonical_ioc_hash: String(contentHash) };
  }
  return null;
}

/** @param {UrlhausCheckpoint} checkpoint */
export function serializeUrlhausCheckpoint(checkpoint) {
  return JSON.stringify({
    v: 1,
    etag: checkpoint.etag ?? null,
    last_modified: checkpoint.last_modified ?? null,
    raw_content_hash: checkpoint.raw_content_hash ?? null,
    canonical_ioc_hash: checkpoint.canonical_ioc_hash ?? null,
    last_success_at: checkpoint.last_success_at ?? new Date().toISOString()
  });
}

/**
 * Decide whether URLHaus export can skip DB import.
 * @param {{ checkpoint: UrlhausCheckpoint|null, statusCode: number, responseEtag?: string|null, responseLastModified?: string|null, canonicalIocHash?: string|null }} input
 */
export function evaluateUrlhausExportSkip(input) {
  const {
    checkpoint,
    statusCode,
    responseEtag = null,
    responseLastModified = null,
    canonicalIocHash = null
  } = input || {};

  if (Number(statusCode) === 304) {
    return { skip: true, reason: 'not_modified' };
  }
  if (checkpoint?.etag && responseEtag && checkpoint.etag === responseEtag) {
    return { skip: true, reason: 'etag_unchanged' };
  }
  if (checkpoint?.last_modified && responseLastModified && checkpoint.last_modified === responseLastModified) {
    return { skip: true, reason: 'last_modified_unchanged' };
  }
  if (checkpoint?.canonical_ioc_hash && canonicalIocHash && checkpoint.canonical_ioc_hash === canonicalIocHash) {
    return { skip: true, reason: 'canonical_unchanged' };
  }
  return { skip: false, reason: null };
}

/**
 * Fetch URLHaus export with optional conditional headers.
 * @param {string} authKey
 * @param {{ signal?: AbortSignal, checkpoint?: UrlhausCheckpoint|null, fetchImpl?: typeof fetch }} [options]
 */
export async function fetchUrlhausExport(authKey, options = {}) {
  const { signal, checkpoint = null, fetchImpl } = options;
  const url = buildUrlhausRecentCsvUrl(authKey);
  const headers = {};
  if (checkpoint?.etag) headers['If-None-Match'] = String(checkpoint.etag);
  if (checkpoint?.last_modified) headers['If-Modified-Since'] = String(checkpoint.last_modified);

  const fetchFn = fetchImpl || globalThis.fetch;
  const res = await fetchFn(url, { method: 'GET', headers, signal });
  const etag = res.headers?.get?.('etag') ?? null;
  const lastModified = res.headers?.get?.('last-modified') ?? null;

  if (res.status === 304) {
    return {
      status: 304,
      text: null,
      etag: etag || checkpoint?.etag || null,
      lastModified: lastModified || checkpoint?.last_modified || null,
      rawContentHash: checkpoint?.raw_content_hash || null
    };
  }

  if (!res.ok) {
    throw new Error(`URLhaus CSV export request failed: ${res.status}`);
  }

  const text = await res.text();
  return {
    status: res.status,
    text,
    etag,
    lastModified,
    rawContentHash: hashUrlhausRawContent(text)
  };
}

/** @param {import('pg').PoolClient} client @param {string} sourceName */
export async function loadUrlhausCheckpoint(client, sourceName) {
  const { rows } = await client.query(
    `SELECT s.content_hash, s.updated_at, c.last_cursor
     FROM integration_source_state s
     FULL OUTER JOIN integration_checkpoints c ON c.source_name = s.source_name
     WHERE COALESCE(s.source_name, c.source_name) = $1
     LIMIT 1`,
    [sourceName]
  );
  const row = rows[0];
  if (!row) return null;
  const parsed = parseUrlhausCheckpoint(row.last_cursor, row.content_hash);
  if (!parsed) return null;
  if (!parsed.last_success_at && row.updated_at) {
    parsed.last_success_at = row.updated_at instanceof Date
      ? row.updated_at.toISOString()
      : String(row.updated_at);
  }
  return parsed;
}

/**
 * @param {import('pg').PoolClient} client
 * @param {string} sourceName
 * @param {UrlhausCheckpoint} checkpoint
 * @param {{ entries?: Array<{ observable: string, observableType: string }>|null }} [opts]
 */
export async function saveUrlhausCheckpoint(client, sourceName, checkpoint, opts = {}) {
  const { entries = null } = opts;
  const payload = {
    ...checkpoint,
    last_success_at: new Date().toISOString()
  };
  const lastCursor = serializeUrlhausCheckpoint(payload);
  const canonical = payload.canonical_ioc_hash || null;

  await client.query(
    `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (source_name)
     DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
    [sourceName, lastCursor]
  );

  if (entries) {
    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash,
                     items_json = EXCLUDED.items_json,
                     updated_at = NOW()`,
      [
        sourceName,
        canonical,
        JSON.stringify(entries.map((e) => ({ observable: e.observable, observableType: e.observableType })))
      ]
    );
  } else {
    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, '[]'::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = COALESCE(EXCLUDED.content_hash, integration_source_state.content_hash),
                     updated_at = NOW()`,
      [sourceName, canonical]
    );
  }
}
