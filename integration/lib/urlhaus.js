/**
 * URLhaus recent CSV export (abuse.ch) — auth, parsing, and safe logging.
 */

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
