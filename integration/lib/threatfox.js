/**
 * ThreatFox recent IOC API (abuse.ch) — auth, parsing, and safe logging.
 */

export const THREATFOX_FEED_KEY = 'threatfox-abusech';
export const THREATFOX_API_URL_DEFAULT = 'https://threatfox-api.abuse.ch/api/v1/';
export const THREATFOX_SOURCE_URL_MASKED = THREATFOX_API_URL_DEFAULT;
export const THREATFOX_AUTH_REQUIRED_MSG =
  'ThreatFox Auth-Key is missing. Configure it in integration settings or THREATFOX_AUTH_KEY env.';
export const THREATFOX_RECENT_DAYS_DEFAULT = 3;
export const THREATFOX_RECENT_DAYS_MIN = 1;
export const THREATFOX_RECENT_DAYS_MAX = 7;

const AUTH_KEY_HEADER_PATTERN = /\bAuth-Key\s*[:=]\s*\S+/gi;
const BEARER_PATTERN = /\bBearer\s+\S+/gi;

export function validateThreatFoxRecentDays(value, fallback = THREATFOX_RECENT_DAYS_DEFAULT) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const rounded = Math.floor(n);
  if (rounded < THREATFOX_RECENT_DAYS_MIN || rounded > THREATFOX_RECENT_DAYS_MAX) {
    return fallback;
  }
  return rounded;
}

export function normalizeThreatFoxApiUrl(value) {
  const raw = String(value || THREATFOX_API_URL_DEFAULT).trim();
  if (!raw) return THREATFOX_API_URL_DEFAULT;
  return raw.endsWith('/') ? raw : `${raw}/`;
}

export function buildThreatFoxRecentRequestBody(days) {
  return {
    query: 'get_iocs',
    days: validateThreatFoxRecentDays(days)
  };
}

export function maskThreatFoxAuthKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `************${s.slice(-4)}`;
}

export function sanitizeThreatFoxErrorMessage(message) {
  let out = String(message || '');
  out = out.replace(AUTH_KEY_HEADER_PATTERN, 'Auth-Key: ***');
  out = out.replace(BEARER_PATTERN, 'Bearer ***');
  out = out.replace(/("auth_key"\s*:\s*)"[^"]*"/gi, '$1"***"');
  return out;
}

function isIPv4(value) {
  const m = String(value || '').match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/);
  if (!m) return false;
  return m.slice(1).every((oct) => Number(oct) >= 0 && Number(oct) <= 255);
}

function isIPv6(value) {
  return String(value || '').includes(':');
}

function isCIDR(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(String(value || ''));
}

export function mapThreatFoxHashType(iocType) {
  const t = String(iocType || '').trim().toLowerCase();
  if (t === 'md5_hash' || t === 'md5') return 'md5';
  if (t === 'sha1_hash' || t === 'sha1') return 'sha1';
  if (t === 'sha256_hash' || t === 'sha256') return 'sha256';
  if (t === 'ssdeep') return 'ssdeep';
  if (t === 'imphash') return 'imphash';
  return null;
}

export function classifyThreatFoxObservable(iocValue, iocType) {
  const raw = String(iocValue || '').trim();
  const type = String(iocType || '').trim().toLowerCase();
  if (!raw) return null;

  if (type === 'ip:port') {
    const [host] = raw.split(':');
    if (!host) return null;
    if (isIPv4(host)) return { observable: host, observableType: 'ip' };
    if (isIPv6(host)) return { observable: host, observableType: 'ip6' };
    return { observable: host.toLowerCase(), observableType: 'domain' };
  }

  if (type === 'ip') {
    if (isIPv4(raw) || isCIDR(raw)) return { observable: raw, observableType: 'ip' };
    if (isIPv6(raw)) return { observable: raw, observableType: 'ip6' };
    return null;
  }

  const hashType = mapThreatFoxHashType(type);
  if (hashType) return { observable: raw.toLowerCase(), observableType: hashType };

  if (type === 'url') return { observable: raw, observableType: 'url' };
  if (type === 'domain' || type === 'hostname') return { observable: raw.toLowerCase(), observableType: 'domain' };

  return null;
}

export function mapThreatFoxConfidence(level) {
  const n = Number(level);
  if (Number.isNaN(n)) return 'medium';
  if (n >= 80) return 'high';
  if (n >= 50) return 'medium';
  return 'low';
}

export function parseThreatFoxUtcTimestamp(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return null;
  const normalized = raw.replace(' UTC', '').replace(' ', 'T');
  const dt = new Date(`${normalized}Z`);
  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

export function normalizeThreatFoxTags(raw) {
  if (Array.isArray(raw)) {
    return raw.map((t) => String(t || '').trim()).filter(Boolean);
  }
  const v = String(raw ?? '').trim();
  if (!v || v.toLowerCase() === 'none') return [];
  return v.split(',').map((t) => t.trim()).filter(Boolean);
}

export function mapThreatFoxApiRow(row) {
  if (!row || typeof row !== 'object') return null;
  const classified = classifyThreatFoxObservable(row.ioc, row.ioc_type);
  if (!classified) return null;

  const tags = normalizeThreatFoxTags(row.tags);
  const threatType = String(row.threat_type || '').trim() || 'threat-intel';

  return {
    ...classified,
    iocId: String(row.id ?? row.ioc_id ?? '').trim() || null,
    threatType,
    threatTypeDesc: String(row.threat_type_desc || '').trim() || null,
    malware: String(row.malware || '').trim() || null,
    malwarePrintable: String(row.malware_printable || '').trim() || null,
    malwareAlias: String(row.malware_alias || '').trim() || null,
    confidence: mapThreatFoxConfidence(row.confidence_level),
    firstSeen: parseThreatFoxUtcTimestamp(row.first_seen),
    lastSeen: parseThreatFoxUtcTimestamp(row.last_seen),
    reference: String(row.reference || '').trim() || null,
    tags,
    reporter: String(row.reporter || '').trim() || null,
    rawMetadata: row
  };
}

export function buildThreatFoxNote(entry) {
  const parts = [
    'Auto-imported from ThreatFox API',
    entry.iocId ? `ioc_id=${entry.iocId}` : null,
    entry.threatType ? `threat_type=${entry.threatType}` : null,
    entry.malwarePrintable ? `malware=${entry.malwarePrintable}` : (entry.malware ? `malware=${entry.malware}` : null),
    entry.malwareAlias ? `malware_alias=${entry.malwareAlias}` : null,
    entry.confidence ? `confidence=${entry.confidence}` : null,
    entry.reporter ? `reporter=${entry.reporter}` : null,
    entry.reference ? `reference=${entry.reference}` : null,
    entry.tags?.length ? `tags=${entry.tags.join(',')}` : null,
    entry.firstSeen ? `first_seen=${entry.firstSeen.toISOString()}` : null,
    entry.lastSeen ? `last_seen=${entry.lastSeen.toISOString()}` : null
  ].filter(Boolean);
  return parts.join(' | ');
}

export function parseThreatFoxApiResponse(json) {
  const payload = json && typeof json === 'object' ? json : {};
  const status = String(payload.query_status || '').trim().toLowerCase();

  if (status === 'no_result') {
    return { entries: [], fetched: 0, parsed: 0, skipped: 0, queryStatus: status };
  }

  if (status && status !== 'ok') {
    const message = String(payload.query_status_desc || payload.message || status).trim() || 'ThreatFox API query failed';
    const err = new Error(message);
    err.queryStatus = status;
    if (status.includes('auth') || status.includes('key')) {
      err.statusCode = 401;
    }
    throw err;
  }

  const rows = Array.isArray(payload.data) ? payload.data : [];
  let skipped = 0;
  const entries = [];

  for (const row of rows) {
    const entry = mapThreatFoxApiRow(row);
    if (!entry) {
      skipped += 1;
      continue;
    }
    entries.push(entry);
  }

  entries.sort((a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`));

  return {
    entries,
    fetched: rows.length,
    parsed: entries.length,
    skipped,
    queryStatus: status || 'ok'
  };
}

export async function fetchThreatFoxRecentIocs({
  authKey,
  apiUrl = THREATFOX_API_URL_DEFAULT,
  days = THREATFOX_RECENT_DAYS_DEFAULT,
  signal,
  fetchFn = fetch
}) {
  const key = String(authKey || '').trim();
  if (!key) throw new Error(THREATFOX_AUTH_REQUIRED_MSG);

  const url = normalizeThreatFoxApiUrl(apiUrl);
  const body = buildThreatFoxRecentRequestBody(days);

  const res = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Auth-Key': key,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(body),
    signal
  });

  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`ThreatFox API returned invalid JSON (HTTP ${res.status})`);
  }

  if (res.status === 401 || res.status === 403) {
    const err = new Error(`ThreatFox API authentication failed (HTTP ${res.status})`);
    err.statusCode = res.status;
    throw err;
  }

  if (res.status === 429) {
    const err = new Error('ThreatFox API rate limit exceeded (HTTP 429)');
    err.statusCode = 429;
    throw err;
  }

  if (!res.ok) {
    throw new Error(`ThreatFox API request failed (HTTP ${res.status})`);
  }

  return parseThreatFoxApiResponse(json);
}

export async function resolveThreatFoxAuthKey(client, envAuthKey = process.env.THREATFOX_AUTH_KEY) {
  const res = await client.query(
    `SELECT credentials FROM integration_feeds WHERE key = $1`,
    [THREATFOX_FEED_KEY]
  );
  const creds = res.rows[0]?.credentials;
  const fromDb = creds && typeof creds === 'object' ? String(creds.auth_key || '').trim() : '';
  if (fromDb) return fromDb;

  const fromEnv = String(envAuthKey || '').trim();
  if (fromEnv) return fromEnv;

  return null;
}

export async function resolveThreatFoxRecentDays(client, envDays = process.env.THREATFOX_RECENT_DAYS) {
  const res = await client.query(
    `SELECT credentials FROM integration_feeds WHERE key = $1`,
    [THREATFOX_FEED_KEY]
  );
  const creds = res.rows[0]?.credentials;
  const fromDb = creds && typeof creds === 'object' ? creds.recent_days : null;
  if (fromDb != null && fromDb !== '') {
    return validateThreatFoxRecentDays(fromDb);
  }
  return validateThreatFoxRecentDays(envDays);
}

export function formatFeedCredentialsSummary(key, credentials) {
  if (key !== THREATFOX_FEED_KEY) return null;
  const authKey = credentials && typeof credentials === 'object' ? credentials.auth_key : null;
  const configured = Boolean(String(authKey || '').trim());
  const recentDays = validateThreatFoxRecentDays(
    credentials?.recent_days,
    THREATFOX_RECENT_DAYS_DEFAULT
  );
  return {
    auth_key_configured: configured,
    masked_auth_key: maskThreatFoxAuthKey(authKey),
    recent_days: recentDays
  };
}
