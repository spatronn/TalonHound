import crypto from 'crypto';

const HASH_TYPES = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

export const FEED_WINDOWS = ['1d', '3d', '7d', 'all'];
export const FEED_IOC_TYPES = ['ip', 'domain', 'url', 'hash'];

export function observableTypesForFeedIocType(iocType) {
  const t = String(iocType || '').toLowerCase();
  if (t === 'ip') return ['ip'];
  if (t === 'domain') return ['domain'];
  if (t === 'url') return ['url'];
  if (t === 'hash') return [...HASH_TYPES];
  return [];
}

export function confidenceToScore(confidence) {
  const raw = String(confidence || '').trim().toLowerCase();
  if (raw === 'high') return 100;
  if (raw === 'medium') return 50;
  if (raw === 'low') return 25;
  const n = Number(raw);
  if (Number.isFinite(n)) return Math.max(0, Math.min(100, Math.floor(n)));
  return 0;
}

function parseIpv4(host) {
  const parts = String(host || '').trim().split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => {
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    return n;
  });
  if (nums.some((n) => n == null)) return null;
  return nums;
}

/** Exclude RFC1918, loopback, link-local, multicast, reserved. */
export function isPrivateOrReservedIp(value) {
  const raw = String(value || '').trim();
  if (!raw) return true;
  const host = raw.split('/')[0].trim();
  const nums = parseIpv4(host);
  if (!nums) return false;
  const [a, b] = nums;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

export function normalizeFeedLine(row, feedIocType) {
  const t = String(feedIocType || '').toLowerCase();
  const value = String(row?.observable || '').trim();
  if (!value) return null;
  if (t === 'ip' && isPrivateOrReservedIp(value)) return null;
  if (t === 'domain') return value.toLowerCase();
  if (t === 'url') return value;
  if (t === 'hash') return value.toLowerCase();
  return value;
}

export function sortFeedRows(rows) {
  return [...rows].sort((a, b) => {
    const ta = new Date(a.recency_ts || 0).getTime();
    const tb = new Date(b.recency_ts || 0).getTime();
    if (tb !== ta) return tb - ta;
    const ca = confidenceToScore(a.confidence);
    const cb = confidenceToScore(b.confidence);
    if (cb !== ca) return cb - ca;
    return String(a.observable || '').localeCompare(String(b.observable || ''));
  });
}

export function buildPlainTextFeed(rows, feedIocType, maxItems = null) {
  const sorted = sortFeedRows(rows);
  const seen = new Set();
  const lines = [];
  const cap = maxItems != null && Number.isFinite(Number(maxItems)) ? Number(maxItems) : null;

  for (const row of sorted) {
    const line = normalizeFeedLine(row, feedIocType);
    if (!line) continue;
    const key = line.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push(line);
    if (cap != null && lines.length >= cap) break;
  }

  const content = lines.length ? `${lines.join('\n')}\n` : '';
  const content_hash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  return { content, content_hash, item_count: lines.length, lines };
}

export function sliceFeedContent(content, limit) {
  if (limit == null || !Number.isFinite(limit) || limit <= 0) {
    return { content: content || '', item_count: countLines(content) };
  }
  const lines = String(content || '').split('\n').filter((l) => l.length > 0);
  const sliced = lines.slice(0, limit);
  const out = sliced.length ? `${sliced.join('\n')}\n` : '';
  return { content: out, item_count: sliced.length };
}

function countLines(content) {
  return String(content || '').split('\n').filter((l) => l.length > 0).length;
}

export function computeResponseEtag(contentHash, iocType, window, limit) {
  const base = `${contentHash || ''}|${iocType || ''}|${window || ''}|${limit ?? 'all'}`;
  return `"${crypto.createHash('sha256').update(base, 'utf8').digest('hex').slice(0, 32)}"`;
}
