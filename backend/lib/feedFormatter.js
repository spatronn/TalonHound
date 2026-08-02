import crypto from 'crypto';

const HASH_TYPES = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

export const FEED_WINDOWS = ['1d', '3d', '7d', 'all'];
export const FEED_IOC_TYPES = ['ip', 'domain', 'url', 'hash'];
const FEED_IOC_TYPE_SET = new Set(FEED_IOC_TYPES);

/**
 * Normalize raw ioc type input (string, array, JSON string) into a sorted unique list.
 * @returns {{ ok: true, value: string[] } | { ok: false, error: string }}
 */
export function normalizeFeedIocTypes(raw) {
  let list;
  if (raw == null) {
    return { ok: false, error: 'ioc_types is required' };
  }
  if (Array.isArray(raw)) {
    list = raw;
  } else if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) return { ok: false, error: 'ioc_types is required' };
    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (!Array.isArray(parsed)) {
          return { ok: false, error: 'ioc_types must be a non-empty array' };
        }
        list = parsed;
      } catch {
        return { ok: false, error: 'ioc_types must be a non-empty array' };
      }
    } else if (trimmed.includes(',')) {
      list = trimmed.split(',').map((s) => s.trim()).filter(Boolean);
    } else {
      list = [trimmed];
    }
  } else {
    return { ok: false, error: 'ioc_types must be a non-empty array' };
  }

  if (!list.length) {
    return { ok: false, error: 'ioc_types must include at least one type' };
  }

  const seen = new Set();
  const out = [];
  for (const item of list) {
    const t = String(item || '').trim().toLowerCase();
    if (!t) continue;
    if (!FEED_IOC_TYPE_SET.has(t)) {
      return { ok: false, error: 'ioc_types must be ip, domain, url, or hash' };
    }
    if (seen.has(t)) {
      return { ok: false, error: 'ioc_types must not contain duplicates' };
    }
    seen.add(t);
    out.push(t);
  }

  if (!out.length) {
    return { ok: false, error: 'ioc_types must include at least one type' };
  }

  out.sort((a, b) => FEED_IOC_TYPES.indexOf(a) - FEED_IOC_TYPES.indexOf(b));
  return { ok: true, value: out };
}

/** Canonical snapshot/lookup key — single type stays "ip"; multi is "domain,url". */
export function feedIocTypesKey(types) {
  const norm = normalizeFeedIocTypes(types);
  if (!norm.ok) return '';
  return norm.value.join(',');
}

export function observableTypesForFeedIocType(iocType) {
  const t = String(iocType || '').toLowerCase();
  if (t === 'ip') return ['ip'];
  if (t === 'domain') return ['domain'];
  if (t === 'url') return ['url'];
  if (t === 'hash') return [...HASH_TYPES];
  return [];
}

/** Union of observable_type values for one or more feed IOC categories. */
export function observableTypesForFeedIocTypes(iocTypes) {
  const norm = normalizeFeedIocTypes(iocTypes);
  if (!norm.ok) return [];
  const out = new Set();
  for (const t of norm.value) {
    for (const ot of observableTypesForFeedIocType(t)) out.add(ot);
  }
  return [...out];
}

/** Map an ioc_items.observable_type to the feed category used for line normalization. */
export function feedCategoryForObservableType(observableType) {
  const t = String(observableType || '').toLowerCase();
  if (HASH_TYPES.has(t) || t === 'file_hash' || t === 'hash') return 'hash';
  if (t === 'ip' || t === 'domain' || t === 'url') return t;
  return null;
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

/**
 * @param {Array<object>} rows
 * @param {string|string[]} feedIocTypes - single category or multi-type list
 * @param {number|null} maxItems
 */
export function buildPlainTextFeed(rows, feedIocTypes, maxItems = null) {
  const sorted = sortFeedRows(rows);
  const seen = new Set();
  const lines = [];
  const cap = maxItems != null && Number.isFinite(Number(maxItems)) ? Number(maxItems) : null;
  const norm = normalizeFeedIocTypes(
    Array.isArray(feedIocTypes) || (typeof feedIocTypes === 'string' && feedIocTypes.includes(','))
      ? feedIocTypes
      : [feedIocTypes]
  );
  const types = norm.ok ? norm.value : [];
  const multi = types.length !== 1;

  for (const row of sorted) {
    const lineType = multi
      ? (feedCategoryForObservableType(row.observable_type) || types[0])
      : types[0];
    const line = normalizeFeedLine(row, lineType);
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

export function computeResponseEtag(contentHash, iocTypeKey, window, limit) {
  const base = `${contentHash || ''}|${iocTypeKey || ''}|${window || ''}|${limit ?? 'all'}`;
  return `"${crypto.createHash('sha256').update(base, 'utf8').digest('hex').slice(0, 32)}"`;
}
