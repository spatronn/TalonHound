import { DslError } from './errors.js';

// ---------------------------------------------------------------------------
// Text values
// ---------------------------------------------------------------------------

// A value is "meaningless" if, after trimming, it is empty or consists solely of
// wildcard/placeholder characters. Broad-but-valid queries like `ioc contains "a"`
// are explicitly allowed; only genuinely empty/wildcard-only values are rejected.
export function isMeaninglessTextValue(raw) {
  const v = String(raw ?? '').trim();
  if (v.length === 0) return true;
  return /^[%_*\s]+$/.test(v);
}

export function assertUsableTextValue(raw, { field, operator, position } = {}) {
  if (isMeaninglessTextValue(raw)) {
    throw new DslError(
      `Value for "${field} ${operator}" must not be empty or wildcard-only`,
      { code: 'empty_value', position, field }
    );
  }
  return String(raw).trim();
}

// Escape LIKE/ILIKE metacharacters so a user value is matched literally. The builder
// pairs this with `ESCAPE '\'`.
export function likeEscape(value) {
  return String(value).replace(/([\\%_])/g, '\\$1');
}

// ---------------------------------------------------------------------------
// IOC value normalization
// ---------------------------------------------------------------------------

// Collapse an IPv6 literal to its canonical compressed lowercase form when the input
// is unambiguously IPv6. Non-IPv6 input is returned trimmed/lowercased unchanged so
// the caller can still compare case-insensitively. Best-effort: anything that does
// not parse cleanly is left as-is.
export function canonicalizeIpv6(value) {
  const raw = String(value).trim();
  if (!raw.includes(':')) return null;
  let head = raw;
  // Strip zone id / brackets / port-less forms are out of scope; keep it simple.
  if (head.startsWith('[') && head.endsWith(']')) head = head.slice(1, -1);
  const zoneIdx = head.indexOf('%');
  const zone = zoneIdx >= 0 ? head.slice(zoneIdx) : '';
  if (zoneIdx >= 0) head = head.slice(0, zoneIdx);

  const doubleColon = head.split('::');
  if (doubleColon.length > 2) return null;

  const expand = (part) => (part === '' ? [] : part.split(':'));
  let groups;
  if (doubleColon.length === 2) {
    const left = expand(doubleColon[0]);
    const right = expand(doubleColon[1]);
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    groups = expand(head);
  }
  if (groups.length !== 8) return null;

  const nums = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    nums.push(parseInt(g, 16));
  }

  // Compress the longest run of zero groups.
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i += 1) {
    if (nums[i] === 0) {
      if (curStart < 0) curStart = i;
      curLen += 1;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  const hex = nums.map((x) => x.toString(16));
  let out;
  if (bestLen >= 2) {
    const before = hex.slice(0, bestStart).join(':');
    const after = hex.slice(bestStart + bestLen).join(':');
    out = `${before}::${after}`;
  } else {
    out = hex.join(':');
  }
  return `${out}${zone.toLowerCase()}`;
}

// Normalize the comparison value for an `ioc` condition. Trims, and lowercases (host
// and URL comparisons are case-insensitive; ILIKE also ignores case). IPv6 literals
// are canonicalized so `2001:0db8::0001` matches stored `2001:db8::1`.
export function normalizeIocValue(raw) {
  const trimmed = String(raw ?? '').trim();
  const ipv6 = canonicalizeIpv6(trimmed);
  if (ipv6) return ipv6;
  return trimmed.toLowerCase();
}

// ---------------------------------------------------------------------------
// Date/time values
// ---------------------------------------------------------------------------

const RE_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const RE_DATETIME = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/;
const RE_ISO_TZ = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/;

function daysInMonth(year, month) {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function validParts(y, mo, d, h = 0, mi = 0, s = 0) {
  if (mo < 1 || mo > 12) return false;
  if (d < 1 || d > daysInMonth(y, mo)) return false;
  if (h < 0 || h > 23) return false;
  if (mi < 0 || mi > 59) return false;
  if (s < 0 || s > 59) return false;
  return true;
}

// Parse a DSL date literal. Returns:
//   { value: <string bound as a parameter>, hasTimezone: boolean, display: <canonical> }
// hasTimezone=false  -> builder casts `::timestamp AT TIME ZONE <configured tz>`
// hasTimezone=true   -> literal already carries an offset/Z; builder casts `::timestamptz`
export function parseDateLiteral(raw, { field, operator, position } = {}) {
  const v = String(raw ?? '').trim();
  const fail = () => {
    throw new DslError(`Invalid date format: ${raw}`, { code: 'invalid_date', position, field });
  };
  if (!v) fail();

  let m = RE_DATE.exec(v);
  if (m) {
    const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
    if (!validParts(y, mo, d)) fail();
    const canonical = `${m[1]}-${m[2]}-${m[3]} 00:00:00`;
    return { value: canonical, hasTimezone: false, display: `${m[1]}-${m[2]}-${m[3]}` };
  }

  m = RE_DATETIME.exec(v);
  if (m) {
    const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
    if (!validParts(y, mo, d, h, mi, s)) fail();
    const canonical = `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}`;
    return { value: canonical, hasTimezone: false, display: canonical };
  }

  m = RE_ISO_TZ.exec(v);
  if (m) {
    const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
    if (!validParts(y, mo, d, h, mi, s)) fail();
    const parsed = new Date(v);
    if (Number.isNaN(parsed.getTime())) fail();
    return { value: v, hasTimezone: true, display: v };
  }

  return fail();
}
