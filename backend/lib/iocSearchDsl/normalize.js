import { DslError } from './errors.js';
import { normalizeExactHash, HASH_LENGTH_BY_TYPE } from '../fileArtifacts/hashNormalize.js';

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
// Exact file-hash values (md5/sha1/sha256)
// ---------------------------------------------------------------------------

// Validate + normalize an exact hash literal for a hash-kind field. Delegates to the
// single canonical hash normalizer (fileArtifacts/hashNormalize) so the DSL never grows
// a second, divergent notion of what a valid/normalized hash is. Trims surrounding
// whitespace and lowercases hex; rejects wrong-length or non-hex input with a DslError
// consistent with the other value validators — never silently degrades to a substring
// search. Returns the normalized lowercase hash on success.
export function assertHashValue(raw, { field, hashType, operator, position } = {}) {
  const normalized = normalizeExactHash(hashType, raw);
  if (!normalized) {
    const expectedLen = HASH_LENGTH_BY_TYPE[hashType];
    const detail = expectedLen
      ? `Expected ${expectedLen} hexadecimal characters.`
      : 'Expected a hexadecimal hash value.';
    throw new DslError(
      `Invalid ${hashType} value for "${field} ${operator}". ${detail}`,
      { code: 'invalid_hash_value', position, field }
    );
  }
  return normalized.normalized_hash_value;
}

// ---------------------------------------------------------------------------
// Non-identity file-artifact attributes (imphash / tlsh / ssdeep)
// ---------------------------------------------------------------------------

// Per-type validator + normalizer. Formats and case-folding are derived from the actual
// production data in file_artifact_non_identity_attrs, NOT assumed:
//   imphash - 32 hex, stored lowercase (0 uppercase observed). Case-insensitive hex, so we
//             lowercase; compared exact. `fold: 'lower'`.
//   tlsh    - optional 'T1' version prefix + 70 hex (72- or 70-char forms both occur), stored
//             in mixed case. TLSH is a hex digest, so comparison is case-insensitive; we
//             lowercase and the resolver compares LOWER(attr_value). `fold: 'lower'`.
//   ssdeep  - blocksize:chunk:double_chunk. The chunk parts are base64 (case-significant:
//             'A' != 'a'), and '+'/'/' are valid base64 chars — so ssdeep is compared
//             case-SENSITIVELY and never lowercased. `fold: 'none'`.
// Each `detail` names the expected shape so an invalid value gets an explicit DslError
// consistent with the other validators (never a silent downgrade to a different search).
const ATTR_VALUE_SPECS = Object.freeze({
  imphash: {
    fold: 'lower',
    re: /^[0-9a-f]{32}$/,
    detail: 'Expected a 32-character hexadecimal imphash.'
  },
  tlsh: {
    fold: 'lower',
    re: /^(t1)?[0-9a-f]{70}$/,
    detail: 'Expected a TLSH digest: 70 hex characters, optionally prefixed with "T1".'
  },
  ssdeep: {
    fold: 'none',
    re: /^[0-9]+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+$/,
    detail: 'Expected an ssdeep hash of the form blocksize:chunk:double_chunk.'
  }
});

export function assertAttrValue(raw, { field, attrType, operator, position } = {}) {
  const spec = ATTR_VALUE_SPECS[attrType];
  if (!spec) {
    throw new DslError(
      `Invalid value for "${field} ${operator}".`,
      { code: 'invalid_attr_value', position, field }
    );
  }
  const trimmed = String(raw ?? '').trim();
  const candidate = spec.fold === 'lower' ? trimmed.toLowerCase() : trimmed;
  if (!candidate || !spec.re.test(candidate)) {
    throw new DslError(
      `Invalid ${attrType} value for "${field} ${operator}". ${spec.detail}`,
      { code: 'invalid_attr_value', position, field }
    );
  }
  return candidate;
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
