/**
 * Exact file-hash identity helpers for File Artifacts.
 * Identity types: md5, sha1, sha256. SHA512 is not supported in TalonHound.
 * Non-identity (imphash/tlsh/ssdeep) must never drive automatic merge.
 */

export const EXACT_HASH_TYPES = Object.freeze(['md5', 'sha1', 'sha256']);
export const EXACT_HASH_TYPE_SET = new Set(EXACT_HASH_TYPES);

/** Primary priority: SHA256 > SHA1 > MD5 */
export const PRIMARY_HASH_PRIORITY = Object.freeze(['sha256', 'sha1', 'md5']);

export const HASH_LENGTH_BY_TYPE = Object.freeze({
  md5: 32,
  sha1: 40,
  sha256: 64
});

export const NON_IDENTITY_ATTR_TYPES = Object.freeze(['imphash', 'tlsh', 'ssdeep']);
export const NON_IDENTITY_ATTR_TYPE_SET = new Set(NON_IDENTITY_ATTR_TYPES);

const HEX_RE = /^[a-f0-9]+$/;

/**
 * @param {unknown} value
 * @returns {string}
 */
export function normalizeHashValue(value) {
  return String(value || '').trim().toLowerCase();
}

/**
 * @param {unknown} type
 * @returns {string}
 */
export function normalizeHashType(type) {
  return String(type || '').trim().toLowerCase();
}

/**
 * Infer exact hash type from hex length. Returns null if not exact identity.
 * @param {string} normalizedValue
 * @returns {'md5'|'sha1'|'sha256'|null}
 */
export function inferExactHashType(normalizedValue) {
  const v = normalizeHashValue(normalizedValue);
  if (!v || !HEX_RE.test(v)) return null;
  if (v.length === 32) return 'md5';
  if (v.length === 40) return 'sha1';
  if (v.length === 64) return 'sha256';
  return null;
}

/**
 * Validate and normalize an exact hash. Returns null when invalid.
 * @param {unknown} hashType
 * @param {unknown} hashValue
 * @returns {{ hash_type: 'md5'|'sha1'|'sha256', normalized_hash_value: string } | null}
 */
export function normalizeExactHash(hashType, hashValue) {
  const type = normalizeHashType(hashType);
  const value = normalizeHashValue(hashValue);
  if (!EXACT_HASH_TYPE_SET.has(type)) return null;
  const expectedLen = HASH_LENGTH_BY_TYPE[type];
  if (!value || value.length !== expectedLen || !HEX_RE.test(value)) return null;
  return { hash_type: type, normalized_hash_value: value };
}

/**
 * True when type is an exact identity hash type used for file artifacts.
 * @param {unknown} type
 */
export function isExactFileHashIocType(type) {
  return EXACT_HASH_TYPE_SET.has(normalizeHashType(type));
}

/**
 * Pick primary hash from a list of { hash_type, ... } using SHA256 > SHA1 > MD5.
 * @param {Array<{ hash_type: string, id?: string, normalized_hash_value?: string }>} hashes
 * @returns {object|null}
 */
export function selectPrimaryHash(hashes) {
  const list = Array.isArray(hashes) ? hashes : [];
  for (const preferred of PRIMARY_HASH_PRIORITY) {
    const hit = list.find((h) => normalizeHashType(h?.hash_type) === preferred);
    if (hit) return hit;
  }
  return list[0] || null;
}

/**
 * Compare primary priority: lower number = higher priority. Unknown = 99.
 * @param {string} hashType
 */
export function primaryPriorityRank(hashType) {
  const idx = PRIMARY_HASH_PRIORITY.indexOf(normalizeHashType(hashType));
  return idx >= 0 ? idx : 99;
}

/**
 * Whether candidate type should replace current primary.
 * @param {string|null|undefined} currentType
 * @param {string} candidateType
 */
export function shouldPromotePrimary(currentType, candidateType) {
  if (!currentType) return EXACT_HASH_TYPE_SET.has(normalizeHashType(candidateType));
  return primaryPriorityRank(candidateType) < primaryPriorityRank(currentType);
}

/**
 * Parse pipe-separated note key=value pairs (MalwareBazaar / File Information style).
 * @param {unknown} note
 * @returns {Record<string, string>}
 */
export function parseNoteKeyValues(note) {
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

/**
 * Extract exact hashes from a note + optional primary observable.
 * Non-identity fields are ignored for merge evidence.
 * @param {{ observableType?: string, observable?: string, note?: string }} input
 * @returns {Array<{ hash_type: string, normalized_hash_value: string }>}
 */
export function extractExactHashesFromNote(input = {}) {
  const found = new Map();
  const add = (type, value) => {
    const n = normalizeExactHash(type, value);
    if (!n) return;
    found.set(`${n.hash_type}:${n.normalized_hash_value}`, n);
  };

  const primaryType = normalizeHashType(input.observableType);
  if (EXACT_HASH_TYPE_SET.has(primaryType)) {
    add(primaryType, input.observable);
  }

  const kv = parseNoteKeyValues(input.note);
  for (const type of EXACT_HASH_TYPES) {
    if (kv[type]) add(type, kv[type]);
  }
  return [...found.values()];
}

/**
 * Extract exact hashes from VirusTotal raw_response / attributes.
 * @param {object|null|undefined} rawResponse
 * @returns {Array<{ hash_type: string, normalized_hash_value: string }>}
 */
export function extractExactHashesFromVtRaw(rawResponse) {
  const attr = rawResponse?.data?.attributes || rawResponse?.attributes || {};
  const found = new Map();
  for (const type of EXACT_HASH_TYPES) {
    const n = normalizeExactHash(type, attr[type]);
    if (n) found.set(`${n.hash_type}:${n.normalized_hash_value}`, n);
  }
  return [...found.values()];
}

/**
 * Extract non-identity attrs from note (never merge evidence).
 * @param {unknown} note
 * @returns {Array<{ attr_type: string, attr_value: string }>}
 */
export function extractNonIdentityAttrsFromNote(note) {
  const kv = parseNoteKeyValues(note);
  const out = [];
  for (const type of NON_IDENTITY_ATTR_TYPES) {
    const value = String(kv[type] || '').trim();
    if (value) out.push({ attr_type: type, attr_value: value });
  }
  return out;
}

/**
 * True when a field name is a non-identity / weak signal (not auto-merge evidence).
 * @param {unknown} field
 */
export function isWeakMergeSignal(field) {
  const f = String(field || '').trim().toLowerCase();
  return [
    'file_name', 'filename', 'file_type', 'mime', 'mime_type', 'size', 'size_bytes',
    'malware_family', 'signature', 'family', 'tags', 'category',
    'imphash', 'tlsh', 'ssdeep', 'timestamp', 'first_seen', 'last_seen', 'note', 'url', 'reference'
  ].includes(f);
}
