/**
 * THIB 1.0 integrity: deterministic content SHA-256 over canonical JSON
 * (excluding the integrity.hash field itself).
 */

import crypto from 'node:crypto';

/**
 * Stable JSON stringify: sorted object keys, arrays preserved.
 * @param {unknown} value
 */
export function canonicalJsonStringify(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortValue);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = sortValue(value[key]);
  }
  return out;
}

/**
 * Compute integrity hash for a THIB object.
 * Hash excludes the entire `integrity` object so alg/hash fields cannot recurse.
 * @param {object} bundle
 */
export function computeThibContentSha256(bundle) {
  const clone = JSON.parse(JSON.stringify(bundle));
  delete clone.integrity;
  const payload = canonicalJsonStringify(clone);
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * @param {object} bundle
 */
export function attachThibIntegrity(bundle) {
  const next = JSON.parse(JSON.stringify(bundle));
  delete next.integrity;
  const hash = computeThibContentSha256(next);
  next.integrity = {
    alg: 'sha256',
    content_sha256: hash
  };
  return next;
}

/**
 * @param {object} bundle
 */
export function verifyThibIntegrity(bundle) {
  const claimed = bundle?.integrity?.content_sha256 || bundle?.integrity?.hash;
  if (!claimed || typeof claimed !== 'string') {
    return { ok: false, error: 'Missing integrity.content_sha256' };
  }
  const actual = computeThibContentSha256(bundle);
  if (actual !== claimed.toLowerCase() && actual !== claimed) {
    return { ok: false, error: 'Integrity hash mismatch', expected: claimed, actual };
  }
  return { ok: true, content_sha256: actual };
}
