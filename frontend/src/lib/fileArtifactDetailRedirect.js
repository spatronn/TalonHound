/**
 * Decide whether an IOC detail response should navigate to the canonical
 * file-artifact IOC (replace history; no loop when already on canonical).
 */

function hashRank(type) {
  const t = String(type || '').trim().toLowerCase();
  if (t === 'sha256') return 0;
  if (t === 'sha1') return 1;
  if (t === 'md5') return 2;
  return 9;
}

/**
 * @param {{
 *   requestedPublicId?: string|null,
 *   summary?: { observable_type?: string }|null,
 *   fileArtifact?: {
 *     is_legacy_alias?: boolean,
 *     canonical_ioc_public_id?: string|null,
 *     primary_hash?: { hash_type?: string }|null
 *   }|null
 * }} input
 * @returns {{ toPublicId: string, requestedType: string, primaryType: string, message: string }|null}
 */
export function resolveCanonicalDetailRedirect(input = {}) {
  const requestedPublicId = String(input.requestedPublicId || '').trim();
  const fa = input.fileArtifact;
  if (!fa || !fa.is_legacy_alias) return null;

  const toPublicId = String(fa.canonical_ioc_public_id || '').trim();
  if (!toPublicId || !requestedPublicId || toPublicId === requestedPublicId) return null;

  const requestedType = String(input.summary?.observable_type || '').trim().toLowerCase();
  const primaryType = String(fa.primary_hash?.hash_type || '').trim().toLowerCase();
  if (!primaryType) return null;

  // Only redirect when primary is a stronger exact hash than the requested alias.
  if (!(requestedType === 'md5' || requestedType === 'sha1')) return null;
  if (hashRank(primaryType) >= hashRank(requestedType)) return null;

  const primaryLabel = primaryType.toUpperCase();
  const requestedLabel = requestedType.toUpperCase();
  return {
    toPublicId,
    requestedType,
    primaryType,
    message: `Requested ${requestedLabel} is a known hash of this ${primaryLabel} file artifact.`
  };
}
