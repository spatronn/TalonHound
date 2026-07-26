/**
 * Metadata merge policy for file artifacts.
 */

import { pickFileMetadataValue } from '../iocFileInformation.js';

/**
 * @param {object} canonical
 * @param {object} duplicate
 * @returns {object} fields to apply on canonical
 */
export function mergeArtifactMetadata(canonical = {}, duplicate = {}) {
  const firstSeenCandidates = [canonical.first_seen_at, duplicate.first_seen_at].filter(Boolean);
  const lastSeenCandidates = [canonical.last_seen_at, duplicate.last_seen_at].filter(Boolean);

  let first_seen_at = null;
  let last_seen_at = null;
  if (firstSeenCandidates.length) {
    first_seen_at = firstSeenCandidates.reduce((a, b) => (new Date(a) <= new Date(b) ? a : b));
  }
  if (lastSeenCandidates.length) {
    last_seen_at = lastSeenCandidates.reduce((a, b) => (new Date(a) >= new Date(b) ? a : b));
  }

  const sizeA = canonical.size_bytes != null ? Number(canonical.size_bytes) : null;
  const sizeB = duplicate.size_bytes != null ? Number(duplicate.size_bytes) : null;
  let size_bytes = sizeA ?? sizeB ?? null;
  const metadata = {
    ...(canonical.metadata && typeof canonical.metadata === 'object' ? canonical.metadata : {}),
    ...(duplicate.metadata && typeof duplicate.metadata === 'object' ? duplicate.metadata : {})
  };
  if (sizeA != null && sizeB != null && sizeA !== sizeB) {
    metadata.size_conflict = { canonical: sizeA, duplicate: sizeB };
    // Keep canonical size; do not blind overwrite
    size_bytes = sizeA;
  }

  return {
    file_name: pickFileMetadataValue(canonical.file_name, duplicate.file_name),
    file_type: pickFileMetadataValue(canonical.file_type, duplicate.file_type),
    mime_type: pickFileMetadataValue(canonical.mime_type, duplicate.mime_type),
    size_bytes,
    first_seen_at,
    last_seen_at,
    metadata
  };
}

/**
 * Deterministic canonical artifact selection among candidates.
 * 1) Prefer artifact that already has sha256 hash
 * 2) Older created_at
 * 3) More linked IOC evidence
 * 4) Lexicographically smaller UUID
 *
 * @param {Array<{
 *   id: string,
 *   created_at?: string|Date,
 *   has_sha256?: boolean,
 *   link_count?: number
 * }>} candidates
 */
export function selectCanonicalArtifact(candidates) {
  const list = Array.isArray(candidates) ? [...candidates] : [];
  if (!list.length) return null;
  list.sort((a, b) => {
    const shaA = a.has_sha256 ? 1 : 0;
    const shaB = b.has_sha256 ? 1 : 0;
    if (shaA !== shaB) return shaB - shaA;
    const tA = a.created_at ? new Date(a.created_at).getTime() : Number.POSITIVE_INFINITY;
    const tB = b.created_at ? new Date(b.created_at).getTime() : Number.POSITIVE_INFINITY;
    if (tA !== tB) return tA - tB;
    const cA = Number(a.link_count || 0);
    const cB = Number(b.link_count || 0);
    if (cA !== cB) return cB - cA;
    return String(a.id).localeCompare(String(b.id));
  });
  return list[0];
}
