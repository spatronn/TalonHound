/**
 * Build the Known Hashes rows for File Information.
 *
 * Prefer artifact-backed known_hashes. When file_information carries additional
 * verified hash types (e.g. VirusTotal-promoted MD5) that are not yet on the
 * artifact, include them additively so the Intelligence tab does not hide a
 * provider-confirmed identity.
 *
 * @param {{ known_hashes?: Array<{ hash_type?: string, value?: string, is_primary?: boolean }>|null }|null|undefined} fileArtifact
 * @param {{ md5?: string|null, sha1?: string|null, sha256?: string|null }|null|undefined} fileInformation
 * @returns {Array<{ hash_type: string, value: string, is_primary: boolean }>}
 */
export function buildKnownHashDisplayRows(fileArtifact, fileInformation) {
  const known = Array.isArray(fileArtifact?.known_hashes) ? fileArtifact.known_hashes : [];
  const fi = fileInformation || {};
  const byType = new Map();

  const add = (hashType, value, isPrimary) => {
    const type = String(hashType || '').trim().toLowerCase();
    const normalized = String(value || '').trim().toLowerCase();
    if (!type || !normalized) return;
    if (!['md5', 'sha1', 'sha256'].includes(type)) return;
    const prev = byType.get(type);
    if (prev) {
      if (isPrimary && !prev.is_primary) prev.is_primary = true;
      return;
    }
    byType.set(type, { hash_type: type, value: normalized, is_primary: Boolean(isPrimary) });
  };

  for (const h of known) {
    add(h?.hash_type, h?.value, h?.is_primary);
  }
  add('md5', fi.md5, false);
  add('sha1', fi.sha1, false);
  add('sha256', fi.sha256, false);

  const rows = ['sha256', 'sha1', 'md5']
    .map((type) => byType.get(type))
    .filter(Boolean);

  if (rows.length && !rows.some((r) => r.is_primary)) {
    const preferred = rows.find((r) => r.hash_type === 'sha256')
      || rows.find((r) => r.hash_type === 'sha1')
      || rows[0];
    if (preferred) preferred.is_primary = true;
  }

  return rows;
}
