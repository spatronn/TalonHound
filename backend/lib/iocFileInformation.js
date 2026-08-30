/**
 * File Information builder for hash/file IOC detail responses.
 * Merges metadata from ioc_items notes (primary) and source evidence notes (enrichment).
 */

// Values treated as absent when merging file metadata across sources.
export const FILE_METADATA_PLACEHOLDERS = new Set([
  '-', 'unknown', 'Unknown', 'n/a', 'N/A', 'none', 'None', 'null', ''
]);

/**
 * Return the first value that is non-null and not a placeholder.
 * Falls back to the first non-null value (even if a placeholder) so we never
 * lose data entirely.
 */
export function pickFileMetadataValue(current, next) {
  if (current && !FILE_METADATA_PLACEHOLDERS.has(String(current))) return current;
  if (next && !FILE_METADATA_PLACEHOLDERS.has(String(next))) return next;
  return current || next || null;
}

function parseNoteKeyValues(note) {
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

const FILE_IOC_TYPES = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

/**
 * Build File Information from ioc_items rows and source evidence rows.
 *
 * ioc_items rows are read first (primary owner). Source evidence rows act as
 * enrichment fallback so that richer providers (e.g. MalwareBazaar) fill in
 * fields that were absent when a different source first imported the hash.
 * Placeholder values ('-', 'Unknown', 'n/a' etc.) in primary rows are
 * overwritten by real values from evidence rows.
 */
export function buildFileInformation(rows, observable, observableType, evidenceRows = []) {
  const type = String(observableType || '').toLowerCase();
  const looksLikeFileIoc = FILE_IOC_TYPES.has(type);

  let md5 = null;
  let sha1 = null;
  let sha256 = null;
  let ssdeep = null;
  let imphash = null;
  let tlsh = null;
  let fileName = null;
  let fileType = null;
  let mime = null;
  let reporter = null;
  let vtpercent = null;

  for (const row of [...rows, ...(evidenceRows || [])]) {
    const kv = parseNoteKeyValues(row.note);
    md5 = pickFileMetadataValue(md5, kv.md5);
    sha1 = pickFileMetadataValue(sha1, kv.sha1);
    sha256 = pickFileMetadataValue(sha256, kv.sha256);
    ssdeep = pickFileMetadataValue(ssdeep, kv.ssdeep);
    imphash = pickFileMetadataValue(imphash, kv.imphash);
    tlsh = pickFileMetadataValue(tlsh, kv.tlsh);
    fileName = pickFileMetadataValue(fileName, kv.file_name);
    fileType = pickFileMetadataValue(fileType, kv.file_type);
    mime = pickFileMetadataValue(mime, kv.mime);
    reporter = pickFileMetadataValue(reporter, kv.reporter);
    vtpercent = pickFileMetadataValue(vtpercent, kv.vtpercent);
  }

  if (type === 'sha256' && !sha256) sha256 = observable;
  if (type === 'sha1' && !sha1) sha1 = observable;
  if (type === 'md5' && !md5) md5 = observable;
  if (type === 'ssdeep' && !ssdeep) ssdeep = observable;

  const hasData = Boolean(
    md5 || sha1 || sha256 || ssdeep || imphash || tlsh || fileName || fileType || mime || reporter || vtpercent
  );

  if (!hasData && !looksLikeFileIoc) return null;

  return {
    md5,
    sha1,
    sha256,
    ssdeep,
    imphash,
    tlsh,
    file_name: fileName,
    file_type: fileType,
    mime,
    reporter,
    vtpercent
  };
}
