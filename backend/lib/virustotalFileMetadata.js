/**
 * Promote trusted VirusTotal file-enrichment metadata into an IOC's File
 * Information view — conservatively.
 *
 * VirusTotal is an ENRICHMENT PROVIDER, never the ingestion source of an IOC.
 * This module extracts deterministic technical file metadata from a persisted
 * VirusTotal response and fills ONLY empty File Information fields (strict
 * no-overwrite), so a value learned from AlienVault OTX / MalwareBazaar / an
 * analyst / another feed is never clobbered because VirusTotal happened to run
 * later.
 *
 * Semantic tiers (see task spec):
 *   A. Canonical / technical (md5, sha1, sha256, mime, file_type, imphash, tlsh,
 *      ssdeep) — deterministic properties/derived identifiers of the same binary.
 *      Promotable into EMPTY canonical fields only.
 *   B. Observed / provider (submission / observed file names) — what uploaders
 *      called the file. Surfaced as `observed_file_names` (an observation); never
 *      used to overwrite canonical `file_name`.
 *   C. Opinion / interpretation (verdicts, malware family, reputation, AV
 *      detection names) — NOT handled here. Classification/reputation semantics
 *      are unchanged.
 *
 * Pure — no DB, no HTTP, no React — unit-testable with `node --test`.
 */

import { normalizeExactHash, EXACT_HASH_TYPE_SET } from './fileArtifacts/hashNormalize.js';
import { FILE_METADATA_PLACEHOLDERS } from './iocFileInformation.js';
import { VT_PROVIDER } from './virustotalEnrichment.js';

/** Canonical (tier A) File Information fields VirusTotal may fill when empty. */
export const VT_CANONICAL_FILE_FIELDS = Object.freeze([
  'md5', 'sha1', 'sha256', 'mime', 'file_type', 'imphash', 'tlsh', 'ssdeep'
]);

const MAX_ATTR_LEN = 512; // sanity cap for free-text technical attributes
const MAX_NAMES = 10;
const MAX_NAME_LEN = 512;
const IMPHASH_RE = /^[a-f0-9]{32}$/;

/** True when a value is present and not a known "absent" placeholder ('-', 'Unknown', …). */
export function isMeaningfulFileValue(value) {
  if (value == null) return false;
  const s = String(value).trim();
  if (!s) return false;
  return !FILE_METADATA_PLACEHOLDERS.has(s);
}

/** Remove ASCII control characters (0x00-0x1F and 0x7F). */
function stripControlChars(str) {
  let out = '';
  for (const ch of str) {
    const code = ch.charCodeAt(0);
    if (code > 0x1f && code !== 0x7f) out += ch;
  }
  return out;
}

/**
 * Coerce a provider textual attribute to a safe, trimmed string, or null.
 * Rejects non-string/number, control characters, over-long, and placeholder values.
 * (Rendering escaping is handled by the frontend; this is defence-in-depth.)
 */
function sanitizeText(value, maxLen = MAX_ATTR_LEN) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const s = stripControlChars(String(value)).trim();
  if (!s || s.length > maxLen) return null;
  if (FILE_METADATA_PLACEHOLDERS.has(s)) return null;
  return s;
}

/** IMPHASH is an MD5-shaped 32-hex digest; validate to that shape or drop it. */
function sanitizeImphash(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const s = String(value).trim().toLowerCase();
  return IMPHASH_RE.test(s) ? s : null;
}

/** Filter/normalise an array of observed file names into a bounded, de-duped list. */
function sanitizeNames(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of value) {
    const s = sanitizeText(raw, MAX_NAME_LEN);
    if (!s) continue;
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
    if (out.length >= MAX_NAMES) break;
  }
  return out;
}

/**
 * Extract validated technical file metadata from a VirusTotal file response.
 * Accepts the raw API response (`{ data: { attributes } }`), a bare attributes
 * object, or a normalized-summary `file` block. Never throws.
 *
 * @param {object|null|undefined} rawResponse
 * @returns {{
 *   md5: string|null, sha1: string|null, sha256: string|null,
 *   mime: string|null, file_type: string|null,
 *   imphash: string|null, tlsh: string|null, ssdeep: string|null,
 *   names: string[], meaningful_name: string|null
 * }}
 */
export function extractVtFileMetadata(rawResponse) {
  const attr = (rawResponse && typeof rawResponse === 'object')
    ? (rawResponse.data?.attributes || rawResponse.attributes || rawResponse)
    : {};

  const out = {
    md5: null, sha1: null, sha256: null,
    mime: null, file_type: null,
    imphash: null, tlsh: null, ssdeep: null,
    names: [], meaningful_name: null
  };

  for (const type of ['md5', 'sha1', 'sha256']) {
    const n = normalizeExactHash(type, attr[type]);
    if (n) out[type] = n.normalized_hash_value;
  }

  // VT calls the human file type `type_description` (e.g. "Win32 EXE"); fall back
  // to the short `type_tag` (e.g. "peexe"). MIME, when VT supplies it.
  out.file_type = sanitizeText(attr.type_description) || sanitizeText(attr.type_tag);
  out.mime = sanitizeText(attr.mime_type);
  // IMPHASH lives under pe_info for PE files; some responses expose it top-level.
  out.imphash = sanitizeImphash(attr.pe_info?.imphash ?? attr.imphash);
  out.tlsh = sanitizeText(attr.tlsh);
  out.ssdeep = sanitizeText(attr.ssdeep);
  out.meaningful_name = sanitizeText(attr.meaningful_name, MAX_NAME_LEN);
  out.names = sanitizeNames(attr.names);

  return out;
}

/**
 * Verify VirusTotal's returned identity is consistent with the IOC being enriched
 * before any metadata is attached. For an exact-hash IOC, VT must echo the same
 * hash type with the same value. For a non-hash file IOC (e.g. ssdeep/tlsh type),
 * identity can't be cross-checked by hash, so require at least one exact hash to
 * confirm the report is about a real file object.
 */
function verifyVtIdentity(primaryType, primaryValue, vtFileMeta) {
  const type = String(primaryType || '').toLowerCase();
  if (!EXACT_HASH_TYPE_SET.has(type)) {
    const hasAnyHash = Boolean(vtFileMeta.md5 || vtFileMeta.sha1 || vtFileMeta.sha256);
    return hasAnyHash
      ? { ok: true, reason: 'no_hash_identity_available' }
      : { ok: false, reason: 'no_file_identity' };
  }
  const n = normalizeExactHash(type, primaryValue);
  if (!n) return { ok: false, reason: 'invalid_primary_value' };
  const vtSame = vtFileMeta[type];
  if (!vtSame) return { ok: false, reason: 'vt_missing_primary_hash_type' };
  if (vtSame !== n.normalized_hash_value) return { ok: false, reason: 'identity_mismatch' };
  return { ok: true, reason: 'matched' };
}

/** Merge observed names into an existing observation list without duplicates. */
function mergeObservedNames(existing, names, meaningfulName) {
  const seen = new Set();
  const out = [];
  const push = (raw) => {
    const s = sanitizeText(raw, MAX_NAME_LEN);
    if (!s) return;
    const key = s.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(s);
  };
  for (const n of Array.isArray(existing) ? existing : []) push(n);
  push(meaningfulName);
  for (const n of Array.isArray(names) ? names : []) push(n);
  return out.slice(0, MAX_NAMES);
}

/**
 * Additively promote trusted VirusTotal file metadata into a File Information
 * object. Returns a NEW object (does not mutate the input). Strict no-overwrite:
 * a field already holding a meaningful value is left untouched. Fields filled
 * from VirusTotal are recorded in a `provenance` map so the UI can attribute them.
 *
 * @param {object|null} fileInformation  built File Information (from buildFileInformation)
 * @param {object|null} vtFileMeta        VT `file` metadata (extractVtFileMetadata output or persisted summary.file)
 * @param {{ primaryType?: string, primaryValue?: string }} [options]
 * @returns {{ file_information: object|null, promoted: string[], identity_ok: boolean, identity_reason?: string }}
 */
export function promoteVtFileMetadataIntoFileInformation(fileInformation, vtFileMeta, options = {}) {
  if (!fileInformation || typeof fileInformation !== 'object') {
    return { file_information: fileInformation ?? null, promoted: [], identity_ok: false, identity_reason: 'no_file_information' };
  }
  if (!vtFileMeta || typeof vtFileMeta !== 'object') {
    return { file_information: fileInformation, promoted: [], identity_ok: false, identity_reason: 'no_vt_metadata' };
  }

  const identity = verifyVtIdentity(options.primaryType, options.primaryValue, vtFileMeta);
  if (!identity.ok) {
    return { file_information: fileInformation, promoted: [], identity_ok: false, identity_reason: identity.reason };
  }

  const next = { ...fileInformation };
  const provenance = { ...(fileInformation.provenance || {}) };
  const promoted = [];

  const fill = (field, value) => {
    if (!isMeaningfulFileValue(value)) return;      // nothing valid to promote
    if (isMeaningfulFileValue(next[field])) return; // strict no-overwrite
    next[field] = value;
    provenance[field] = VT_PROVIDER;
    promoted.push(field);
  };

  for (const field of VT_CANONICAL_FILE_FIELDS) {
    fill(field, vtFileMeta[field]);
  }

  // Observed names are an observation, never a canonical `file_name` overwrite.
  const observed = mergeObservedNames(next.observed_file_names, vtFileMeta.names, vtFileMeta.meaningful_name);
  if (observed.length) {
    next.observed_file_names = observed;
    if (!provenance.observed_file_names) provenance.observed_file_names = VT_PROVIDER;
  }

  if (Object.keys(provenance).length) next.provenance = provenance;

  return { file_information: next, promoted, identity_ok: true, identity_reason: identity.reason };
}
