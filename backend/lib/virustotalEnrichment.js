export const VT_PROVIDER = 'virustotal';

export const VT_NOT_INDEXED_MESSAGE =
  'VirusTotal has no report for this URL yet. The URL may not have been submitted or indexed.';

/** @param {number} httpStatus */
export function isVtResourceNotFound(httpStatus) {
  return Number(httpStatus) === 404;
}

export function buildVtNotIndexedResponse(overrides = {}) {
  return {
    status: 'not_found',
    provider: VT_PROVIDER,
    message: VT_NOT_INDEXED_MESSAGE,
    is_error: false,
    ...overrides
  };
}

/**
 * Map VT HTTP status to user-facing error message (fatal/integration errors only).
 * @param {number} httpStatus
 */
export function vtHttpErrorMessage(httpStatus) {
  const code = Number(httpStatus);
  if (code === 401 || code === 403) return 'Invalid VirusTotal API key.';
  if (code === 429) return 'VirusTotal rate limit reached. Try again later.';
  return 'VirusTotal enrichment failed.';
}

// Base of the VirusTotal human/browser report GUI. This is intentionally NOT the
// API base (`/api/v3`) — the API requires an API key and must never be used for
// browser navigation. See buildVirusTotalGuiUrl below.
export const VT_GUI_BASE = 'https://www.virustotal.com/gui';

/**
 * Unpadded URL-safe Base64, matching the identifier VirusTotal accepts for URL
 * objects when the canonical (SHA256) `data.id` is not available.
 * @param {string} value
 */
export function vtBase64UrlEncode(value) {
  return Buffer.from(String(value ?? ''), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

// Encode a single GUI path segment. VT URL ids and file hashes are already
// URL-safe (hex / base64url), so encodeURIComponent is a no-op on them and never
// corrupts them. IPv6 literals contain colons that are valid in a path segment
// and that VirusTotal expects verbatim, so we restore them after encoding.
function encodeVtSegment(value, { keepColons = false } = {}) {
  const encoded = encodeURIComponent(String(value));
  return keepColons ? encoded.replace(/%3A/gi, ':') : encoded;
}

/**
 * Build the VirusTotal WEB GUI report URL for an IOC. This is the single source
 * of truth for IOC-type -> GUI-route mapping. API collection names differ from
 * GUI routes (e.g. `/api/v3/ip_addresses/` vs `/gui/ip-address/`), so the mapping
 * is explicit rather than a string replacement on the API self-link.
 *
 * PRIMARY:  the VirusTotal object id (`data.id`) returned by the API — for URL
 *           and file IOCs this is VirusTotal's own canonical identifier.
 * FALLBACK: the normalized observable itself (domain/ip/hash), or an unpadded
 *           URL-safe Base64 of the original URL for URL IOCs.
 *
 * @param {{ type?: string, observable?: string, vtObjectId?: string|null }} args
 * @returns {string|null} GUI URL, or null when the type is unsupported / empty.
 */
export function buildVirusTotalGuiUrl({ type, observable, vtObjectId } = {}) {
  const t = String(type || '').toLowerCase();
  const id = vtObjectId == null ? '' : String(vtObjectId).trim();
  const obs = observable == null ? '' : String(observable).trim();

  switch (t) {
    case 'url': {
      // Prefer VT's canonical URL id; never re-derive by SHA256 ourselves —
      // VirusTotal owns URL canonicalization. Fall back to unpadded base64url.
      const urlId = id || (obs ? vtBase64UrlEncode(obs) : '');
      return urlId ? `${VT_GUI_BASE}/url/${encodeVtSegment(urlId)}` : null;
    }
    case 'domain': {
      const domain = id || obs;
      return domain ? `${VT_GUI_BASE}/domain/${encodeVtSegment(domain)}` : null;
    }
    case 'ip':
    case 'ipv6':
    case 'ip_address':
    case 'ip-address': {
      const ip = id || obs;
      return ip ? `${VT_GUI_BASE}/ip-address/${encodeVtSegment(ip, { keepColons: true })}` : null;
    }
    case 'hash':
    case 'file':
    case 'file_hash':
    case 'md5':
    case 'sha1':
    case 'sha256': {
      // VT file object ids are SHA256 even when queried by MD5/SHA1; prefer the
      // API-supplied canonical id, else the original supported hash (VT resolves it).
      const hash = id || obs;
      return hash ? `${VT_GUI_BASE}/file/${encodeVtSegment(hash)}` : null;
    }
    default:
      return null;
  }
}

/**
 * Return a copy of a normalized VT summary whose `permalink` is a GUI report URL.
 * Applied both when normalizing a fresh response and when serving a cached row,
 * so summaries stored before this fix self-heal on read.
 * @param {any} summary
 */
export function ensureVtGuiPermalink(summary) {
  if (!summary || typeof summary !== 'object') return summary;
  const gui = buildVirusTotalGuiUrl({
    type: summary.ioc_type,
    observable: summary.ioc_value,
    vtObjectId: summary.vt_object_id
  });
  // Only override when we could build a GUI URL; otherwise drop any stale API
  // self-link rather than exposing an `/api/v3/...` URL to the browser.
  return { ...summary, permalink: gui };
}
