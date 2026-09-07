/**
 * Canonical IOC detail navigation target.
 *
 * IOC detail is addressed by the opaque `public_id` (a UUID-like slug), never by
 * the raw observable. Routing through the encoded public id means URL, hash,
 * domain and IP IOCs all resolve through the same route param — and, because the
 * id is short and path-safe, the rendered link is a real, right-clickable anchor
 * regardless of how gnarly the underlying IOC value is (URLs with / ? & = % #).
 *
 * Pure logic — no React, no DOM — so it can be unit tested with `node --test`
 * and shared by every place that links to an IOC detail page.
 */

export const IOC_DETAIL_BASE = '/ioc/details';

/** Normalise a public id to a trimmed string, or '' when absent. */
export function normalizeIocPublicId(publicId) {
  if (publicId == null) return '';
  return String(publicId).trim();
}

/**
 * Build the canonical IOC detail href for a public id.
 * Returns `null` when there is no usable public id, so callers can fall back to
 * rendering the IOC value as plain (non-navigating) text.
 * The id is percent-encoded so any path-significant characters stay route-safe.
 *
 * @param {unknown} publicId
 * @returns {string|null}
 */
export function iocDetailHref(publicId) {
  const id = normalizeIocPublicId(publicId);
  if (!id) return null;
  return `${IOC_DETAIL_BASE}/${encodeURIComponent(id)}`;
}
