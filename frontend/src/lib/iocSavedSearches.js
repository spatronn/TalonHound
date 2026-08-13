/**
 * Helpers for IOC List saved-search UI.
 */

export function savedSearchCreatePayload({ name, query, description } = {}) {
  const n = String(name || '').trim();
  const q = String(query || '').trim();
  const errors = [];
  if (!n) errors.push('name');
  if (!q) errors.push('query');
  if (errors.length) return { ok: false, errors };
  const body = { name: n, query: q };
  const d = description == null ? '' : String(description).trim();
  if (d) body.description = d;
  return { ok: true, body };
}

export function savedSearchErrorMessage(payload, fallback = 'Failed to save search') {
  if (payload?.code === 'SAVED_SEARCH_NAME_DUPLICATE') {
    return 'A saved search with this name already exists.';
  }
  return payload?.message || payload?.error?.message || fallback;
}
