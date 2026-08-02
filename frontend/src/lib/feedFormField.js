/**
 * Helpers for FeedFormField accessibility wiring (id / describedby).
 */

/**
 * Build aria-describedby from optional helper + error ids.
 * @param {{ helperId?: string, errorId?: string, existing?: string }} opts
 * @returns {string|undefined}
 */
export function mergeAriaDescribedBy({ helperId, errorId, existing } = {}) {
  const parts = [existing, helperId, errorId]
    .map((v) => String(v || '').trim())
    .filter(Boolean);
  return parts.length ? parts.join(' ') : undefined;
}

/**
 * Stable ids derived from a React useId() value.
 * @param {string} baseId
 */
export function feedFieldDomIds(baseId) {
  const id = String(baseId || 'field');
  return {
    fieldId: id,
    helperId: `${id}-helper`,
    errorId: `${id}-error`
  };
}
