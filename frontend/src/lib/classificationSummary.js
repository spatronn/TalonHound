/**
 * Normalizes a threat_classifications array into a deduplicated, unknown-filtered list.
 * Each item is expected to be { value, label, ... } or a plain slug string.
 * Returns the visible entries in backend order; empty array means Unknown should be shown.
 *
 * @param {Array<{value: string, label?: string}|string>|null|undefined} classifications
 * @returns {Array<{value: string, label: string|null}>}
 */
export function normalizeVisibleClassifications(classifications) {
  const list = Array.isArray(classifications) ? classifications : [];
  const seen = new Set();
  const result = [];
  for (const item of list) {
    const value = (typeof item === 'string' ? item : item?.value) || '';
    if (!value || value.toLowerCase() === 'unknown') continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ value, label: (typeof item === 'object' && item !== null) ? (item.label ?? null) : null });
  }
  return result;
}
