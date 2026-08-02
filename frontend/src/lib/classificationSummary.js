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

/**
 * Analyst/manual classifications stored on the IOC (editable via threat-classifications PATCH).
 * @param {object|null|undefined} summary
 */
export function getAnalystThreatClassifications(summary) {
  return normalizeVisibleClassifications(summary?.threat_classifications);
}

/**
 * Feed-derived classifications that are not already present in the analyst set.
 * These come from feed_intelligence and are display-only in the edit modal.
 * @param {object|null|undefined} summary
 * @returns {Array<{value: string, label: string|null, origin: 'feed', source_name: string|null}>}
 */
export function getFeedOnlyThreatClassifications(summary) {
  const analystKeys = new Set(
    getAnalystThreatClassifications(summary).map((c) => String(c.value).toLowerCase())
  );
  const list = Array.isArray(summary?.feed_intelligence?.classifications)
    ? summary.feed_intelligence.classifications
    : [];
  const seen = new Set();
  const result = [];
  for (const item of list) {
    const value = String(item?.value || '').trim();
    if (!value || value.toLowerCase() === 'unknown') continue;
    const key = value.toLowerCase();
    if (analystKeys.has(key) || seen.has(key)) continue;
    seen.add(key);
    result.push({
      value,
      label: item?.label ?? null,
      origin: 'feed',
      source_name: item?.source_name ? String(item.source_name) : null,
      active: item?.active !== false
    });
  }
  return result;
}

/**
 * Card display set: analyst classifications first, then feed-only extras (same merge as before).
 * @param {object|null|undefined} summary
 */
export function getDisplayedThreatClassifications(summary) {
  return [
    ...getAnalystThreatClassifications(summary),
    ...getFeedOnlyThreatClassifications(summary)
  ];
}

/**
 * Editable modal draft slugs — analyst/manual only (stable classification value keys).
 * @param {object|null|undefined} summary
 * @returns {string[]}
 */
export function editableThreatClassificationSlugs(summary) {
  const fromMulti = getAnalystThreatClassifications(summary).map((c) => c.value);
  if (fromMulti.length) return fromMulti;
  if (Array.isArray(summary?.threat_classifications)) return [];
  const legacy = summary?.threat_classification || summary?.primary_threat_classification;
  if (legacy && String(legacy).toLowerCase() !== 'unknown') return [String(legacy)];
  return [];
}

/**
 * View-model for the edit-threat-classifications modal.
 * Feed-only entries are included as read-only so they are not silently omitted.
 * @param {object|null|undefined} summary
 */
export function buildThreatClassificationModalState(summary) {
  const editableSlugs = editableThreatClassificationSlugs(summary);
  const feedOnly = getFeedOnlyThreatClassifications(summary);
  return {
    editableSlugs,
    feedOnly,
    /** All classification values the user sees as "present" on open (editable + feed). */
    presentValues: [
      ...editableSlugs,
      ...feedOnly.map((c) => c.value)
    ]
  };
}

/**
 * Save payload for analyst classifications. Feed-only values are never included
 * (they remain sourced from feed_intelligence on the card).
 * @param {string[]} draftSlugs
 * @returns {{ classifications: string[], threat_classifications: string[] }}
 */
export function buildThreatClassificationSavePayload(draftSlugs) {
  const slugs = (Array.isArray(draftSlugs) ? draftSlugs : [])
    .map((s) => String(s || '').trim())
    .filter((s) => s && s.toLowerCase() !== 'unknown');
  const unique = [...new Set(slugs)];
  return {
    classifications: unique,
    threat_classifications: unique
  };
}
