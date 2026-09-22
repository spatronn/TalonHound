/**
 * Threat Library report tags — pure helpers for the report header editor.
 *
 * Report tags are campaign/threat context drawn from the global tag catalog.
 * IOC records linked to the report inherit them as "Threat Context" tags at read
 * time; they never become direct IOC tags and never change IOC classification.
 */

export const REPORT_TAG_PICKER_LIMIT = 8;

/** Normalized, name-sorted, de-duplicated report tags from an API payload. */
export function normalizeReportTags(tags) {
  const seen = new Set();
  const out = [];
  for (const t of Array.isArray(tags) ? tags : []) {
    const id = Number(t?.id);
    const name = String(t?.name || '').trim();
    if (!Number.isFinite(id) || id <= 0 || !name || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name, type: t?.type || null });
  }
  return out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/** GET /tags params for the picker: active catalog tags not already on the report. */
export function reportTagPickerParams(currentTags, search) {
  const exclude = normalizeReportTags(currentTags).map((t) => t.id);
  const q = String(search || '').trim();
  return {
    active: true,
    limit: REPORT_TAG_PICKER_LIMIT,
    ...(q ? { q } : {}),
    ...(exclude.length ? { exclude_ids: exclude.join(',') } : {})
  };
}

/**
 * Keep report tags when a report payload omits them (e.g. retry / import
 * responses), but take them whenever the server sends them.
 */
export function mergeReportPayload(prev, next) {
  if (!next) return next;
  if (Array.isArray(next.tags) || !Array.isArray(prev?.tags)) return next;
  return { ...next, tags: prev.tags };
}

/** Tooltip copy explaining what a report tag does. */
export const REPORT_TAG_HELP =
  'Report tags describe the campaign/threat context. IOC records linked to this report show them as Threat Context tags; they are not added to the IOC directly and do not change IOC classification.';
