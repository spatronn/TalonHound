/** Pure helpers for Threat Classifications admin ordering UX. */

export const THREAT_CLASSIFICATION_MANAGER_COLUMNS = Object.freeze([
  'handle',
  'classification',
  'description',
  'status',
  'builtin',
  'actions'
]);

export function isUnknownThreatClassification(item) {
  return String(item?.slug || '').toLowerCase() === 'unknown';
}

export function isThreatClassificationRowLocked(item) {
  return isUnknownThreatClassification(item);
}

/**
 * Unknown first, then active by sort_order/name, then inactive by sort_order/name.
 * @template {{ slug?: string, active?: boolean, sort_order?: number, name?: string }} T
 * @param {T[]} items
 * @returns {T[]}
 */
export function sortThreatClassificationsForDisplay(items) {
  return [...(items || [])].sort((a, b) => {
    const aUnknown = isUnknownThreatClassification(a) ? 0 : 1;
    const bUnknown = isUnknownThreatClassification(b) ? 0 : 1;
    if (aUnknown !== bUnknown) return aUnknown - bUnknown;
    const aActive = a.active !== false ? 0 : 1;
    const bActive = b.active !== false ? 0 : 1;
    if (aActive !== bActive) return aActive - bActive;
    const so = (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0);
    if (so) return so;
    return String(a.name || a.slug || '').localeCompare(String(b.name || b.slug || ''));
  });
}

/**
 * Normalize a dragged order so Unknown stays first and inactive trails active.
 * Relative order within active/inactive groups is preserved from `orderedItems`.
 * @template {{ id: string, slug?: string, active?: boolean }} T
 * @param {T[]} orderedItems
 * @returns {T[]}
 */
export function normalizeThreatClassificationDragOrder(orderedItems) {
  const list = [...(orderedItems || [])];
  const unknown = list.find((item) => isUnknownThreatClassification(item));
  const rest = list.filter((item) => !isUnknownThreatClassification(item));
  const actives = rest.filter((item) => item.active !== false);
  const inactives = rest.filter((item) => item.active === false);
  return unknown ? [unknown, ...actives, ...inactives] : [...actives, ...inactives];
}

/**
 * Apply arrayMove-style reorder then normalize locked groups.
 * @template {{ id: string }} T
 * @param {T[]} items
 * @param {string} activeId
 * @param {string} overId
 * @returns {T[]}
 */
export function applyThreatClassificationReorder(items, activeId, overId) {
  const list = [...(items || [])];
  const from = list.findIndex((item) => String(item.id) === String(activeId));
  const to = list.findIndex((item) => String(item.id) === String(overId));
  if (from < 0 || to < 0 || from === to) return normalizeThreatClassificationDragOrder(list);
  const activeItem = list[from];
  if (isThreatClassificationRowLocked(activeItem) || isThreatClassificationRowLocked(list[to])) {
    return normalizeThreatClassificationDragOrder(list);
  }
  const next = [...list];
  const [moved] = next.splice(from, 1);
  next.splice(to, 0, moved);
  return normalizeThreatClassificationDragOrder(next);
}

export function buildThreatClassificationReorderPayload(items) {
  return {
    ordered_ids: (items || []).map((item) => String(item.id))
  };
}

/**
 * Merge visible (possibly filtered) drag result with hidden inactive rows.
 * @template {{ id: string, active?: boolean }} T
 * @param {T[]} allItems
 * @param {T[]} visibleOrdered
 * @param {boolean} showInactive
 * @returns {T[]}
 */
export function mergeVisibleThreatClassificationOrder(allItems, visibleOrdered, showInactive) {
  if (showInactive) return normalizeThreatClassificationDragOrder(visibleOrdered);
  const inactive = sortThreatClassificationsForDisplay(allItems).filter((item) => item.active === false);
  return normalizeThreatClassificationDragOrder([...visibleOrdered, ...inactive]);
}

/**
 * Options for classification pickers: keep API order, append inactive extras at the end.
 * @param {Array<{ value: string, label?: string }>} options
 * @param {Array<{ value: string, label?: string }>} inactiveOptions
 */
export function mergeThreatClassificationPickerOptions(options, inactiveOptions = []) {
  const allOptions = [...(options || [])];
  for (const inactive of inactiveOptions || []) {
    if (inactive?.value && !allOptions.some((o) => o.value === inactive.value)) {
      allOptions.push(inactive);
    }
  }
  return allOptions;
}
