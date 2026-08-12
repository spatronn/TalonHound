/**
 * Framework-agnostic helpers for the collapsed, searchable multi-select popover
 * (SearchableMultiSelect). Kept free of React so the selection/filter/summary
 * logic is unit-testable without mounting a component.
 */

/** Chips shown in the closed field before collapsing the rest into "+N more". */
export const MULTI_SELECT_MAX_CHIPS = 4;

/** Bounded popover list height (px); the list scrolls internally past this. */
export const MULTI_SELECT_LIST_MAX_HEIGHT = 260;

/**
 * Case-insensitive substring filter over option labels.
 * @template {{ value: unknown, label?: string }} T
 * @param {T[]} options
 * @param {string} query
 * @param {(option: T) => string} [getLabel]
 * @returns {T[]}
 */
export function filterMultiSelectOptions(options, query, getLabel) {
  const list = Array.isArray(options) ? options : [];
  const q = String(query || '').trim().toLowerCase();
  if (!q) return list;
  const labelOf = typeof getLabel === 'function' ? getLabel : (o) => o?.label;
  return list.filter((opt) => String(labelOf(opt) ?? '').toLowerCase().includes(q));
}

/**
 * Toggle a value in/out of the selection. Values are compared as strings and
 * the result is de-duplicated while preserving order.
 * @param {Array<string|number>} selected
 * @param {string|number} value
 * @returns {string[]}
 */
export function toggleMultiSelectValue(selected, value) {
  const list = Array.isArray(selected) ? selected.map(String) : [];
  const v = String(value);
  const set = new Set(list);
  if (set.has(v)) set.delete(v);
  else set.add(v);
  return [...set];
}

/**
 * Compact summary for the closed field: a limited number of chips plus an
 * overflow count for the remainder.
 * @param {Array<string|number>} selectedValues
 * @param {(value: string) => string} [getLabel]
 * @param {number} [maxChips]
 * @returns {{ chips: Array<{ value: string, label: string }>, overflowCount: number }}
 */
export function summarizeMultiSelectChips(selectedValues, getLabel, maxChips = MULTI_SELECT_MAX_CHIPS) {
  const list = Array.isArray(selectedValues) ? selectedValues.map(String) : [];
  const labelOf = typeof getLabel === 'function' ? getLabel : (v) => v;
  const max = Number.isFinite(maxChips) && maxChips > 0 ? maxChips : list.length;
  const chips = list.slice(0, max).map((value) => {
    const label = labelOf(value);
    return { value, label: String(label == null || label === '' ? value : label) };
  });
  const overflowCount = Math.max(0, list.length - chips.length);
  return { chips, overflowCount };
}
