/** @param {string|undefined|null} raw */
export function normalizeIocLifecycleStatus(raw) {
  const s = String(raw || 'active').trim().toLowerCase();
  if (s === 'expired') return 'Expired';
  if (s === 'suppressed') return 'Suppressed';
  if (s === 'disabled' || s === 'inactive') return 'Inactive';
  if (s === 'purged') return 'Purged';
  return 'Active';
}

/**
 * @param {{ source_names?: string[], historical_sources?: Array<{ feed_name?: string }>, source_name?: string }} item
 */
export function resolveIocDisplaySource(item) {
  const active = (item?.source_names || []).filter(Boolean);
  if (active.length) {
    return {
      label: active[0],
      extra: active.length > 1 ? active.length - 1 : 0,
      kind: 'active'
    };
  }
  const historical = (item?.historical_sources || [])
    .map((h) => h?.feed_name)
    .filter(Boolean);
  if (historical.length) {
    return {
      label: historical[0],
      extra: historical.length > 1 ? historical.length - 1 : 0,
      kind: 'historical'
    };
  }
  if (item?.source_name) {
    return { label: item.source_name, extra: 0, kind: 'row' };
  }
  return { label: 'No active source', extra: 0, kind: 'none' };
}

/** @param {Array<object>} items */
export function decorateIocListItems(items = []) {
  return (items || []).map((it) => {
    const src = resolveIocDisplaySource(it);
    return {
      ...it,
      lifecycle_status: normalizeIocLifecycleStatus(it.status),
      display_source: src.label,
      display_source_kind: src.kind,
      display_source_extra: src.extra
    };
  });
}

/**
 * Browse uses active scope; search spans all lifecycle statuses.
 * @param {boolean} hasSearch
 * @param {string|undefined|null} rawStatus
 */
export function resolveIocListStatusScope(hasSearch, rawStatus) {
  if (hasSearch) return 'all';
  return String(rawStatus || 'active').trim().toLowerCase() || 'active';
}
