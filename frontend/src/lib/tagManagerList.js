export const TAG_MANAGER_PAGE_SIZE = 25;
export const TAG_MANAGER_SEARCH_DEBOUNCE_MS = 300;

/**
 * Tag Manager table columns. Category is intentionally omitted — a tag is just a
 * tag; the legacy `category` column is retained in the DB but no longer surfaced.
 */
export const TAG_MANAGER_TABLE_COLUMNS = ['Name', 'Source', 'Description', 'Active', 'Actions'];

/**
 * Blank Add Tag form. No category — see TAG_MANAGER_TABLE_COLUMNS note. No color:
 * tag chip colors are derived from source/origin (manual = orange, feed = blue),
 * never from a stored per-tag color.
 */
export const EMPTY_TAG_FORM = {
  name: '',
  description: '',
  is_active: true
};

/** Populate the Edit Tag form from an existing tag row (category/color ignored). */
export function buildTagFormFromTag(tag) {
  return {
    name: tag?.name || '',
    description: tag?.description || '',
    is_active: tag?.is_active !== false
  };
}

/**
 * Build the create/update payload for /admin/tags. Category and color are never
 * sent; the backend applies its own internal default for the legacy category
 * column, and chip colors are derived from source/origin rather than stored.
 */
export function buildTagSavePayload({ editingTag, form } = {}) {
  const f = form || {};
  if (editingTag?.id) {
    return {
      description: f.description,
      is_active: f.is_active
    };
  }
  return {
    name: f.name,
    description: f.description,
    is_active: f.is_active
  };
}

export function formatTagManagerShowingLabel({ page, pageSize = TAG_MANAGER_PAGE_SIZE, totalItems }) {
  const total = Math.max(0, Number(totalItems) || 0);
  if (total === 0) return 'Showing 0 of 0';
  const size = Math.max(1, Number(pageSize) || TAG_MANAGER_PAGE_SIZE);
  const p = Math.max(1, Number(page) || 1);
  const from = (p - 1) * size + 1;
  const to = Math.min(p * size, total);
  return `Showing ${from}–${to} of ${total}`;
}

export function buildTagManagerQueryParams({
  page = 1,
  search = '',
  showInactive = true,
  pageSize = TAG_MANAGER_PAGE_SIZE
} = {}) {
  const params = {
    page: Math.max(1, Number(page) || 1),
    page_size: pageSize,
    include_inactive: showInactive ? 'true' : 'false'
  };
  const q = String(search || '').trim();
  if (q) params.search = q;
  return params;
}

export function buildTagManagerUrlSearchParams({ page = 1, search = '', showInactive = true } = {}) {
  const next = new URLSearchParams();
  const q = String(search || '').trim();
  if (q) next.set('search', q);
  if (Number(page) > 1) next.set('page', String(page));
  if (!showInactive) next.set('show_inactive', 'false');
  return next;
}

export function parseTagManagerUrlState(searchParams) {
  const page = Math.max(1, Number(searchParams?.get?.('page') || 1) || 1);
  const search = String(searchParams?.get?.('search') || '');
  const showInactiveRaw = searchParams?.get?.('show_inactive');
  const showInactive = showInactiveRaw == null ? true : showInactiveRaw !== 'false';
  return { page, search, showInactive };
}

/** Clamp page when total shrinks after disable/filter. */
export function clampTagManagerPage(page, totalItems, pageSize = TAG_MANAGER_PAGE_SIZE) {
  const totalPages = Math.max(1, Math.ceil(Math.max(0, Number(totalItems) || 0) / pageSize) || 1);
  return Math.min(Math.max(1, Number(page) || 1), totalPages);
}
