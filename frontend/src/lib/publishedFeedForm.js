// Pure form-state helpers for the Published Feed create/edit form.
//
// The form supports two mutually-exclusive content modes:
//   'basic' — IOC Types + Default Window + Threat Feeds (legacy Basic Filters)
//   'query' — an Advanced Query using the IOC List DSL
// Safety Filters and Delivery apply in both modes. Toggling modes preserves the unsaved
// values of the inactive mode, and only the active mode is sent as effective on save.

export const FEED_FILTER_MODES = { BASIC: 'basic', QUERY: 'query' };

export const FEED_OUTPUT_FORMATS = { TXT: 'txt', JSON: 'json' };

/** Normalize any persisted/typed value to one of the two known modes ('basic' default). */
export function normalizeFilterMode(value) {
  return String(value || '').trim().toLowerCase() === FEED_FILTER_MODES.QUERY
    ? FEED_FILTER_MODES.QUERY
    : FEED_FILTER_MODES.BASIC;
}

/** Normalize any persisted/typed output format to 'txt' (default) or 'json'. */
export function normalizeOutputFormat(value) {
  return String(value || '').trim().toLowerCase() === FEED_OUTPUT_FORMATS.JSON
    ? FEED_OUTPUT_FORMATS.JSON
    : FEED_OUTPUT_FORMATS.TXT;
}

function splitCsv(s) {
  return String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
}

/** Blank form for the create flow. */
export function emptyFeedForm() {
  return {
    name: '',
    description: '',
    enabled: true,
    filter_mode: FEED_FILTER_MODES.BASIC,
    advanced_query: '',
    output_format: FEED_OUTPUT_FORMATS.TXT,
    include_source_metadata: true,
    include_classification: true,
    include_enrichment: false,
    ioc_types: ['ip'],
    exclude_false_positive: true,
    exclude_expired: true,
    include_feed_keys: [],
    include_tags: '',
    exclude_tags: '',
    time_window: 'all',
    max_items: '',
    refresh_interval_minutes: 15
  };
}

/**
 * Build the edit-form state from a persisted feed. Opens in the feed's persisted mode and
 * never converts one mode into the other; a feed with no filter_mode is treated as basic.
 */
export function feedToForm(feed) {
  if (!feed) return emptyFeedForm();
  const iocTypes = Array.isArray(feed.ioc_types) && feed.ioc_types.length
    ? feed.ioc_types
    : (feed.ioc_type ? [feed.ioc_type] : ['ip']);
  return {
    name: feed.name || '',
    description: feed.description || '',
    enabled: Boolean(feed.enabled),
    filter_mode: normalizeFilterMode(feed.filter_mode),
    advanced_query: feed.advanced_query || '',
    output_format: normalizeOutputFormat(feed.output_format || feed.format),
    include_source_metadata: feed.include_source_metadata !== false,
    include_classification: feed.include_classification !== false,
    include_enrichment: feed.include_enrichment === true,
    ioc_types: iocTypes,
    exclude_false_positive: feed.exclude_false_positive !== false,
    exclude_expired: feed.exclude_expired !== false,
    include_feed_keys: Array.isArray(feed.include_feed_keys) ? feed.include_feed_keys : [],
    include_tags: (feed.include_tags || []).join(', '),
    exclude_tags: (feed.exclude_tags || []).join(', '),
    time_window: feed.time_window || 'all',
    max_items: feed.max_items ?? '',
    refresh_interval_minutes: feed.refresh_interval_minutes || 15
  };
}

/**
 * Flip the content mode, preserving every other field (including the inactive mode's
 * unsaved values) so a Basic → Advanced → Basic round-trip loses nothing.
 */
export function toggleFilterMode(form) {
  const next = form.filter_mode === FEED_FILTER_MODES.QUERY
    ? FEED_FILTER_MODES.BASIC
    : FEED_FILTER_MODES.QUERY;
  return { ...form, filter_mode: next };
}

/** Client-side validation. Returns an error string, or null when the form is submittable. */
export function validateFeedForm(form) {
  if (!String(form.name || '').trim()) return 'Name is required';
  if (form.filter_mode === FEED_FILTER_MODES.QUERY) {
    if (!String(form.advanced_query || '').trim()) return 'Enter an Advanced Query';
    return null;
  }
  if (!Array.isArray(form.ioc_types) || !form.ioc_types.length) {
    return 'Select at least one IOC type';
  }
  return null;
}

/**
 * Build the API payload. Only the active mode's base-set fields are effective: query mode
 * sends advanced_query (Basic fields are preserved but inert); basic mode sends null query.
 */
export function buildFeedPayload(form) {
  const queryMode = form.filter_mode === FEED_FILTER_MODES.QUERY;
  const jsonFormat = normalizeOutputFormat(form.output_format) === FEED_OUTPUT_FORMATS.JSON;
  return {
    name: String(form.name || '').trim(),
    description: String(form.description || '').trim() || null,
    enabled: Boolean(form.enabled),
    filter_mode: queryMode ? FEED_FILTER_MODES.QUERY : FEED_FILTER_MODES.BASIC,
    advanced_query: queryMode ? String(form.advanced_query || '').trim() : null,
    ioc_types: form.ioc_types,
    output_format: jsonFormat ? FEED_OUTPUT_FORMATS.JSON : FEED_OUTPUT_FORMATS.TXT,
    // JSON include flags are always sent; the backend ignores them for TXT feeds.
    include_source_metadata: Boolean(form.include_source_metadata),
    include_classification: Boolean(form.include_classification),
    include_enrichment: Boolean(form.include_enrichment),
    exclude_false_positive: Boolean(form.exclude_false_positive),
    exclude_expired: Boolean(form.exclude_expired),
    include_feed_keys: form.include_feed_keys,
    include_tags: splitCsv(form.include_tags),
    exclude_tags: splitCsv(form.exclude_tags),
    time_window: form.time_window,
    max_items: form.max_items === '' ? null : Number(form.max_items),
    refresh_interval_minutes: Number(form.refresh_interval_minutes) || 15
  };
}
