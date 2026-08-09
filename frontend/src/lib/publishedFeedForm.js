// Pure form-state helpers for the Published Feed create/edit form.
//
// The form supports two mutually-exclusive content modes:
//   'basic' — IOC Types + Default Window + Threat Feeds (legacy Basic Filters)
//   'query' — an Advanced Query using the IOC List DSL
// Safety Filters and Delivery apply in both modes. Toggling modes preserves the unsaved
// values of the inactive mode, and only the active mode is sent as effective on save.
//
// Output formats are multi-select: at least one of TXT / JSON must be enabled.

export const FEED_FILTER_MODES = { BASIC: 'basic', QUERY: 'query' };

export const FEED_OUTPUT_FORMATS = { TXT: 'txt', JSON: 'json' };

const FORMAT_ORDER = [FEED_OUTPUT_FORMATS.TXT, FEED_OUTPUT_FORMATS.JSON];

/** Normalize any persisted/typed value to one of the two known modes ('basic' default). */
export function normalizeFilterMode(value) {
  return String(value || '').trim().toLowerCase() === FEED_FILTER_MODES.QUERY
    ? FEED_FILTER_MODES.QUERY
    : FEED_FILTER_MODES.BASIC;
}

/** Canonical formats array: non-empty subset of ['txt','json'] in fixed order. */
export function normalizeFeedFormats(input) {
  let raw = input;
  if (raw == null) return [FEED_OUTPUT_FORMATS.TXT];
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) raw = parsed;
      else raw = [raw];
    } catch {
      raw = raw.split(',').map((s) => s.trim()).filter(Boolean);
    }
  }
  if (!Array.isArray(raw)) return [FEED_OUTPUT_FORMATS.TXT];
  const seen = new Set();
  for (const item of raw) {
    const v = String(item || '').trim().toLowerCase();
    if (v === 'txt' || v === 'json') seen.add(v);
  }
  if (!seen.size) return [FEED_OUTPUT_FORMATS.TXT];
  return FORMAT_ORDER.filter((f) => seen.has(f));
}

/** @deprecated Prefer normalizeFeedFormats — single format for legacy callers. */
export function normalizeOutputFormat(value) {
  return String(value || '').trim().toLowerCase() === FEED_OUTPUT_FORMATS.JSON
    ? FEED_OUTPUT_FORMATS.JSON
    : FEED_OUTPUT_FORMATS.TXT;
}

function splitCsv(s) {
  return String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
}

/** Blank form for the create flow. Default: TXT on, JSON off. */
export function emptyFeedForm() {
  return {
    name: '',
    description: '',
    enabled: true,
    filter_mode: FEED_FILTER_MODES.BASIC,
    advanced_query: '',
    formats: [FEED_OUTPUT_FORMATS.TXT],
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
  let formats;
  if (Array.isArray(feed.formats) && feed.formats.length) {
    formats = normalizeFeedFormats(feed.formats);
  } else if (feed.output_format || feed.format) {
    formats = normalizeFeedFormats([normalizeOutputFormat(feed.output_format || feed.format)]);
  } else {
    formats = [FEED_OUTPUT_FORMATS.TXT];
  }
  return {
    name: feed.name || '',
    description: feed.description || '',
    enabled: Boolean(feed.enabled),
    filter_mode: normalizeFilterMode(feed.filter_mode),
    advanced_query: feed.advanced_query || '',
    formats,
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

/** Toggle one output format checkbox. Returns updated form (formats may be empty — validate on save). */
export function toggleFeedFormat(form, format) {
  const v = String(format || '').trim().toLowerCase();
  if (v !== 'txt' && v !== 'json') return form;
  const current = new Set(normalizeFeedFormats(form.formats));
  if (current.has(v)) current.delete(v);
  else current.add(v);
  return { ...form, formats: FORMAT_ORDER.filter((f) => current.has(f)) };
}

export function feedHasJsonFormat(form) {
  return normalizeFeedFormats(form?.formats).includes(FEED_OUTPUT_FORMATS.JSON);
}

/** Client-side validation. Returns an error string, or null when the form is submittable. */
export function validateFeedForm(form) {
  if (!String(form.name || '').trim()) return 'Name is required';
  const formats = normalizeFeedFormats(form.formats);
  // Allow empty formats only if caller cleared both; reject before save.
  if (!Array.isArray(form.formats) || !form.formats.length) {
    return 'Select at least one output format (TXT or JSON)';
  }
  if (!formats.length) return 'Select at least one output format (TXT or JSON)';
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
  const formats = normalizeFeedFormats(form.formats);
  return {
    name: String(form.name || '').trim(),
    description: String(form.description || '').trim() || null,
    enabled: Boolean(form.enabled),
    filter_mode: queryMode ? FEED_FILTER_MODES.QUERY : FEED_FILTER_MODES.BASIC,
    advanced_query: queryMode ? String(form.advanced_query || '').trim() : null,
    ioc_types: form.ioc_types,
    formats,
    // JSON include flags are always sent; the backend ignores them when JSON is off.
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

/** Public pull URL helper for a feed slug + format. */
export function buildPublishedFeedPullUrl(baseUrl, slug, apiKey, format) {
  const u = new URL(`/api/published-feeds/${encodeURIComponent(slug)}`, baseUrl || 'http://localhost');
  if (apiKey) u.searchParams.set('api_key', apiKey);
  if (format) u.searchParams.set('format', format);
  return u.pathname + u.search;
}
