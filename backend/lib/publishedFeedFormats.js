// Published Feed multi-output format helpers (TXT / JSON checkbox model).

export const FEED_OUTPUT_FORMATS = { TXT: 'txt', JSON: 'json' };

const ORDER = [FEED_OUTPUT_FORMATS.TXT, FEED_OUTPUT_FORMATS.JSON];

/**
 * Canonicalize formats to a non-empty subset of ['txt','json'] in fixed order.
 * @returns {{ ok: true, value: string[] } | { ok: false, error: string }}
 */
export function normalizeFeedFormats(input) {
  let raw = input;
  if (raw == null) {
    return { ok: true, value: [FEED_OUTPUT_FORMATS.TXT] };
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) raw = parsed;
      else raw = [raw];
    } catch {
      raw = raw.split(',').map((s) => s.trim()).filter(Boolean);
    }
  }
  if (!Array.isArray(raw)) {
    return { ok: false, error: 'formats must be an array of txt and/or json' };
  }
  const seen = new Set();
  for (const item of raw) {
    const v = String(item || '').trim().toLowerCase();
    if (v !== 'txt' && v !== 'json') {
      return { ok: false, error: "formats may only include 'txt' and 'json'" };
    }
    seen.add(v);
  }
  if (!seen.size) {
    return { ok: false, error: 'formats must include at least one of txt, json' };
  }
  const value = ORDER.filter((f) => seen.has(f));
  return { ok: true, value };
}

/** Resolve formats from a feed row / config. Defaults to ['txt']. */
export function resolvePublishedFeedFormats(feed) {
  if (Array.isArray(feed?.formats) && feed.formats.length) {
    const n = normalizeFeedFormats(feed.formats);
    if (n.ok) return n.value;
  }
  // Legacy single format column (pre-migration / in-memory tests)
  if (feed?.format != null) {
    return String(feed.format).trim().toLowerCase() === 'json'
      ? [FEED_OUTPUT_FORMATS.JSON]
      : [FEED_OUTPUT_FORMATS.TXT];
  }
  return [FEED_OUTPUT_FORMATS.TXT];
}

/** True when JSON is among enabled formats. */
export function feedHasJsonFormat(feed) {
  return resolvePublishedFeedFormats(feed).includes(FEED_OUTPUT_FORMATS.JSON);
}

/** True when TXT is among enabled formats. */
export function feedHasTxtFormat(feed) {
  return resolvePublishedFeedFormats(feed).includes(FEED_OUTPUT_FORMATS.TXT);
}

/**
 * Primary format for Content-Type default / legacy single-format APIs:
 * prefer txt when both enabled; otherwise the sole format.
 */
export function resolvePublishedFeedFormat(feed) {
  const formats = resolvePublishedFeedFormats(feed);
  if (formats.includes(FEED_OUTPUT_FORMATS.TXT)) return FEED_OUTPUT_FORMATS.TXT;
  return formats[0] || FEED_OUTPUT_FORMATS.TXT;
}

export function isJsonFormatFeed(feed) {
  return feedHasJsonFormat(feed);
}

/**
 * Resolve which format to serve for a public request.
 * - omitted → TXT if enabled, else the only enabled format
 * - explicit → must be enabled
 * @returns {{ format: string } | { error: string, status: number }}
 */
export function resolveRequestedFeedFormat(feed, rawFormat) {
  const enabled = resolvePublishedFeedFormats(feed);
  if (rawFormat == null || rawFormat === '') {
    if (enabled.includes(FEED_OUTPUT_FORMATS.TXT)) {
      return { format: FEED_OUTPUT_FORMATS.TXT };
    }
    return { format: enabled[0] };
  }
  const v = String(rawFormat).trim().toLowerCase();
  if (v !== 'txt' && v !== 'json') {
    return { error: "format must be 'txt' or 'json'", status: 400 };
  }
  if (!enabled.includes(v)) {
    return { error: 'Requested format is not enabled for this feed', status: 404 };
  }
  return { format: v };
}

/**
 * Build formats list from create/update body.
 * Accepts `formats`, or legacy `output_format` / `format`.
 */
export function resolveFormatsInput(body, fallbackFormats = [FEED_OUTPUT_FORMATS.TXT]) {
  if (body?.formats !== undefined) {
    return normalizeFeedFormats(body.formats);
  }
  const raw = body?.output_format !== undefined ? body.output_format
    : (body?.format !== undefined ? body.format : undefined);
  if (raw === undefined) {
    return { ok: true, value: [...fallbackFormats] };
  }
  const v = String(raw).trim().toLowerCase();
  if (v !== 'txt' && v !== 'json') {
    return { ok: false, error: "output_format must be 'txt' or 'json'" };
  }
  return { ok: true, value: [v] };
}
