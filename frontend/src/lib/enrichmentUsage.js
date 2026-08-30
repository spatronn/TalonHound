// Pure transforms for the Enrichment Usage page. No React / DOM here so the logic
// is unit-testable with node --test, matching the rest of src/lib.

export const DEFAULT_RANGE = 'last_30_days';

export const RANGE_OPTIONS = [
  { value: 'today', label: 'Today' },
  { value: 'last_7_days', label: 'Last 7 Days' },
  { value: 'last_30_days', label: 'Last 30 Days' },
  { value: 'custom', label: 'Custom' }
];

export const IOC_TYPE_OPTIONS = [
  { value: '', label: 'All Types' },
  { value: 'ip', label: 'IP' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'hash', label: 'Hash' }
];

// Trend-chart series. Colors are the existing TalonHound accent tokens (no new hues).
export const TREND_SERIES = [
  { key: 'request_count', label: 'Total Requests', color: '#38bdf8' },
  { key: 'external_call_count', label: 'External API Calls', color: '#f59e0b' },
  { key: 'cache_hit_count', label: 'Cache Hits', color: '#34d399' }
];

// --- formatting -------------------------------------------------------------

export function formatNumber(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return Number(value).toLocaleString('en-US');
}

export function formatPercent(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return `${Number(value)}%`;
}

export function formatMs(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  const ms = Number(value);
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${Math.round(ms)} ms`;
}

// "Today" in the canonical TalonHound System Timezone (never the browser's local
// tz, never UTC-by-default). Mirrors the backend, which anchors the range to the DB
// session CURRENT_DATE (also the System Timezone). Used for the custom date-picker
// seeds/bounds; the rendered buckets themselves come from the backend's system-tz range.
export function todayInTimeZone(timeZone, now = new Date()) {
  const build = (tz) => {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit'
    }).formatToParts(now);
    const pick = (type) => parts.find((p) => p.type === type)?.value || '';
    return `${pick('year')}-${pick('month')}-${pick('day')}`;
  };
  try {
    return build(timeZone || 'UTC');
  } catch {
    return build('UTC');
  }
}

/** 'YYYY-MM-DD' for N days before today in the given timezone (calendar arithmetic). */
export function daysAgoInTimeZone(timeZone, days, now = new Date()) {
  const d = new Date(`${todayInTimeZone(timeZone, now)}T00:00:00.000Z`);
  d.setUTCDate(d.getUTCDate() - Number(days || 0));
  return d.toISOString().slice(0, 10);
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** 'YYYY-MM-DD' -> 'Aug 12' (UTC, avoids timezone drift on the axis). */
export function formatDateLabel(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(iso || ''));
  if (!m) return String(iso || '');
  return `${MONTHS[Number(m[2]) - 1]} ${Number(m[3])}`;
}

// --- series / buckets -------------------------------------------------------

function addDaysIso(iso, days) {
  const d = new Date(`${iso}T00:00:00.000Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

/** Inclusive list of ISO dates from..to (bounded by the API's max range). */
export function buildDailyBuckets(from, to) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(from)) || !/^\d{4}-\d{2}-\d{2}$/.test(String(to))) return [];
  const out = [];
  let cur = from;
  // hard safety cap so a malformed range can never loop unboundedly
  for (let i = 0; i < 400 && cur <= to; i += 1) {
    out.push(cur);
    cur = addDaysIso(cur, 1);
  }
  return out;
}

const SERIES_KEYS = ['request_count', 'external_call_count', 'cache_hit_count', 'success_count', 'failure_count', 'rate_limit_count'];

/**
 * Fill the full date span with the API series, zero-filling missing days. Days before
 * telemetry collection started are flagged `collected:false` so the UI can show them
 * as "not collected" rather than a misleading real zero.
 */
export function mergeSeries(from, to, series = [], { collectionStartedOn = null } = {}) {
  const byDate = new Map((series || []).map((row) => [String(row.date), row]));
  return buildDailyBuckets(from, to).map((date) => {
    const row = byDate.get(date) || {};
    const filled = { date, collected: true };
    for (const key of SERIES_KEYS) filled[key] = Number(row[key] || 0);
    if (collectionStartedOn && date < collectionStartedOn) filled.collected = false;
    return filled;
  });
}

// --- chart geometry ---------------------------------------------------------

function niceMax(value) {
  if (value <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(value)));
  const norm = value / pow;
  let step;
  if (norm <= 1) step = 1;
  else if (norm <= 2) step = 2;
  else if (norm <= 5) step = 5;
  else step = 10;
  return step * pow;
}

/**
 * Compute SVG coordinates for the multi-series line chart. Pure geometry so it can be
 * verified without a DOM.
 * @param {Array} buckets   output of mergeSeries
 * @param {Array<{key,color,label}>} seriesDefs
 */
export function computeChartGeometry(buckets = [], seriesDefs = TREND_SERIES, {
  width = 720,
  height = 260,
  padding = { top: 16, right: 16, bottom: 28, left: 44 }
} = {}) {
  const innerW = Math.max(1, width - padding.left - padding.right);
  const innerH = Math.max(1, height - padding.top - padding.bottom);
  const n = buckets.length;

  let rawMax = 0;
  for (const b of buckets) {
    for (const s of seriesDefs) rawMax = Math.max(rawMax, Number(b[s.key] || 0));
  }
  const maxY = niceMax(rawMax);

  const xFor = (i) => (n <= 1 ? padding.left + innerW / 2 : padding.left + (i / (n - 1)) * innerW);
  const yFor = (v) => padding.top + innerH - (Number(v || 0) / maxY) * innerH;

  const lines = seriesDefs.map((s) => {
    const pts = buckets.map((b, i) => ({ x: xFor(i), y: yFor(b[s.key]) }));
    return {
      key: s.key,
      color: s.color,
      label: s.label,
      points: pts,
      polyline: pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')
    };
  });

  // ~5 y gridlines
  const yTickCount = 4;
  const yTicks = [];
  for (let i = 0; i <= yTickCount; i += 1) {
    const value = (maxY / yTickCount) * i;
    yTicks.push({ y: yFor(value), value: Math.round(value) });
  }

  // up to ~6 x labels, evenly spaced across buckets
  const xTicks = [];
  if (n > 0) {
    const maxLabels = Math.min(6, n);
    const stride = n === 1 ? 1 : (n - 1) / (maxLabels - 1 || 1);
    for (let i = 0; i < maxLabels; i += 1) {
      const idx = Math.round(i * stride);
      const b = buckets[Math.min(idx, n - 1)];
      xTicks.push({ x: xFor(Math.min(idx, n - 1)), label: formatDateLabel(b.date) });
    }
  }

  return { width, height, padding, innerW, innerH, maxY, lines, xTicks, yTicks, isEmpty: rawMax === 0 };
}

// --- summary cards ----------------------------------------------------------

/** The six required summary cards (+ two secondary), in display order. */
export function summaryCards(summary = {}) {
  return [
    { key: 'request_count', label: 'Total Requests', value: formatNumber(summary.request_count), tone: 'default' },
    { key: 'external_call_count', label: 'External API Calls', value: formatNumber(summary.external_call_count), tone: 'accent', hint: 'Real outbound provider calls (consumption)' },
    { key: 'cache_hit_count', label: 'Cache Hits', value: formatNumber(summary.cache_hit_count), tone: 'ok' },
    { key: 'success_rate', label: 'Success Rate', value: formatPercent(summary.success_rate), tone: 'ok' },
    { key: 'failure_count', label: 'Failed Requests', value: formatNumber(summary.failure_count), tone: summary.failure_count > 0 ? 'warn' : 'default' },
    { key: 'rate_limit_count', label: 'Rate Limit Events', value: formatNumber(summary.rate_limit_count), tone: summary.rate_limit_count > 0 ? 'warn' : 'default' },
    { key: 'cache_hit_rate', label: 'Cache Hit Rate', value: formatPercent(summary.cache_hit_rate), tone: 'default', secondary: true },
    { key: 'avg_external_response_time_ms', label: 'Avg Provider Latency', value: formatMs(summary.avg_external_response_time_ms), tone: 'default', secondary: true }
  ];
}

export function hasAnyUsage(summary = {}) {
  return Number(summary.request_count || 0) > 0;
}

// --- provider table ---------------------------------------------------------

const PROVIDER_SORT = {
  external_call_count: (r) => Number(r.external_call_count || 0),
  request_count: (r) => Number(r.request_count || 0),
  cache_hit_count: (r) => Number(r.cache_hit_count || 0),
  cache_hit_rate: (r) => Number(r.cache_hit_rate ?? -1),
  success_count: (r) => Number(r.success_count || 0),
  failure_count: (r) => Number(r.failure_count || 0),
  rate_limit_count: (r) => Number(r.rate_limit_count || 0),
  avg_external_response_time_ms: (r) => Number(r.avg_external_response_time_ms ?? -1),
  display_name: (r) => String(r.display_name || r.provider_key || '')
};

/** Sort provider rows by a column. Default: external calls desc (primary consumption). */
export function sortProviderRows(rows = [], sortKey = 'external_call_count', dir = 'desc') {
  const accessor = PROVIDER_SORT[sortKey] || PROVIDER_SORT.external_call_count;
  const sign = dir === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const av = accessor(a);
    const bv = accessor(b);
    if (typeof av === 'string' || typeof bv === 'string') {
      return String(av).localeCompare(String(bv)) * (dir === 'asc' ? 1 : -1);
    }
    if (av === bv) return String(a.display_name || '').localeCompare(String(b.display_name || ''));
    return (av - bv) * sign;
  });
}

// --- quota ------------------------------------------------------------------

/**
 * Present a provider quota. Never invents data: null quota => 'unavailable'.
 * @returns {{state:'available'|'unavailable', label:string, used?, limit?, pct?, barPct?, window?}}
 */
export function quotaView(quota) {
  if (!quota || !Number.isFinite(Number(quota.limit)) || Number(quota.limit) <= 0) {
    return { state: 'unavailable', label: 'Quota unavailable' };
  }
  const limit = Number(quota.limit);
  const used = Number.isFinite(Number(quota.used)) ? Number(quota.used) : null;
  const pct = used != null ? (quota.used_pct != null ? Number(quota.used_pct) : Math.round((used / limit) * 1000) / 10) : null;
  return {
    state: 'available',
    limit,
    used,
    pct,
    barPct: pct == null ? null : Math.max(0, Math.min(100, pct)),
    window: quota.window || null,
    label: used != null
      ? `${formatNumber(used)} / ${formatNumber(limit)}`
      : `Limit ${formatNumber(limit)}`
  };
}

// --- provider option list (for the filter dropdown) -------------------------

/** Build the provider filter options from the API's provider breakdown. */
export function providerFilterOptions(providers = []) {
  const opts = [{ value: '', label: 'All Providers' }];
  for (const p of providers) {
    opts.push({ value: p.provider_key, label: p.display_name || p.provider_key });
  }
  return opts;
}
