/**
 * Presentation helpers for the Custom Threat Feeds page.
 *
 * Kept pure (no React, no DOM) so the summary/status transformations can be unit
 * tested with `node --test`. The page renders these into the same visual grammar
 * as the built-in Feeds dashboard.
 *
 * Custom Threat Feeds only expose the operational data their sync jobs actually
 * record: enabled/archived state, the most-recent run status + error, last-run /
 * last-success timestamps, and the schedule. There is NO authoritative health
 * model and NO computed next-run for custom feeds, so this module never fabricates
 * one — the page shows Schedule (not Next Run) and State/Last Result (not Health).
 */

/** Result statuses that represent a genuine failure/error worth flagging. */
const NEEDS_ATTENTION_STATUSES = new Set(['failed', 'partial_success']);
/** Result statuses that represent in-flight work. */
const RUNNING_STATUSES = new Set(['running', 'queued']);

function normStatus(feed) {
  return String(feed?.last_run_status || '').trim().toLowerCase();
}

/** A custom feed is "enabled" when its integration is active and not archived. */
export function isCustomFeedEnabled(feed) {
  return feed?.active !== false && !feed?.archived_at;
}

function truncate(text, max = 60) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  if (raw.length <= max) return raw;
  return `${raw.slice(0, max - 1)}…`;
}

function titleCase(value) {
  const s = String(value || '').trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

/**
 * Summary-card counts derived ONLY from data custom feeds actually expose.
 * @param {Array<object>} feeds
 * @returns {{ total: number, enabled: number, needs_attention: number, running_queued: number }}
 */
export function summarizeCustomThreatFeeds(feeds) {
  const list = Array.isArray(feeds) ? feeds : [];
  let enabled = 0;
  let needsAttention = 0;
  let runningQueued = 0;
  for (const feed of list) {
    const status = normStatus(feed);
    if (isCustomFeedEnabled(feed)) enabled += 1;
    if (NEEDS_ATTENTION_STATUSES.has(status)) needsAttention += 1;
    if (RUNNING_STATUSES.has(status)) runningQueued += 1;
  }
  return { total: list.length, enabled, needs_attention: needsAttention, running_queued: runningQueued };
}

/**
 * State badge model (Enabled / Disabled / Archived) — parallels the built-in feed
 * State column. Returns semantic parts; the page maps them to the shared badge style.
 * @param {object} feed
 * @returns {{ label: string, kind: 'enabled'|'disabled'|'archived' }}
 */
export function customFeedStatePresentation(feed) {
  if (feed?.archived_at) return { label: 'Archived', kind: 'archived' };
  return feed?.active !== false
    ? { label: 'Enabled', kind: 'enabled' }
    : { label: 'Disabled', kind: 'disabled' };
}

/**
 * Last Result presentation from the most-recent run status + error, mirroring the
 * built-in "Last Result" column. Custom-feed jobs do not expose new/updated
 * counts, so no metrics are fabricated — only a clear status and the error text
 * (truncated, full text in the tooltip).
 * @param {object} feed
 * @returns {{ primary: string, tone: 'success'|'warning'|'danger'|'info'|'neutral', title: string }}
 */
export function customFeedLastResultPresentation(feed) {
  const status = normStatus(feed);
  const error = String(feed?.last_error || '').trim();
  switch (status) {
    case 'success':
      return { primary: 'Completed', tone: 'success', title: 'Last sync completed successfully' };
    case 'partial_success':
      return { primary: 'Completed with errors', tone: 'warning', title: error || 'Completed with some errors' };
    case 'failed': {
      const short = truncate(error, 60);
      return { primary: short ? `Failed · ${short}` : 'Failed', tone: 'danger', title: error || 'Last sync failed' };
    }
    case 'running':
      return { primary: 'Running', tone: 'info', title: 'Sync in progress' };
    case 'queued':
      return { primary: 'Queued', tone: 'info', title: 'Sync queued' };
    case '':
      return { primary: 'Never run', tone: 'neutral', title: 'This feed has not run yet' };
    default:
      return { primary: titleCase(status), tone: 'neutral', title: error || status };
  }
}

/**
 * Compact secondary metadata shown under the feed name (host · format · IOC type ·
 * confidence · expiration), so lower-priority config stays visible without a wide
 * dense table. Missing values are omitted rather than shown as blanks.
 * @param {object} feed
 * @returns {string[]}
 */
export function customFeedMetadataParts(feed) {
  const parts = [];
  const host = String(feed?.url_host || feed?.url_display || '').trim();
  if (host) parts.push(host);
  const format = String(feed?.format || '').trim();
  if (format) parts.push(format);
  const iocMode = String(feed?.ioc_type_mode || '').trim();
  if (iocMode) parts.push(feed?.fixed_ioc_type ? `${iocMode} (${feed.fixed_ioc_type})` : iocMode);
  const confidence = String(feed?.default_confidence || '').trim();
  if (confidence) parts.push(titleCase(confidence));
  const expiration = String(feed?.expiration_summary || '').trim();
  if (expiration) parts.push(expiration);
  return parts;
}
