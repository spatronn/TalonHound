/**
 * Threat Library list row presentation: pure, node-tested descriptors the
 * list page renders. Every number here is a canonical API field — nothing is
 * recounted in the browser:
 *   entities   entity_count
 *   indicators total_unique_indicator_count (Original ∪ linked-source union),
 *              via the same indicatorListCell rules as before; preparing /
 *              failed reports show preliminary observables, never Indicators
 *   matched    matched_count (union Indicators with a matched IOC record)
 */

import { formatUserDateParts, formatUserDateTime } from '../../lib/formatDate.js';
import { sourceTypeLabel } from './reportDisplayLabels.js';
import { isOpenableSourceUrl } from './reportOverview.js';
import { REPORT_PHASES, indicatorListCellTitle, resolveReportPhase, resolveTotalUniqueIndicatorCount } from './reportPhase.js';
import { normalizeReportTags } from './reportTags.js';
import { statusLabel } from './stages.js';

/** Tag chips shown before the "+N" overflow chip. */
export const REPORT_LIST_VISIBLE_TAGS = 3;

const PHASE_TONES = Object.freeze({
  [REPORT_PHASES.FINALIZED]: 'ready',
  [REPORT_PHASES.REVIEW_READY]: 'review',
  [REPORT_PHASES.PREPARING]: 'processing',
  [REPORT_PHASES.FAILED]: 'failed'
});

/**
 * Status pill: the existing statusLabel text (never colour alone) plus a
 * tone from the report phase.
 * @returns {{ phase: string, tone: 'ready'|'review'|'processing'|'failed', label: string }}
 */
export function describeReportListStatus(report) {
  const phase = resolveReportPhase(report);
  // Title Case so the pill reads like the status tabs ("Needs Review").
  const raw = String(statusLabel(report) || '').trim();
  const label = raw ? raw.replace(/(^|[\s(])([a-z])/g, (m, pre, ch) => pre + ch.toUpperCase()) : 'Unknown';
  return { phase, tone: PHASE_TONES[phase], label };
}

const COMPACT = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
const PLAIN = new Intl.NumberFormat('en-US');

/**
 * Metric display text: exact with grouping below 10,000 ("3,218"), compact
 * above ("12.3K") so a huge report never widens its cell. The exact value is
 * always in the metric tooltip.
 */
export function formatReportMetric(value) {
  if (value == null || value === '') return '—';
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return '—';
  return n < 10000 ? PLAIN.format(n) : COMPACT.format(n);
}

function exact(n) {
  return PLAIN.format(Number(n) || 0);
}

/**
 * The three Intelligence metrics for one row.
 * @returns {{ key: 'entities'|'indicators'|'matched', value: string, label: string, title: string, muted: boolean }[]}
 */
export function describeReportIntelligence(report) {
  const phase = resolveReportPhase(report);
  const entities = Number(report?.entity_count ?? 0) || 0;
  const matched = Number(report?.matched_count ?? 0) || 0;

  let indicators;
  if (phase === REPORT_PHASES.PREPARING || phase === REPORT_PHASES.FAILED) {
    const raw = report?.raw_candidate_count ?? report?.indicator_count ?? null;
    const n = raw == null ? 0 : Number(raw) || 0;
    if (n > 0) {
      indicators = {
        value: formatReportMetric(n),
        label: 'Preliminary',
        title: `${exact(n)} preliminary observables — not yet a reviewed Indicator set`,
        muted: true
      };
    } else {
      indicators = {
        value: '—',
        label: phase === REPORT_PHASES.PREPARING ? 'Analyzing' : 'Indicators',
        title: phase === REPORT_PHASES.PREPARING ? 'Analysis in progress' : 'No Indicator set (analysis failed)',
        muted: true
      };
    }
  } else {
    const unique = resolveTotalUniqueIndicatorCount(report);
    const raw = report?.raw_candidate_count ?? report?.indicator_count ?? 0;
    const n = unique != null ? unique : Number(raw) || 0;
    indicators = {
      value: formatReportMetric(n),
      label: 'Indicators',
      title: indicatorListCellTitle(report) || `${exact(n)} unique Indicators`,
      muted: false
    };
  }

  return [
    { key: 'entities', value: formatReportMetric(entities), label: 'Entities', title: `${exact(entities)} entities identified in this report`, muted: false },
    { key: 'indicators', ...indicators },
    {
      key: 'matched',
      value: formatReportMetric(matched),
      label: 'Matched',
      title: `${exact(matched)} unique Indicators matched to an existing global IOC record`,
      muted: false
    }
  ];
}

/** Host of an http(s) URL (as written, port included); null when not openable. */
function urlHost(value) {
  if (!isOpenableSourceUrl(value)) return null;
  try {
    return new URL(String(value).trim()).host || null;
  } catch {
    return null;
  }
}

/**
 * Source cell: the stored publisher / source name, else the URL host, PDF
 * file name or bundle label. `title` always carries the full untruncated
 * value(s); `href` is set only for an http(s) source URL.
 * @returns {{ label: string, title: string, href: string|null, type: string, typeLabel: string }}
 */
export function describeReportSource(report) {
  const type = String(report?.source_type || '').toLowerCase();
  const typeLabel = type ? sourceTypeLabel(type) : 'Unknown';
  const url = String(report?.source_url || '').trim();
  const href = isOpenableSourceUrl(url) ? url : null;
  const name = String(report?.source_name || '').trim();
  let label;
  if (name) label = name;
  else if (type === 'url') label = urlHost(url) || url || 'URL';
  else if (type === 'pdf') label = String(report?.source_file_name || '').trim() || 'PDF';
  else if (type === 'thib') label = 'THIB bundle';
  else label = type || '—';
  const fileName = String(report?.source_file_name || '').trim();
  const details = [label];
  if (url && url !== label) details.push(url);
  if (fileName && fileName !== label) details.push(fileName);
  return { label, title: details.join('\n'), href, type, typeLabel };
}

/**
 * Report tags (already enabled-only and name-sorted by the API) split into
 * at most `max` visible chips and the "+N" overflow, whose tooltip lists the
 * rest. A narrow Report cell shows fewer chips (CSS container query), so one
 * overflow entry is produced per possible visible count (1..visible.length):
 * `shown` chips visible -> "+count" with the remaining names as `title`.
 * @returns {{
 *   visible: { id: number, name: string }[],
 *   hidden: { id: number, name: string }[],
 *   hiddenTitle: string,
 *   overflow: { shown: number, count: number, title: string }[]
 * }}
 */
export function splitReportListTags(tags, max = REPORT_LIST_VISIBLE_TAGS) {
  const all = normalizeReportTags(tags);
  const limit = Math.max(0, Math.floor(Number(max)) || 0);
  const visible = all.slice(0, limit);
  const hidden = all.slice(limit);
  const overflow = [];
  for (let shown = 1; shown <= visible.length; shown += 1) {
    const rest = all.slice(shown);
    if (rest.length) overflow.push({ shown, count: rest.length, title: rest.map((t) => t.name).join(', ') });
  }
  return { visible, hidden, hiddenTitle: hidden.map((t) => t.name).join(', '), overflow };
}

/**
 * Imported cell: the TalonHound import instant (created_at) in the system
 * timezone, split for a two-line cell; null when absent. Never the
 * publication date.
 * @returns {{ date: string, time: string, title: string }|null}
 */
export function describeReportImported(report, timeZone) {
  const parts = report?.created_at ? formatUserDateParts(report.created_at, timeZone) : null;
  if (!parts) return null;
  return { ...parts, title: `Imported into TalonHound ${formatUserDateTime(report.created_at, timeZone)}` };
}
