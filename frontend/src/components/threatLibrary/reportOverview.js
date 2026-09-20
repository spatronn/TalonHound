/**
 * Pure helpers behind the redesigned Threat Library report page: filter
 * counts, overview metrics, compact metadata lists (empty values hidden),
 * grouped entities and source / artifact presentation.
 *
 * Every number here is derived from the loaded candidate rows with the same
 * predicates the review table filters use, so a metric card, a filter-tab
 * count and the rows the user sees after clicking that tab never disagree.
 */

import { REVIEW_FILTERS, matchReviewFilter } from './candidateReview.js';
import { resolveReportPhase, REPORT_PHASES, canShowReviewTable } from './reportPhase.js';
import { statusLabel } from './stages.js';
import { artifactTypeLabel, entityTypeLabel, humanizeEnum, languageLabel, sourceTypeLabel } from './reportDisplayLabels.js';

/**
 * Per-filter row counts for the indicator filter tabs.
 * @param {object[]} candidates
 * @returns {Record<string, number>} keyed by REVIEW_FILTERS id
 */
export function buildReviewFilterCounts(candidates) {
  const rows = Array.isArray(candidates) ? candidates : [];
  const counts = {};
  for (const f of REVIEW_FILTERS) {
    counts[f.id] = rows.reduce((n, c) => (matchReviewFilter(c, f.id) ? n + 1 : n), 0);
  }
  return counts;
}

/**
 * Overview metrics. `available` is false while the candidate set is still
 * moving (preparing / failed), in which case the numbers must not be shown as
 * report statistics.
 *
 * - candidates: rows in the analyst review set (same as the "Indicators" tab)
 * - new / existing / needsReview / contextOnly: same predicates as the filter tabs
 * - reviewed: review-set rows that are no longer pending (total - needsReview)
 */
export function buildOverviewMetrics(candidates, report) {
  const counts = buildReviewFilterCounts(candidates);
  const total = counts.indicators || 0;
  const needsReview = counts.needs_review || 0;
  const reviewed = Math.max(0, total - needsReview);
  return {
    available: Boolean(report) && canShowReviewTable(report),
    candidates: total,
    new: counts.new || 0,
    existing: counts.existing || 0,
    needsReview,
    contextOnly: counts.context_only || 0,
    all: counts.all || 0,
    reviewed,
    total,
    progressPct: total > 0 ? Math.round((reviewed / total) * 100) : 0
  };
}

function present(value) {
  if (value == null) return false;
  if (typeof value === 'string') return value.trim() !== '';
  if (typeof value === 'number') return Number.isFinite(value);
  return true;
}

function pushIf(list, label, value, extra = {}) {
  if (!present(value)) return;
  list.push({ key: label.toLowerCase().replace(/\s+/g, '_'), label, value: String(value), ...extra });
}

function formatBlocks(documentMeta) {
  const n = Number(documentMeta?.block_count);
  if (!Number.isFinite(n) || n <= 0) return null;
  return `${n} block${n === 1 ? '' : 's'}`;
}

function formatConfidence(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return `${Math.round(n * 100)}%`;
}

/**
 * Compact report metadata for the Overview tab. Only fields with a real value
 * are returned, so the caller never renders "Label: —".
 *
 * `finalized_at` is deliberately not listed: it is written at exactly the
 * transition the Status row already shows (Finalize → Ready), nothing reads
 * it, and it survives a Retry (stale "Finalized" next to "Needs review"). The
 * actor + time of finalization live in the audit log; the API keeps the field.
 *
 * @param {object} report
 * @param {{ documentMeta?: object|null, artifacts?: object[], entityCount?: number|null, indicatorCount?: { label: string, value: number|null }|null, formatDateTime?: (iso: string) => string }} [opts]
 * @returns {{ key: string, label: string, value: string, mono?: boolean }[]}
 */
export function buildReportDetails(report, opts = {}) {
  const items = [];
  if (!report) return items;
  const fmt = typeof opts.formatDateTime === 'function' ? opts.formatDateTime : (v) => String(v);
  pushIf(items, 'Source', report.source_name);
  pushIf(items, 'TLP', opts.tlpLabel);
  pushIf(items, 'Report type', report.report_type ? humanizeEnum(report.report_type) : null);
  pushIf(items, 'Language', report.language ? languageLabel(report.language) : null);
  pushIf(items, 'Confidence', formatConfidence(report.confidence));
  pushIf(items, 'Published', report.published_at ? fmt(report.published_at) : null);
  pushIf(items, 'Imported', report.created_at ? fmt(report.created_at) : null);
  pushIf(items, 'Document', formatBlocks(opts.documentMeta));
  const artifactCount = Array.isArray(opts.artifacts) ? opts.artifacts.length : 0;
  pushIf(items, 'Artifacts', artifactCount > 0 ? artifactCount : null);
  const entityCount = opts.entityCount ?? report.entity_count;
  pushIf(items, 'Entities', entityCount != null && Number(entityCount) > 0 ? Number(entityCount) : null);
  if (opts.indicatorCount && opts.indicatorCount.value != null) {
    pushIf(items, opts.indicatorCount.label, opts.indicatorCount.value);
  }
  pushIf(items, 'Status', statusLabel(report));
  return items;
}

const ENTITY_GROUP_ORDER = Object.freeze([
  'threat_actor',
  'malware',
  'campaign',
  'tool',
  'attack_pattern',
  'vulnerability',
  'infrastructure',
  'organization'
]);

/** True when an entity carries more than a name (confidence / evidence / description). */
export function entityHasDetail(entity) {
  if (!entity) return false;
  return present(entity.description) || present(entity.evidence_text) || (entity.confidence != null && entity.confidence !== '');
}

/**
 * Entities grouped by canonical type, in a fixed analyst-friendly order with
 * unknown types appended alphabetically. Each group keeps the canonical type
 * (for keys / tests) and a display label; entity rows are passed through
 * untouched so no canonical value is rewritten.
 *
 * @param {object[]} entities
 * @returns {{ type: string, label: string, items: object[] }[]}
 */
export function groupEntitiesByType(entities) {
  const rows = Array.isArray(entities) ? entities : [];
  const byType = new Map();
  for (const e of rows) {
    const type = String(e?.entity_type || 'other').toLowerCase();
    if (!byType.has(type)) byType.set(type, []);
    byType.get(type).push(e);
  }
  const known = ENTITY_GROUP_ORDER.filter((t) => byType.has(t));
  const unknown = [...byType.keys()].filter((t) => !ENTITY_GROUP_ORDER.includes(t)).sort();
  return [...known, ...unknown].map((type) => ({
    type,
    label: entityTypeLabel(type, { plural: true }),
    items: byType.get(type).slice().sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')))
  }));
}

/** Entity confidence as a percentage string, or null when absent. */
export function entityConfidenceLabel(entity) {
  return formatConfidence(entity?.confidence);
}

/**
 * Only http(s) source URLs may be offered as an explicit "Open source" action.
 * Anything else (javascript:, data:, file:, plain text) is displayed inert.
 */
export function isOpenableSourceUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return false;
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

export function formatByteSize(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/**
 * Source tab facts (excluding the editable Source URL, which has its own
 * control). Empty values are omitted.
 */
export function buildSourceDetails(report, { documentMeta = null, artifacts = [], formatDateTime } = {}) {
  const items = [];
  if (!report) return items;
  const fmt = typeof formatDateTime === 'function' ? formatDateTime : (v) => String(v);
  pushIf(items, 'Source type', report.source_type ? sourceTypeLabel(report.source_type) : null);
  pushIf(items, 'File name', report.source_file_name);
  pushIf(items, 'SHA-256', report.source_sha256, { mono: true });
  const lang = report.language || documentMeta?.language;
  pushIf(items, 'Language', lang ? languageLabel(lang) : null);
  pushIf(items, 'Published', report.published_at ? fmt(report.published_at) : null);
  pushIf(items, 'Imported', report.created_at ? fmt(report.created_at) : null);
  const blocks = formatBlocks(documentMeta);
  if (blocks) {
    const title = present(documentMeta?.title) && documentMeta.title !== report.title ? `${documentMeta.title} · ${blocks}` : blocks;
    pushIf(items, 'Document', title);
  }
  const count = Array.isArray(artifacts) ? artifacts.length : 0;
  pushIf(items, 'Artifacts', count > 0 ? count : null);
  return items;
}

/**
 * User-facing artifact row: type label, a display name and only the facts that
 * exist. Storage keys and other internal identifiers are never surfaced.
 */
export function describeArtifact(artifact, { formatDateTime } = {}) {
  const a = artifact || {};
  const fmt = typeof formatDateTime === 'function' ? formatDateTime : (v) => String(v);
  const facts = [];
  const size = formatByteSize(a.size_bytes);
  if (size) facts.push(size);
  if (present(a.mime_type)) facts.push(String(a.mime_type).split(';')[0].trim());
  if (a.fetched_at) facts.push(`fetched ${fmt(a.fetched_at)}`);
  else if (a.created_at) facts.push(fmt(a.created_at));
  if (a.requires_ocr === true) facts.push('OCR required');
  return {
    key: String(a.public_id || a.id || a.storage_key || a.artifact_type || ''),
    typeLabel: artifactTypeLabel(a.artifact_type),
    name: present(a.file_name) ? String(a.file_name) : null,
    sha256: present(a.sha256) ? String(a.sha256) : null,
    facts
  };
}

/** Short status line for the Overview when metrics are not yet available. */
export function describeOverviewPhaseNote(report) {
  const phase = resolveReportPhase(report);
  if (phase === REPORT_PHASES.PREPARING) return 'Indicator statistics will be available when analysis completes.';
  if (phase === REPORT_PHASES.FAILED) return 'Analysis failed before the indicator set was prepared. Retry analysis to produce review statistics.';
  return null;
}
