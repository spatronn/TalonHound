/**
 * Row-level presentation for the indicator table and its detail drawer.
 *
 * Both read the same candidate row: the table shows `describeEvidencePreview`
 * (three short lines), the drawer shows `describeCandidateDetail` (every
 * fact the row carries). Neither mutates or re-derives review semantics —
 * assessment, role, review status, match and promotion outcome are the
 * canonical row fields rendered through display labels.
 */

import { describeCandidateProvenance, confidenceLabel, iocResultLabel } from './candidateReview.js';
import {
  assessmentLabel,
  candidateTypeLabel,
  matchCellLabel,
  reviewStatusLabel,
  roleLabel
} from './reportDisplayLabels.js';

export function candidateDisplayValue(candidate) {
  return String(candidate?.normalized_value || candidate?.original_value || '');
}

/**
 * Concise evidence cell: assertion (with derived / AI qualifiers), the first
 * section heading or table reference, and the occurrence count.
 * @returns {{ primary: string, secondary: string|null, tertiary: string, warning: string|null }}
 */
export function describeEvidencePreview(candidate) {
  const p = describeCandidateProvenance(candidate);
  const qualifiers = [];
  if (p.decision === 'AI') qualifiers.push('AI');
  if (!p.direct) qualifiers.push('derived');
  const primary = qualifiers.length ? `${p.assertion} · ${qualifiers.join(' · ')}` : p.assertion;
  const secondary = p.section || p.tableRow || null;
  const parts = [`${p.occurrences} occurrence${p.occurrences === 1 ? '' : 's'}`];
  if (p.pages) parts.push(p.pages);
  return {
    primary,
    secondary,
    tertiary: parts.join(' · '),
    warning: p.resolution ? p.resolution.label : null
  };
}

function occurrenceLabel(o, idx) {
  const bits = [];
  if (o.section_heading) bits.push(String(o.section_heading));
  else if (o.zone) bits.push(String(o.zone).replace(/_/g, ' '));
  if (o.page != null) bits.push(`p${o.page}`);
  if (o.form) bits.push(String(o.form));
  if (o.port != null) bits.push(`port ${o.port}`);
  return bits.length ? bits.join(' · ') : `Occurrence ${idx + 1}`;
}

/**
 * Everything the drawer renders for one row. Field values keep the canonical
 * row data in `raw` so the UI can show labels without losing the source.
 *
 * @returns {{
 *   value: string,
 *   typeLabel: string,
 *   fields: { key: string, label: string, value: string, raw?: unknown, tone?: string }[],
 *   evidence: { assertion: string, decision: string|null, description: string|null, resolution: { label: string, detail: string|null }|null, ports: string|null, urlHost: string|null, declaredType: string|null, direct: boolean, text: string|null },
 *   occurrences: { key: string, label: string, text: string|null }[],
 *   tableRows: { key: string, label: string, description: string|null }[]
 * }}
 */
export function describeCandidateDetail(candidate, { formatDateTime } = {}) {
  const c = candidate || {};
  const fmt = typeof formatDateTime === 'function' ? formatDateTime : (v) => String(v);
  const ev = c.evidence || {};
  const p = describeCandidateProvenance(c);
  const fields = [];
  fields.push({ key: 'assessment', label: 'Assessment', value: assessmentLabel(c.assessment) || '—', raw: c.assessment ?? null });
  fields.push({ key: 'role', label: 'Role', value: roleLabel(c.role) || '—', raw: c.role ?? null });
  fields.push({ key: 'confidence', label: 'Confidence', value: confidenceLabel(c), raw: c.confidence ?? null });
  fields.push({ key: 'review_status', label: 'Review state', value: reviewStatusLabel(c.review_status) || '—', raw: c.review_status ?? null });
  fields.push({ key: 'match', label: 'Existing match', value: matchCellLabel(c) || '—', raw: c.match_state ?? null });
  const result = iocResultLabel(c);
  fields.push({
    key: 'ioc_result',
    label: 'IOC result',
    value: c.promotion_detail && result !== '—' ? `${result} · ${c.promotion_detail}` : (result === '—' && c.promotion_detail ? c.promotion_detail : result),
    raw: c.promotion_outcome ?? null
  });
  if (c.promoted_at) fields.push({ key: 'promoted_at', label: 'Promoted', value: fmt(c.promoted_at), raw: c.promoted_at });
  if (c.original_value && c.normalized_value && c.original_value !== c.normalized_value) {
    fields.push({ key: 'original_value', label: 'As written', value: String(c.original_value), raw: c.original_value, mono: true });
  }

  const occurrences = Array.isArray(ev.occurrences) ? ev.occurrences : [];
  const tableRows = Array.isArray(ev.table_rows) ? ev.table_rows : [];
  return {
    value: candidateDisplayValue(c),
    typeLabel: candidateTypeLabel(c.candidate_type),
    fields,
    evidence: {
      assertion: p.assertion,
      decision: p.decision,
      description: p.description,
      resolution: p.resolution ? { label: p.resolution.label, detail: p.resolution.detail } : null,
      ports: p.ports,
      urlHost: p.urlHost,
      declaredType: p.declaredType,
      direct: p.direct,
      occurrenceCount: p.occurrences,
      text: c.evidence_text ? String(c.evidence_text) : null
    },
    occurrences: occurrences.map((o, idx) => ({
      key: `${o.block_id || 'b'}-${o.page ?? 'p'}-${idx}`,
      label: occurrenceLabel(o || {}, idx),
      text: o?.surrounding_text ? String(o.surrounding_text) : null
    })),
    tableRows: tableRows.map((r, idx) => ({
      key: `${r.table_id || 't'}-${r.row_index ?? idx}`,
      label: `Table ${r.table_id || '?'} · row ${Number.isInteger(r.row_index) ? r.row_index + 1 : '?'}${r.type_cell ? ` · ${r.type_cell}` : ''}`,
      description: r.description ? String(r.description) : null
    }))
  };
}

/**
 * Position of the open row inside the current filtered / searched result set
 * (all pages), for the drawer's Previous / Next controls. Ids compare loosely
 * so numeric ids from state and string ids from the API line up.
 *
 * @returns {{ index: number, total: number, prevId: unknown|null, nextId: unknown|null, page: number }}
 *   index is 1-based (0 when the row is not in the set); page is the 1-based
 *   page the row lives on for the given page size.
 */
export function describeDrawerPosition(rows, openId, pageSize = 50) {
  const list = Array.isArray(rows) ? rows : [];
  const size = Number(pageSize) > 0 ? Number(pageSize) : list.length || 1;
  const idx = openId == null ? -1 : list.findIndex((r) => String(r?.id) === String(openId));
  if (idx < 0) return { index: 0, total: list.length, prevId: null, nextId: null, page: 1 };
  return {
    index: idx + 1,
    total: list.length,
    prevId: idx > 0 ? list[idx - 1].id : null,
    nextId: idx < list.length - 1 ? list[idx + 1].id : null,
    page: Math.floor(idx / size) + 1
  };
}
