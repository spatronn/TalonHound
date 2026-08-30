export const REFERENCE_TYPES = Object.freeze([
  'social',
  'free_ti',
  'vendor_report',
  'sandbox',
  'blog',
  'internal_note',
  'other'
]);

export const TLP_VALUES = Object.freeze(['clear', 'green', 'amber', 'red']);

export const CONFIDENCE_VALUES = Object.freeze(['unknown', 'low', 'medium', 'high']);

export const ASSESSMENT_IMPACT_VALUES = Object.freeze([
  'supports_malicious',
  'supports_benign',
  'context_only',
  'needs_review'
]);

const TITLE_MAX = 200;
const SOURCE_NAME_MAX = 120;
const NOTE_MAX = 4000;

const URL_RE = /^https?:\/\/.+/i;

export function normalizeTlp(value) {
  const v = String(value || 'clear').trim().toLowerCase();
  if (v === 'white') return 'clear';
  return v;
}

export function validateAnalystIntelligencePayload(body, { partial = false } = {}) {
  const errors = [];
  const out = {};

  if (!partial || body.title !== undefined) {
    const title = String(body?.title ?? '').trim();
    if (!title) errors.push('title is required');
    else if (title.length > TITLE_MAX) errors.push(`title must be at most ${TITLE_MAX} characters`);
    else out.title = title;
  }

  if (!partial || body.url !== undefined) {
    const rawUrl = body?.url;
    if (rawUrl == null || rawUrl === '') {
      out.url = null;
    } else {
      const url = String(rawUrl).trim();
      if (!URL_RE.test(url)) errors.push('url must be a valid http or https URL');
      else out.url = url;
    }
  }

  if (!partial || body.source_name !== undefined) {
    const sourceName = body?.source_name == null || body?.source_name === ''
      ? null
      : String(body.source_name).trim();
    if (sourceName && sourceName.length > SOURCE_NAME_MAX) {
      errors.push(`source_name must be at most ${SOURCE_NAME_MAX} characters`);
    } else {
      out.source_name = sourceName;
    }
  }

  if (!partial || body.reference_type !== undefined) {
    const referenceType = String(body?.reference_type ?? 'other').trim().toLowerCase();
    if (!REFERENCE_TYPES.includes(referenceType)) errors.push('invalid reference_type');
    else out.reference_type = referenceType;
  }

  if (!partial || body.tlp !== undefined) {
    const tlp = normalizeTlp(body?.tlp ?? 'clear');
    if (!TLP_VALUES.includes(tlp)) errors.push('invalid tlp');
    else out.tlp = tlp;
  }

  if (!partial || body.confidence !== undefined) {
    const confidence = String(body?.confidence ?? 'unknown').trim().toLowerCase();
    if (!CONFIDENCE_VALUES.includes(confidence)) errors.push('invalid confidence');
    else out.confidence = confidence;
  }

  if (!partial || body.assessment_impact !== undefined) {
    const assessmentImpact = String(body?.assessment_impact ?? 'context_only').trim().toLowerCase();
    if (!ASSESSMENT_IMPACT_VALUES.includes(assessmentImpact)) errors.push('invalid assessment_impact');
    else out.assessment_impact = assessmentImpact;
  }

  if (!partial || body.note !== undefined) {
    const note = body?.note == null || body?.note === '' ? null : String(body.note);
    if (note && note.length > NOTE_MAX) errors.push(`note must be at most ${NOTE_MAX} characters`);
    else out.note = note;
  }

  return { ok: errors.length === 0, errors, value: out };
}

export function toPublicAnalystIntelligenceRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    ioc_id: Number(row.ioc_id),
    title: row.title,
    url: row.url || null,
    source_name: row.source_name || null,
    reference_type: row.reference_type,
    tlp: normalizeTlp(row.tlp),
    confidence: row.confidence,
    assessment_impact: row.assessment_impact,
    note: row.note || null,
    created_by: row.created_by || null,
    created_by_username: row.created_by_username || null,
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    updated_by: row.updated_by || null,
    updated_by_username: row.updated_by_username || null,
    updated_at: row.updated_at instanceof Date ? row.updated_at.toISOString() : (row.updated_at || null)
  };
}

export function buildAnalystIntelligenceSummary(rows) {
  const items = Array.isArray(rows) ? rows : [];
  const summary = {
    total_count: items.length,
    supports_malicious_count: 0,
    supports_benign_count: 0,
    needs_review_count: 0,
    context_only_count: 0
  };
  for (const row of items) {
    if (row.assessment_impact === 'supports_malicious') summary.supports_malicious_count += 1;
    else if (row.assessment_impact === 'supports_benign') summary.supports_benign_count += 1;
    else if (row.assessment_impact === 'needs_review') summary.needs_review_count += 1;
    else summary.context_only_count += 1;
  }
  return summary;
}

export function analystIntelligenceAuditSnapshot(row) {
  if (!row) return null;
  return {
    reference_id: row.id,
    ioc_id: Number(row.ioc_id),
    title: row.title,
    url: row.url || null,
    source_name: row.source_name || null,
    reference_type: row.reference_type,
    tlp: normalizeTlp(row.tlp),
    confidence: row.confidence,
    assessment_impact: row.assessment_impact
  };
}

export function diffAnalystIntelligenceFields(before, after) {
  const fields = ['title', 'url', 'source_name', 'reference_type', 'tlp', 'confidence', 'assessment_impact', 'note'];
  const changed = [];
  for (const f of fields) {
    const a = before?.[f] ?? null;
    const b = after?.[f] ?? null;
    if (String(a ?? '') !== String(b ?? '')) changed.push(f);
  }
  return changed;
}
