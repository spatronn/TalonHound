export const EMPTY_ANALYST_REFERENCE_FORM = Object.freeze({
  title: '',
  url: '',
  reference_type: 'other',
  tlp: 'clear',
  confidence: 'unknown',
  assessment_impact: 'context_only',
  note: ''
});

export function toAnalystReferenceForm(item) {
  if (!item) {
    return { ...EMPTY_ANALYST_REFERENCE_FORM };
  }
  return {
    title: item.title || '',
    url: item.url || '',
    reference_type: item.reference_type || 'other',
    tlp: item.tlp || 'clear',
    confidence: item.confidence || 'unknown',
    assessment_impact: item.assessment_impact || 'context_only',
    note: item.note || ''
  };
}

export function buildAnalystReferencePayload(form) {
  const title = String(form?.title ?? '').trim();
  const urlRaw = String(form?.url ?? '').trim();
  const noteRaw = form?.note == null ? '' : String(form.note);
  return {
    title,
    url: urlRaw || null,
    reference_type: String(form?.reference_type || 'other').trim().toLowerCase(),
    tlp: String(form?.tlp || 'clear').trim().toLowerCase(),
    confidence: String(form?.confidence || 'unknown').trim().toLowerCase(),
    assessment_impact: String(form?.assessment_impact || 'context_only').trim().toLowerCase(),
    note: noteRaw.trim() || null
  };
}
