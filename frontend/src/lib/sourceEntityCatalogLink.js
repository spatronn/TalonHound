/**
 * IOC Details → Overview: link a source-reported Threat Actor / Malware Family
 * label to the local catalog (pure helpers; UI in
 * components/iocDetails/SourceEntityCatalogLinkDialog.jsx).
 *
 * Linking resolves the label's catalog identity; the association stays
 * source-reported (it is not analyst attribution). The backend is the
 * authority for candidates, duplicates and permissions.
 */

export const CATALOG_ENTITY_KIND = Object.freeze({
  THREAT_ACTOR: 'threat_actor',
  MALWARE_FAMILY: 'malware_family'
});

const KIND_TEXT = Object.freeze({
  threat_actor: { noun: 'threat actor', title: 'Threat Actor', catalog: 'Threat Actors' },
  malware_family: { noun: 'malware family', title: 'Malware Family', catalog: 'Malware Families' }
});

export function catalogKindText(kind) {
  return KIND_TEXT[kind] || { noun: 'entity', title: 'Entity', catalog: 'catalog' };
}

function currentSources(entity) {
  return (Array.isArray(entity?.sources) ? entity.sources : []).filter((s) => s?.assertion_status === 'current');
}

/**
 * Unlinked source-reported chip → { label } for the "+" action; otherwise null.
 * A chip with a catalog id is already resolved (rendered as a link instead).
 */
export function catalogLinkTarget(entity) {
  if (!entity || entity.id) return null;
  const sources = currentSources(entity);
  if (!sources.length) return null;
  const label = String(sources[0]?.source_label || entity.source_label_key || entity.name || '').trim();
  return label ? { label } : null;
}

/** Same normalization as the backend source_label_normalized key. */
export function catalogLabelKey(raw) {
  const s = String(raw ?? '').trim().replace(/\s+/g, ' ');
  return s ? s.toLowerCase() : null;
}

export function sourceProviders(entity) {
  return [...new Set(currentSources(entity).map((s) => s.source_name).filter(Boolean))];
}

export function chipLinkAriaLabel(kind, entity) {
  return `Link ${entity?.name || 'source-reported entity'} to a local ${catalogKindText(kind).noun}`;
}

/** "AlienVault OTX · Pulse: Name" (one line per stored evidence row). */
export function evidenceLine(evidence) {
  const parts = [evidence?.source_name || evidence?.feed_key || 'Source'];
  if (evidence?.evidence_ref_type === 'otx_pulse') {
    parts.push(`Pulse: ${evidence.evidence_title || evidence.evidence_ref_id}`);
  } else if (evidence?.evidence_title || evidence?.evidence_ref_id) {
    parts.push(evidence.evidence_title || evidence.evidence_ref_id);
  }
  return parts.join(' · ');
}

export function describeCandidateMatch(candidate) {
  switch (candidate?.match) {
    case 'name': return 'Exact name';
    case 'attack_id': return `ATT&CK ${candidate.match_detail || candidate.attack_id || ''}`.trim();
    case 'alias': return candidate.match_detail ? `Alias: ${candidate.match_detail}` : 'Alias';
    case 'slug': return 'Same slug';
    case 'similar': return candidate.match_detail ? `Similar (${candidate.match_detail})` : 'Similar spelling';
    default: return 'Search result';
  }
}

export function buildCatalogLinkRequest({ summary, kind, label, mode, entityId = null, create = null, confirmDistinct = false }) {
  const body = {
    observable_type: String(summary?.observable_type || '').trim(),
    entity_kind: kind,
    source_label: label,
    mode
  };
  if (mode === 'link') body.entity_id = entityId;
  if (mode === 'create') {
    body.create = {
      name: String(create?.name || '').trim(),
      aliases: String(create?.aliases || '')
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean),
      description: String(create?.description || '').trim() || null
    };
    if (confirmDistinct) body.confirm_distinct = true;
  }
  return body;
}

/**
 * Map an API error to dialog state: message + candidates to show, and whether
 * the analyst must explicitly confirm a distinct entity before creating.
 */
export function interpretCatalogLinkError(err, kind) {
  const status = err?.response?.status || null;
  const data = err?.response?.data || {};
  const code = String(data.code || '');
  const noun = catalogKindText(kind).noun;
  const candidates = Array.isArray(data.candidates) ? data.candidates : [];
  if (code === 'POTENTIAL_DUPLICATES') {
    return {
      code,
      message: `Similar ${noun} entries already exist. Link one of them, or confirm this is a distinct ${noun}.`,
      candidates,
      needsDistinctConfirmation: true
    };
  }
  if (code === 'DUPLICATE_ENTITY') {
    return {
      code,
      message: data.error || `This ${noun} already exists in the catalog — link it instead.`,
      candidates,
      switchToLink: true
    };
  }
  if (code === 'ALREADY_LINKED') {
    const names = (data.linked_entities || []).map((e) => e.name).filter(Boolean);
    return {
      code,
      message: names.length
        ? `Already linked to ${names.join(', ')} (possibly by another analyst). Close and refresh to see it.`
        : (data.error || 'Already linked by another analyst.'),
      candidates: [],
      refresh: true
    };
  }
  if (status === 403) {
    return { code: code || 'FORBIDDEN', message: data.error || 'You do not have permission for this action.', candidates: [] };
  }
  if (!err?.response) {
    return { code: 'NETWORK', message: 'Network error — nothing was changed. You can retry safely.', candidates: [] };
  }
  return {
    code: code || 'ERROR',
    message: data.error || data.message || 'Request failed — nothing was changed. You can retry safely.',
    candidates
  };
}

export function catalogLinkSuccessMessage(response, kind) {
  const name = response?.entity?.name || 'catalog entry';
  const noun = catalogKindText(kind).noun;
  if (response?.outcome === 'created_and_linked') return `Created ${noun} "${name}" and linked it`;
  if (response?.outcome === 'already_linked') return `Already linked to ${noun} "${name}"`;
  return `Linked to ${noun} "${name}"`;
}

const ATTRIBUTION_FIELDS = [
  'threat_actors',
  'threat_actor_ids',
  'threat_actor_id',
  'threat_actor_name',
  'analyst_threat_actor_ids',
  'malware_families',
  'malware_family_ids',
  'analyst_malware_family_ids'
];

/** Merge the refreshed attribution fields of a link response into the IOC summary. */
export function mergeAttributionFields(summary, response) {
  if (!summary || !response) return summary;
  const next = { ...summary };
  for (const key of ATTRIBUTION_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(response, key)) next[key] = response[key];
  }
  return next;
}

/** True when the source labels of a chip were linked to the catalog by an analyst. */
export function isAnalystCatalogLink(entity) {
  return currentSources(entity).some((s) => s.resolution_method === 'analyst');
}

/** IOC History "Details" text for catalog link events. */
export function formatCatalogLinkAuditSummary(metadata) {
  if (!metadata || typeof metadata !== 'object') return null;
  if (metadata.operation !== 'link' && metadata.operation !== 'create_and_link') return null;
  if (!metadata.entity_name) return null;
  const sources = [...new Set((metadata.sources || []).map((s) => s?.source_name).filter(Boolean))];
  const reported = metadata.source_label ? `"${metadata.source_label}"` : 'source label';
  const verb = metadata.operation === 'create_and_link' ? 'created + linked' : 'linked';
  const parts = [`${reported}${sources.length ? ` (${sources.join(', ')})` : ''} ${verb} to ${metadata.entity_name}`];
  parts.push('source-reported');
  return parts.join(' · ');
}
