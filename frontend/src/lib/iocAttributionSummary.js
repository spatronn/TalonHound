export function getThreatActorsFromSummary(summary) {
  if (Array.isArray(summary?.threat_actors) && summary.threat_actors.length) {
    return summary.threat_actors.filter((a) => a?.id || a?.name);
  }
  if (Array.isArray(summary?.threat_actor_ids) && summary.threat_actor_ids.length) {
    return summary.threat_actor_ids.map((id) => ({
      id,
      name: summary?.threat_actor_name || id
    }));
  }
  if (summary?.threat_actor_id) {
    return [{ id: summary.threat_actor_id, name: summary.threat_actor_name || summary.threat_actor_id }];
  }
  return [];
}

export function getMalwareFamiliesFromSummary(summary) {
  if (Array.isArray(summary?.malware_families) && summary.malware_families.length) {
    return summary.malware_families.filter((f) => f?.id || f?.name);
  }
  if (Array.isArray(summary?.malware_family_ids) && summary.malware_family_ids.length) {
    return summary.malware_family_ids.map((id) => ({ id, name: id }));
  }
  return [];
}

/** Analyst-editable catalog IDs only — never elevate source-reported associations. */
export function getAnalystThreatActorIdsFromSummary(summary) {
  if (Array.isArray(summary?.analyst_threat_actor_ids)) {
    return summary.analyst_threat_actor_ids.map(String);
  }
  return getThreatActorsFromSummary(summary)
    .filter((a) => a?.id && (a.attribution === 'analyst' || a.attribution === 'mixed'))
    .map((a) => String(a.id));
}

export function getAnalystMalwareFamilyIdsFromSummary(summary) {
  if (Array.isArray(summary?.analyst_malware_family_ids)) {
    return summary.analyst_malware_family_ids.map(String);
  }
  return getMalwareFamiliesFromSummary(summary)
    .filter((f) => f?.id && (f.attribution === 'analyst' || f.attribution === 'mixed'))
    .map((f) => String(f.id));
}

const DIRECT_KINDS = ['directly_attributed_to', 'malware_sample_of'];

/** 'direct' when a source explicitly ties the IOC to the entity, else 'context'. */
export function sourceRelationshipScope(source) {
  if (source?.relationship_scope) return source.relationship_scope;
  return DIRECT_KINDS.includes(source?.association_kind) ? 'direct' : 'context';
}

export function attributionHint(entity) {
  const attribution = entity?.attribution || null;
  const sources = Array.isArray(entity?.sources) ? entity.sources.filter((s) => s.assertion_status === 'current') : [];
  if (attribution === 'analyst') return 'Analyst';
  const direct = sources.filter((s) => sourceRelationshipScope(s) === 'direct');
  if (direct.length) {
    // The stronger relationship leads; Pulse context stays named.
    const namesOf = (list) => [...new Set(list.map((s) => s.source_name).filter(Boolean))].join(', ');
    const context = sources.filter((s) => sourceRelationshipScope(s) === 'context');
    const parts = [attribution === 'mixed' ? 'Analyst' : null, `Direct · ${namesOf(direct) || 'source'}`];
    if (context.length) parts.push(`Context · ${namesOf(context) || 'source'}`);
    return parts.filter(Boolean).join(' · ');
  }
  if (attribution === 'mixed') {
    const names = [...new Set(sources.map((s) => s.source_name).filter(Boolean))];
    return names.length ? `Analyst · ${names.join(', ')}` : 'Analyst · Source-reported';
  }
  if (sources.length) {
    const names = [...new Set(sources.map((s) => s.source_name).filter(Boolean))];
    const kind = sources[0]?.association_kind === 'associated_via_source_pulse'
      ? 'Source-reported (pulse context)'
      : 'Source-reported';
    return names.length ? `${names.join(', ')} · ${kind}` : kind;
  }
  if (attribution === 'source_reported') return 'Source-reported';
  return null;
}
