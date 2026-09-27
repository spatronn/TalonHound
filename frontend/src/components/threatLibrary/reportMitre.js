/**
 * Pure helpers for Threat Library report-level MITRE ATT&CK display.
 * Names/tactics are expected to already be canonical from the API.
 */

export function normalizeMitreMappings(raw) {
  const seen = new Set();
  const out = [];
  for (const m of Array.isArray(raw) ? raw : []) {
    const technique_id = String(m?.technique_id || '').trim();
    if (!technique_id || seen.has(technique_id)) continue;
    seen.add(technique_id);
    const tactics = (Array.isArray(m.tactics) ? m.tactics : [])
      .map((t) => ({
        id: String(t?.id || '').trim(),
        name: String(t?.name || '').trim() || String(t?.id || '').trim()
      }))
      .filter((t) => t.id);
    out.push({
      technique_id,
      technique_name: String(m.technique_name || '').trim() || null,
      attack_type: m.attack_type || null,
      url: m.url || null,
      tactics,
      confidence: m.confidence == null || m.confidence === '' ? null : Number(m.confidence),
      evidence: String(m.evidence || '').trim() || null
    });
  }
  return out.sort((a, b) => a.technique_id.localeCompare(b.technique_id));
}

/**
 * Group mappings by tactic. A technique with multiple tactics appears under
 * each tactic (canonical ATT&CK), not as a duplicated free-floating row.
 */
export function groupMitreByTactic(mappings) {
  const groups = new Map();
  const ungrouped = [];
  for (const m of normalizeMitreMappings(mappings)) {
    if (!m.tactics.length) {
      ungrouped.push(m);
      continue;
    }
    for (const tactic of m.tactics) {
      if (!groups.has(tactic.id)) {
        groups.set(tactic.id, { id: tactic.id, name: tactic.name, items: [] });
      }
      groups.get(tactic.id).items.push(m);
    }
  }
  const ordered = [...groups.values()].sort((a, b) => a.id.localeCompare(b.id));
  if (ungrouped.length) ordered.push({ id: '', name: 'Unmapped', items: ungrouped });
  return ordered;
}

export function formatMitreConfidence(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return `${Math.round(n * 100)}%`;
}

export function mergeReportIntelPayload(prev, next) {
  if (!next) return next;
  let out = next;
  if (!Array.isArray(next.tags) && Array.isArray(prev?.tags)) {
    out = { ...out, tags: prev.tags };
  }
  if (!Array.isArray(next.mitre_attack) && Array.isArray(prev?.mitre_attack)) {
    out = { ...out, mitre_attack: prev.mitre_attack };
  }
  return out;
}
