/**
 * Group file_artifact source_observations for UI Source Evidence.
 * Direct observations become primary rows; provider_hash_mapping siblings
 * collapse into additional_known_hashes under the same provider record.
 */

/**
 * @param {Array<object>} observations
 * @returns {Array<object>}
 */
export function groupFileArtifactObservations(observations) {
  const list = Array.isArray(observations) ? observations : [];
  if (!list.length) return [];

  const groups = new Map();

  const groupKey = (o) => {
    const feed = o.feed_id != null && String(o.feed_id).trim() !== '' ? String(o.feed_id) : '';
    const record = o.source_record_id != null && String(o.source_record_id).trim() !== ''
      ? String(o.source_record_id)
      : '';
    const name = String(o.source_name || '').trim() || 'unknown';
    // Prefer feed+record; fall back to feed+name; never merge different feeds by name alone when feed present
    if (feed || record) return `${feed}::${record}::${name}`;
    return `name::${name}`;
  };

  for (const o of list) {
    const key = groupKey(o);
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        source_name: o.source_name || '-',
        feed_id: o.feed_id || null,
        source_record_id: o.source_record_id || null,
        direct: null,
        mappings: [],
        all: []
      };
      groups.set(key, g);
    }
    g.all.push(o);
    const type = String(o.observation_type || '');
    if (type === 'direct_source_observation' || type === 'migration_backfill') {
      if (!g.direct) g.direct = o;
      else if (String(o.observed_hash_type) === 'sha256' && String(g.direct.observed_hash_type) !== 'sha256') {
        g.mappings.push(g.direct);
        g.direct = o;
      } else {
        g.mappings.push(o);
      }
    } else {
      g.mappings.push(o);
    }
  }

  const out = [];
  for (const g of groups.values()) {
    const primary = g.direct || g.mappings[0] || g.all[0];
    if (!primary) continue;

    const extra = [];
    const seen = new Set();
    const addHash = (type, value) => {
      const t = String(type || '').toLowerCase();
      const v = String(value || '').toLowerCase();
      if (!t || !v) return;
      const k = `${t}:${v}`;
      if (seen.has(k)) return;
      // Skip the primary observed hash itself
      if (
        t === String(primary.observed_hash_type || primary.observed_as || '').toLowerCase()
        && v === String(primary.observed_hash_value || '').toLowerCase()
      ) {
        seen.add(k);
        return;
      }
      seen.add(k);
      extra.push({ hash_type: t, value: v });
    };

    for (const m of g.mappings) {
      addHash(m.observed_hash_type || m.observed_as, m.observed_hash_value);
    }
    // Also collect from all if primary was mapping-only
    for (const m of g.all) {
      if (m === primary) continue;
      addHash(m.observed_hash_type || m.observed_as, m.observed_hash_value);
    }

    const firstSeen = g.all
      .map((x) => x.first_seen_in_source)
      .filter(Boolean)
      .sort()[0] || primary.first_seen_in_source || null;
    const lastSeen = g.all
      .map((x) => x.last_seen_in_source)
      .filter(Boolean)
      .sort()
      .reverse()[0] || primary.last_seen_in_source || null;

    const mappingEvidence = g.mappings.some((m) =>
      ['provider_hash_mapping', 'enrichment_derived'].includes(String(m.observation_type || ''))
    );

    out.push({
      id: primary.id,
      source_name: g.source_name,
      feed_id: g.feed_id,
      observed_as: primary.observed_as || primary.observed_hash_type,
      observed_hash_type: primary.observed_hash_type || primary.observed_as,
      observed_hash_value: primary.observed_hash_value,
      observation_type: primary.observation_type,
      relation_method: primary.relation_method,
      evidence_label: primary.evidence_label
        || (primary.observation_type === 'direct_source_observation'
          ? 'Direct source observation'
          : primary.observation_type),
      confidence: primary.confidence || null,
      first_seen_in_source: firstSeen,
      last_seen_in_source: lastSeen,
      additional_known_hashes: extra,
      mapping_evidence: mappingEvidence ? 'Provider exact-hash mapping' : null,
      _group_size: g.all.length
    });
  }

  out.sort((a, b) => String(a.source_name).localeCompare(String(b.source_name)));
  return out;
}
