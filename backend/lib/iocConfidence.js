/**
 * IOC confidence resolution — inheritance model (no bulk feed-default copy).
 *
 * effective = manual_override ?? max(membership.explicit) ?? max(feed.default) ?? legacy explicit ?? null
 */

import { feedKeyForSourceName } from './iocExpiration.js';

export const CONFIDENCE_LEVELS = Object.freeze(['low', 'medium', 'high']);
export const CONFIDENCE_SOURCES = Object.freeze({
  MANUAL: 'manual',
  FEED_ENTRY: 'feed_entry',
  FEED_DEFAULT: 'feed_default',
  UNKNOWN: 'unknown'
});

export const MAX_CONFIDENCE_OVERRIDE_REASON_LEN = 2000;

const CONFIDENCE_RANK = Object.freeze({ low: 1, medium: 2, high: 3 });

export function normalizeConfidence(value) {
  const c = String(value ?? '').trim().toLowerCase();
  if (!c) return null;
  if (c === 'critical') return 'high';
  if (c === 'unknown' || c === 'none') return null;
  if (CONFIDENCE_LEVELS.includes(c)) return c;
  return null;
}

export function confidenceLabel(value) {
  const c = normalizeConfidence(value);
  if (!c) return null;
  return c.charAt(0).toUpperCase() + c.slice(1);
}

export function confidenceRank(value) {
  return CONFIDENCE_RANK[normalizeConfidence(value)] || 0;
}

export function pickHighestConfidenceValue(values) {
  let best = null;
  let bestRank = 0;
  for (const raw of values) {
    const normalized = normalizeConfidence(raw);
    const rank = confidenceRank(normalized);
    if (normalized && rank >= bestRank) {
      best = normalized;
      bestRank = rank;
    }
  }
  return best;
}

/**
 * @param {{
 *   manualOverride?: string|null,
 *   memberships?: Array<{ status?: string, explicit_confidence?: string|null, feed_default_confidence?: string|null, feed_name?: string|null, feed_key?: string|null }>,
 *   legacyExplicitByFeedKey?: Map<string, string>|Record<string, string>,
 * }} input
 */
export function computeInheritedEffectiveConfidence(input = {}) {
  const includeInactiveMemberships = Boolean(input.includeInactiveMemberships);
  const manual = normalizeConfidence(input.manualOverride);
  if (manual) {
    return {
      effective: manual,
      confidence_source: CONFIDENCE_SOURCES.MANUAL,
      confidence_inherited_from_feed: false,
      confidence_feed_name: null,
      confidence_feed_key: null
    };
  }

  const eligibleMemberships = includeInactiveMemberships
    ? (input.memberships || [])
    : (input.memberships || []).filter((m) => String(m?.status || 'active') === 'active');
  const legacyMap = input.legacyExplicitByFeedKey instanceof Map
    ? input.legacyExplicitByFeedKey
    : new Map(Object.entries(input.legacyExplicitByFeedKey || {}));

  const explicitCandidates = [];
  const explicitContexts = [];

  for (const membership of eligibleMemberships) {
    const explicit = normalizeConfidence(membership.explicit_confidence);
    if (explicit) {
      explicitCandidates.push(explicit);
      explicitContexts.push({
        value: explicit,
        feed_name: membership.feed_name || null,
        feed_key: membership.feed_key || null
      });
    }
  }

  for (const [feedKey, value] of legacyMap.entries()) {
    const explicit = normalizeConfidence(value);
    if (explicit) {
      explicitCandidates.push(explicit);
      explicitContexts.push({ value: explicit, feed_key: feedKey, feed_name: null });
    }
  }

  const bestExplicit = pickHighestConfidenceValue(explicitCandidates);
  if (bestExplicit) {
    const ctx = explicitContexts.find((c) => c.value === bestExplicit) || explicitContexts[0];
    return {
      effective: bestExplicit,
      confidence_source: CONFIDENCE_SOURCES.FEED_ENTRY,
      confidence_inherited_from_feed: false,
      confidence_feed_name: ctx?.feed_name || null,
      confidence_feed_key: ctx?.feed_key || null
    };
  }

  const defaultCandidates = [];
  const defaultContexts = [];
  for (const membership of eligibleMemberships) {
    const feedDefault = normalizeConfidence(membership.feed_default_confidence);
    if (feedDefault) {
      defaultCandidates.push(feedDefault);
      defaultContexts.push({
        value: feedDefault,
        feed_name: membership.feed_name || null,
        feed_key: membership.feed_key || null
      });
    }
  }

  const bestDefault = pickHighestConfidenceValue(defaultCandidates);
  if (bestDefault) {
    const ctx = defaultContexts.find((c) => c.value === bestDefault) || defaultContexts[0];
    return {
      effective: bestDefault,
      confidence_source: CONFIDENCE_SOURCES.FEED_DEFAULT,
      confidence_inherited_from_feed: true,
      confidence_feed_name: ctx?.feed_name || null,
      confidence_feed_key: ctx?.feed_key || null
    };
  }

  return {
    effective: null,
    confidence_source: CONFIDENCE_SOURCES.UNKNOWN,
    confidence_inherited_from_feed: false,
    confidence_feed_name: null,
    confidence_feed_key: null
  };
}

export function buildLegacyExplicitMapFromIocRows(rows = []) {
  const map = new Map();
  for (const row of rows) {
    const explicit = normalizeConfidence(row.source_confidence);
    if (!explicit) continue;
    const feedKey = feedKeyForSourceName(row.source_name);
    if (!feedKey) continue;
    const existing = map.get(feedKey);
    if (!existing || confidenceRank(explicit) >= confidenceRank(existing)) {
      map.set(feedKey, explicit);
    }
  }
  return map;
}

export function buildConfidenceSourceDescription(sourceKind, feedName) {
  const name = String(feedName || '').trim();
  if (sourceKind === CONFIDENCE_SOURCES.MANUAL || sourceKind === 'analyst_override') return 'Manual override';
  if (sourceKind === CONFIDENCE_SOURCES.FEED_ENTRY || sourceKind === 'feed_provided') return 'Feed entry confidence';
  if (sourceKind === CONFIDENCE_SOURCES.FEED_DEFAULT || sourceKind === 'feed_default') {
    return name ? `Feed default from ${name}` : 'Feed default confidence';
  }
  return 'Unknown';
}

export function pickPrimaryIocRow(rows, seedPublicId) {
  if (!Array.isArray(rows) || !rows.length) return null;
  const seed = seedPublicId
    ? rows.find((r) => String(r.public_id || '') === String(seedPublicId))
    : null;
  return seed || rows[0];
}

export function buildIocInheritedConfidenceSummary({
  seedRow = null,
  membershipRows = [],
  iocRows = [],
  seedPublicId = null
} = {}) {
  const primaryRow = seedRow || pickPrimaryIocRow(iocRows, seedPublicId);
  const inherited = computeInheritedEffectiveConfidence({
    manualOverride: primaryRow?.analyst_confidence_override,
    memberships: membershipRows,
    legacyExplicitByFeedKey: buildLegacyExplicitMapFromIocRows(iocRows),
    includeInactiveMemberships: true
  });

  const membershipBreakdown = (membershipRows || [])
    .filter((m) => String(m?.status || 'active') === 'active')
    .map((m) => ({
      feed_key: m.feed_key || null,
      feed_name: m.feed_name || null,
      explicit_confidence: normalizeConfidence(m.explicit_confidence),
      feed_default_confidence: normalizeConfidence(m.feed_default_confidence),
      effective: computeInheritedEffectiveConfidence({
        memberships: [m],
        legacyExplicitByFeedKey: buildLegacyExplicitMapFromIocRows(
          iocRows.filter((r) => feedKeyForSourceName(r.source_name) === m.feed_key)
        )
      }).effective
    }));

  const analystOverride = normalizeConfidence(primaryRow?.analyst_confidence_override);
  const baselineEffective = analystOverride
    ? computeInheritedEffectiveConfidence({
      memberships: membershipRows,
      legacyExplicitByFeedKey: buildLegacyExplicitMapFromIocRows(iocRows)
    }).effective
    : null;

  return {
    effective: inherited.effective,
    confidence: inherited.effective,
    confidence_level: inherited.effective,
    confidence_source: inherited.confidence_source,
    confidence_inherited_from_feed: inherited.confidence_inherited_from_feed,
    confidence_feed_name: inherited.confidence_feed_name,
    confidence_feed_key: inherited.confidence_feed_key,
    source: inherited.confidence_source,
    source_description: buildConfidenceSourceDescription(inherited.confidence_source, inherited.confidence_feed_name),
    analyst_override: analystOverride,
    overridden_by: primaryRow?.overridden_by_email || primaryRow?.analyst_confidence_overridden_by || null,
    overridden_at: primaryRow?.analyst_confidence_overridden_at || null,
    override_reason: primaryRow?.analyst_confidence_override_reason || null,
    baseline_effective: baselineEffective,
    baseline_source: analystOverride ? inherited.confidence_source : null,
    membership_breakdown: membershipBreakdown,
    confidence_set: [...new Set(membershipBreakdown.map((m) => m.effective).filter(Boolean))].sort()
  };
}

export function computeEffectiveConfidence({
  sourceConfidence = null,
  feedDefaultConfidence = null,
  analystOverride = null,
  fallback = null
} = {}) {
  const inherited = computeInheritedEffectiveConfidence({
    manualOverride: analystOverride,
    memberships: [{
      explicit_confidence: sourceConfidence,
      feed_default_confidence: feedDefaultConfidence,
      status: 'active'
    }]
  });
  if (inherited.effective) return inherited.effective;
  return normalizeConfidence(fallback);
}

export function resolveConfidenceSourceKind({
  analystOverride = null,
  sourceConfidence = null,
  feedDefaultConfidence = null
} = {}) {
  return computeInheritedEffectiveConfidence({
    manualOverride: analystOverride,
    memberships: [{
      explicit_confidence: sourceConfidence,
      feed_default_confidence: feedDefaultConfidence,
      status: 'active'
    }]
  }).confidence_source;
}

export function buildIocConfidenceSummary({
  rows,
  seedPublicId = null,
  feedNamesByKey = {}
}) {
  const membershipRows = rows.map((row) => {
    const feedKey = feedKeyForSourceName(row.source_name);
    const feedMeta = feedKey && feedNamesByKey instanceof Map
      ? feedNamesByKey.get(feedKey)
      : feedNamesByKey[feedKey];
    const feedName = typeof feedMeta === 'object' && feedMeta?.name
      ? feedMeta.name
      : (typeof feedMeta === 'string' ? feedMeta : row.source_name);
    const feedDefault = typeof feedMeta === 'object' && feedMeta?.default_confidence != null
      ? feedMeta.default_confidence
      : row.feed_default_confidence;

    return {
      status: 'active',
      explicit_confidence: row.source_confidence,
      feed_default_confidence: feedDefault,
      feed_key: feedKey,
      feed_name: feedName
    };
  });

  return buildIocInheritedConfidenceSummary({
    seedRow: pickPrimaryIocRow(rows, seedPublicId),
    membershipRows,
    iocRows: rows,
    seedPublicId
  });
}

export function validateConfidenceInput(value) {
  const normalized = normalizeConfidence(value);
  if (!normalized) {
    return { ok: false, error: 'confidence must be low, medium, or high' };
  }
  return { ok: true, value: normalized };
}

export function validateConfidenceReason(reason) {
  if (reason == null || reason === '') return { ok: true, value: null };
  const trimmed = String(reason).trim();
  if (trimmed.length > MAX_CONFIDENCE_OVERRIDE_REASON_LEN) {
    return { ok: false, error: `reason must be at most ${MAX_CONFIDENCE_OVERRIDE_REASON_LEN} characters` };
  }
  return { ok: true, value: trimmed || null };
}

export async function fetchFeedDefaultConfidence(client, feedKeyOrSourceName) {
  const feedKey = feedKeyForSourceName(feedKeyOrSourceName) || String(feedKeyOrSourceName || '').trim();
  if (!feedKey) return null;
  try {
    const { rows } = await client.query(
      'SELECT default_confidence FROM integration_feeds WHERE key = $1 LIMIT 1',
      [feedKey]
    );
    return normalizeConfidence(rows[0]?.default_confidence);
  } catch (err) {
    if (err?.code === '42703') return null;
    throw err;
  }
}

export async function fetchFeedNamesByKey(client) {
  const { rows } = await client.query('SELECT key, name, default_confidence FROM integration_feeds');
  const map = new Map();
  for (const row of rows) {
    map.set(String(row.key), {
      name: String(row.name),
      default_confidence: normalizeConfidence(row.default_confidence)
    });
  }
  return map;
}

export function resolveParsedSourceConfidence(sourceConfidence, legacyConfidence) {
  if (sourceConfidence !== undefined) {
    return normalizeConfidence(sourceConfidence);
  }
  return normalizeConfidence(legacyConfidence);
}

export function resolveImportConfidenceFields({
  parsedSourceConfidence = null,
  existingRow = null
} = {}) {
  const sourceConfidence = normalizeConfidence(parsedSourceConfidence);
  const analystOverride = normalizeConfidence(existingRow?.analyst_confidence_override);

  const fallbackConfidence = 'medium';
  return {
    source_confidence: sourceConfidence,
    feed_default_confidence: null,
    confidence: analystOverride || sourceConfidence || fallbackConfidence,
    analyst_confidence_override: analystOverride
  };
}

export async function fetchIocMembershipConfidenceRows(pool, iocItemId, observableType) {
  try {
    const { rows } = await pool.query(
      `SELECT m.id, m.status,
              m.explicit_confidence,
              f.key AS feed_key,
              f.name AS feed_name,
              f.default_confidence AS feed_default_confidence
       FROM ioc_feed_memberships m
       JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE m.ioc_item_id = $1 AND m.ioc_observable_type = $2
       ORDER BY m.last_seen_in_feed DESC`,
      [iocItemId, observableType]
    );
    return rows;
  } catch (err) {
    if (err?.code === '42703') {
      const { rows } = await pool.query(
        `SELECT m.id, m.status,
                NULL::text AS explicit_confidence,
                f.key AS feed_key,
                f.name AS feed_name,
                f.default_confidence AS feed_default_confidence
         FROM ioc_feed_memberships m
         JOIN integration_feeds f ON f.integration_id = m.feed_id
         WHERE m.ioc_item_id = $1 AND m.ioc_observable_type = $2
         ORDER BY m.last_seen_in_feed DESC`,
        [iocItemId, observableType]
      );
      return rows;
    }
    throw err;
  }
}

export async function buildIocConfidenceSummaryForDetails(pool, { rows, seedPublicId }) {
  const seedRow = pickPrimaryIocRow(rows, seedPublicId) || rows?.[0] || null;
  if (!seedRow) {
    return buildIocInheritedConfidenceSummary({ seedRow: null, membershipRows: [], iocRows: [], seedPublicId });
  }

  const membershipRows = await fetchIocMembershipConfidenceRows(pool, seedRow.id, seedRow.observable_type);
  return buildIocInheritedConfidenceSummary({
    seedRow,
    membershipRows,
    iocRows: rows,
    seedPublicId
  });
}

export async function buildDisplayConfidenceForItems(pool, items = [], opts = {}) {
  const includeInactiveMemberships = Boolean(opts.includeInactiveMemberships);
  const keyed = (items || []).filter((x) => Number.isFinite(Number(x?.id)) && String(x?.observable_type || '').trim());
  if (!keyed.length) return new Map();

  const ids = keyed.map((x) => Number(x.id));
  const types = [...new Set(keyed.map((x) => String(x.observable_type)))];

  const { rows: mRows } = await pool.query(
    `SELECT m.ioc_item_id, m.ioc_observable_type, m.status, m.explicit_confidence,
            f.key AS feed_key, f.name AS feed_name, f.default_confidence AS feed_default_confidence
     FROM ioc_feed_memberships m
     JOIN integration_feeds f ON f.integration_id = m.feed_id
     WHERE m.ioc_item_id = ANY($1::bigint[])
       AND m.ioc_observable_type = ANY($2::text[])`,
    [ids, types]
  );

  const byKey = new Map();
  for (const m of mRows) {
    const k = `${m.ioc_item_id}|${m.ioc_observable_type}`;
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(m);
  }

  const out = new Map();
  for (const it of keyed) {
    const k = `${Number(it.id)}|${String(it.observable_type)}`;
    const memberships = byKey.get(k) || [];
    const inherited = computeInheritedEffectiveConfidence({
      manualOverride: it.analyst_confidence_override,
      memberships,
      legacyExplicitByFeedKey: new Map(),
      includeInactiveMemberships
    });
    const effective = inherited.effective || normalizeConfidence(it.confidence) || null;
    out.set(k, {
      confidence_effective: effective,
      confidence_source: inherited.effective ? inherited.confidence_source : (effective ? 'legacy_item' : 'unknown'),
      confidence_source_description: inherited.effective
        ? buildConfidenceSourceDescription(inherited.confidence_source, inherited.confidence_feed_name)
        : (it.source_name ? `Historical from ${it.source_name}` : 'Unknown')
    });
  }
  return out;
}

export async function applyMembershipExplicitConfidence(client, membershipId, explicitConfidence) {
  const explicit = normalizeConfidence(explicitConfidence);
  if (!explicit || !membershipId) return null;
  try {
    await client.query(
      `UPDATE ioc_feed_memberships
       SET explicit_confidence = $2, updated_at = NOW()
       WHERE id = $1`,
      [membershipId, explicit]
    );
    return explicit;
  } catch (err) {
    if (err?.code === '42703') return null;
    throw err;
  }
}

export async function applyIocImportConfidence(client, {
  observable,
  observableType,
  sourceName,
  parsedSourceConfidence = null
}) {
  const explicit = normalizeConfidence(parsedSourceConfidence);
  if (!explicit) return null;

  let existing;
  try {
    const { rows } = await client.query(
      `SELECT analyst_confidence_override
       FROM ioc_items
       WHERE observable = $1 AND observable_type = $2 AND source_name = $3
       ORDER BY created_at DESC
       LIMIT 1`,
      [observable, observableType, sourceName]
    );
    existing = rows[0];
  } catch (err) {
    if (err?.code === '42703') return null;
    throw err;
  }
  if (!existing) return null;

  try {
    if (existing.analyst_confidence_override) {
      await client.query(
        `UPDATE ioc_items
         SET source_confidence = $4
         WHERE observable = $1 AND observable_type = $2 AND source_name = $3`,
        [observable, observableType, sourceName, explicit]
      );
    } else {
      await client.query(
        `UPDATE ioc_items
         SET source_confidence = $4,
             confidence = $4
         WHERE observable = $1 AND observable_type = $2 AND source_name = $3`,
        [observable, observableType, sourceName, explicit]
      );
    }
  } catch (err) {
    if (err?.code === '42703') return null;
    throw err;
  }

  return { source_confidence: explicit };
}

export async function enrichIocConfidenceRows(pool, rows) {
  return rows;
}
