/**
 * IOC confidence resolution — inheritance model (no bulk feed-default copy).
 *
 * effective = manual_override ?? max(membership.explicit) ?? max(feed.default) ?? legacy explicit ?? null
 */

import { feedKeyForSourceName } from './iocExpiration.js';
import { isActiveFeedMembership, isHistoricalFeedMembership, membershipDisplayStatus } from './iocActiveSources.js';

export const CONFIDENCE_LEVELS = Object.freeze(['low', 'medium', 'high']);
export const CONFIDENCE_SOURCES = Object.freeze({
  MANUAL: 'manual',
  MANUAL_ENTRY: 'manual_entry',
  IOC_SOURCE_DEFAULT: 'ioc_source_default',
  FEED_ENTRY: 'feed_entry',
  FEED_DEFAULT: 'feed_default',
  ANALYST_OVERRIDE: 'analyst_override',
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
    ? (input.memberships || []).filter((m) => !m?.purged_at && String(m?.status || '').toLowerCase() !== 'purged')
    : (input.memberships || []).filter((m) => isActiveFeedMembership(m));
  const legacyMap = input.legacyExplicitByFeedKey instanceof Map
    ? input.legacyExplicitByFeedKey
    : new Map(Object.entries(input.legacyExplicitByFeedKey || {}));

  // Per-membership effective = explicit_confidence ?? feed_default_confidence.
  // Global = MAX across all eligible memberships so a high feed default is never
  // beaten by a lower explicit entry confidence from a different source.
  let bestRank = 0;
  let bestCtx = null;

  for (const membership of eligibleMemberships) {
    const explicit = normalizeConfidence(membership.explicit_confidence);
    const feedDefault = normalizeConfidence(membership.feed_default_confidence);
    const value = explicit || feedDefault;
    if (!value) continue;
    const rank = confidenceRank(value);
    if (rank >= bestRank) {
      bestRank = rank;
      bestCtx = {
        value,
        inherited: !explicit,
        source: explicit ? CONFIDENCE_SOURCES.FEED_ENTRY : CONFIDENCE_SOURCES.FEED_DEFAULT,
        feed_name: membership.feed_name || null,
        feed_key: membership.feed_key || null
      };
    }
  }

  for (const [feedKey, value] of legacyMap.entries()) {
    const explicit = normalizeConfidence(value);
    if (!explicit) continue;
    const rank = confidenceRank(explicit);
    if (rank >= bestRank) {
      bestRank = rank;
      bestCtx = {
        value: explicit,
        inherited: false,
        source: CONFIDENCE_SOURCES.FEED_ENTRY,
        feed_name: null,
        feed_key: feedKey
      };
    }
  }

  if (bestCtx) {
    return {
      effective: bestCtx.value,
      confidence_source: bestCtx.source,
      confidence_inherited_from_feed: bestCtx.inherited,
      confidence_feed_name: bestCtx.feed_name,
      confidence_feed_key: bestCtx.feed_key
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

export function buildLegacyExplicitMapFromIocRows(rows = [], { activeOnly = true } = {}) {
  const map = new Map();
  for (const row of rows) {
    if (activeOnly && String(row?.status || 'active') !== 'active') continue;
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

export function buildConfidenceSourceDescription(sourceKind, contextName, opts = {}) {
  const name = String(contextName || '').trim();
  const historical = opts.scope === 'historical' || opts.historical === true;
  if (sourceKind === CONFIDENCE_SOURCES.ANALYST_OVERRIDE || sourceKind === 'analyst_override') {
    return 'Analyst override';
  }
  if (sourceKind === CONFIDENCE_SOURCES.MANUAL || sourceKind === 'manual') return 'Manual override';
  if (sourceKind === CONFIDENCE_SOURCES.MANUAL_ENTRY || sourceKind === 'manual_entry') {
    return historical && name ? `${name} (historical)` : 'Manual entry';
  }
  if (sourceKind === CONFIDENCE_SOURCES.IOC_SOURCE_DEFAULT || sourceKind === 'ioc_source_default') {
    if (historical && name) return `${name} (historical)`;
    return name ? `IOC source default from ${name}` : 'IOC source default';
  }
  if (sourceKind === CONFIDENCE_SOURCES.FEED_ENTRY || sourceKind === 'feed_provided') {
    if (historical && name) return `${name} (historical)`;
    return name ? `${name} (historical entry confidence)` : 'Feed entry confidence';
  }
  if (sourceKind === CONFIDENCE_SOURCES.FEED_DEFAULT || sourceKind === 'feed_default') {
    if (historical && name) return `${name} (historical)`;
    return name ? `Feed default from ${name}` : 'Feed default confidence';
  }
  return 'Unknown';
}

/** Memberships eligible for confidence resolution — never purged. */
export function filterConfidenceMemberships(memberships = [], { allowHistorical = false } = {}) {
  return (memberships || []).filter((m) => {
    if (!m) return false;
    if (m.purged_at || String(m.status || '').toLowerCase() === 'purged') return false;
    if (isActiveFeedMembership(m)) return true;
    if (!allowHistorical) return false;
    const status = String(m.status || '').toLowerCase();
    return status === 'expired' || status === 'removed' || status === 'disabled'
      || isHistoricalFeedMembership(m);
  });
}

/**
 * Resolve confidence from active memberships first, then historical (expired/removed).
 * Purged memberships never contribute.
 */
export function resolveIocConfidenceFromMemberships({
  analystOverride = null,
  membershipRows = [],
  iocRows = [],
  allowHistoricalFallback = true
} = {}) {
  const activeMemberships = filterConfidenceMemberships(membershipRows, { allowHistorical: false });
  const activeIocRows = (iocRows || []).filter((r) => String(r?.status || 'active') === 'active');

  let inherited = computeInheritedEffectiveConfidence({
    manualOverride: analystOverride,
    memberships: activeMemberships,
    legacyExplicitByFeedKey: buildLegacyExplicitMapFromIocRows(activeIocRows)
  });
  let confidenceSourceScope = 'active';

  if (!analystOverride && !inherited.effective && allowHistoricalFallback) {
    const historicalMemberships = filterConfidenceMemberships(membershipRows, { allowHistorical: true })
      .filter((m) => !isActiveFeedMembership(m));
    if (historicalMemberships.length) {
      const historicalIocRows = (iocRows || []).filter((r) => String(r?.status || 'active') !== 'active');
      const historicalInherited = computeInheritedEffectiveConfidence({
        memberships: historicalMemberships,
        legacyExplicitByFeedKey: buildLegacyExplicitMapFromIocRows(historicalIocRows, { activeOnly: false }),
        includeInactiveMemberships: true
      });
      if (historicalInherited.effective) {
        inherited = historicalInherited;
        confidenceSourceScope = 'historical';
      }
    }
  }

  return { inherited, confidenceSourceScope };
}

/**
 * Item-level confidence stored on ioc_items (manual Add IOC / legacy rows).
 * @param {object|null|undefined} row
 */
export function computeItemStoredConfidence(row) {
  if (!row) return null;
  if (normalizeConfidence(row.analyst_confidence_override)) return null;

  const effective = normalizeConfidence(row.confidence);
  if (!effective) return null;

  let source = String(row.confidence_source || '').trim().toLowerCase() || null;
  let sourceName = row.confidence_source_name || row.ioc_source_name || null;

  if (!source && row.ioc_source_id) {
    source = CONFIDENCE_SOURCES.IOC_SOURCE_DEFAULT;
    sourceName = sourceName || row.source_name || null;
  }

  if (!source) {
    source = CONFIDENCE_SOURCES.MANUAL_ENTRY;
  }

  return {
    effective,
    confidence_source: source,
    confidence_ioc_source_id: row.ioc_source_id != null ? Number(row.ioc_source_id) : null,
    confidence_source_name: sourceName,
    confidence_inherited_from_feed: false,
    confidence_feed_name: null,
    confidence_feed_key: null
  };
}

export function buildConfidenceProvenance(summary = {}) {
  const type = summary.analyst_override
    ? CONFIDENCE_SOURCES.ANALYST_OVERRIDE
    : (summary.confidence_source || summary.source || CONFIDENCE_SOURCES.UNKNOWN);
  const sourceName = summary.confidence_source_name || summary.confidence_feed_name || null;
  const label = summary.source_description
    || buildConfidenceSourceDescription(type, sourceName);
  return {
    type,
    source_id: summary.confidence_ioc_source_id ?? null,
    source_name: sourceName,
    label,
    overridden_by: summary.overridden_by || null,
    overridden_at: summary.overridden_at || null
  };
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
  const analystOverride = normalizeConfidence(primaryRow?.analyst_confidence_override);

  const activeMembershipRows = filterConfidenceMemberships(membershipRows, { allowHistorical: false });
  const activeIocRows = (iocRows || []).filter((r) => String(r?.status || 'active') === 'active');

  const { inherited, confidenceSourceScope } = resolveIocConfidenceFromMemberships({
    analystOverride,
    membershipRows,
    iocRows,
    allowHistoricalFallback: true
  });

  if (!analystOverride && !inherited.effective) {
    const hasAnySourceEvidence = activeMembershipRows.length > 0
      || filterConfidenceMemberships(membershipRows, { allowHistorical: true }).length > 0
      || activeIocRows.some((r) => r.ioc_source_id)
      || (iocRows || []).some((r) => r.ioc_source_id)
      || Boolean(primaryRow?.ioc_source_id);
    const itemStored = hasAnySourceEvidence ? computeItemStoredConfidence(primaryRow) : null;
    if (itemStored?.effective) {
      Object.assign(inherited, itemStored);
    }
  }

  const membershipBreakdown = activeMembershipRows.map((m) => ({
      feed_key: m.feed_key || null,
      feed_name: m.feed_name || null,
      explicit_confidence: normalizeConfidence(m.explicit_confidence),
      feed_default_confidence: normalizeConfidence(m.feed_default_confidence),
      effective: computeInheritedEffectiveConfidence({
        memberships: [m],
        legacyExplicitByFeedKey: buildLegacyExplicitMapFromIocRows(
          activeIocRows.filter((r) => feedKeyForSourceName(r.source_name) === m.feed_key)
        )
      }).effective
    }));

  const historicalMemberships = (membershipRows || [])
    .filter((m) => !isActiveFeedMembership(m))
    .map((m) => ({
      feed_key: m.feed_key || null,
      feed_name: m.feed_name || null,
      status: membershipDisplayStatus(m)
    }));

  const baselineEffective = analystOverride
    ? computeInheritedEffectiveConfidence({
      memberships: activeMembershipRows,
      legacyExplicitByFeedKey: buildLegacyExplicitMapFromIocRows(activeIocRows)
    }).effective
    : null;

  const sourceKind = analystOverride
    ? CONFIDENCE_SOURCES.ANALYST_OVERRIDE
    : inherited.confidence_source;
  const sourceContextName = analystOverride
    ? null
    : (inherited.confidence_source_name || inherited.confidence_feed_name || null);
  const descriptionScope = analystOverride ? 'active' : confidenceSourceScope;

  const summary = {
    effective: inherited.effective,
    confidence: inherited.effective,
    confidence_level: inherited.effective,
    confidence_source: sourceKind,
    confidence_source_scope: descriptionScope,
    confidence_inherited_from_feed: inherited.confidence_inherited_from_feed,
    confidence_feed_name: inherited.confidence_feed_name,
    confidence_feed_key: inherited.confidence_feed_key,
    confidence_ioc_source_id: inherited.confidence_ioc_source_id ?? null,
    confidence_source_name: inherited.confidence_source_name ?? inherited.confidence_feed_name ?? null,
    source: sourceKind,
    source_description: buildConfidenceSourceDescription(sourceKind, sourceContextName, { scope: descriptionScope }),
    analyst_override: analystOverride,
    overridden_by: primaryRow?.overridden_by_email || primaryRow?.analyst_confidence_overridden_by || null,
    overridden_at: primaryRow?.analyst_confidence_overridden_at || null,
    override_reason: primaryRow?.analyst_confidence_override_reason || null,
    baseline_effective: baselineEffective,
    baseline_source: analystOverride ? inherited.confidence_source : null,
    membership_breakdown: membershipBreakdown,
    historical_memberships: historicalMemberships,
    has_active_source: activeMembershipRows.length > 0
      || activeIocRows.some((r) => r.ioc_source_id)
      || (String(primaryRow?.status || 'active') === 'active' && Boolean(primaryRow?.ioc_source_id)),
    confidence_set: [...new Set(membershipBreakdown.map((m) => m.effective).filter(Boolean))].sort()
  };
  summary.confidence_provenance = buildConfidenceProvenance(summary);
  return summary;
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
  feedDefaultConfidence = null,
  existingRow = null
} = {}) {
  const sourceConfidence = normalizeConfidence(parsedSourceConfidence);
  const analystOverride = normalizeConfidence(existingRow?.analyst_confidence_override);
  const feedDefault = normalizeConfidence(feedDefaultConfidence);

  return {
    source_confidence: sourceConfidence,
    feed_default_confidence: feedDefault,
    confidence: analystOverride || sourceConfidence || feedDefault || 'medium',
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

  const iocItemIds = [...new Set((rows || []).map((r) => Number(r.id)).filter((id) => Number.isFinite(id)))];
  let membershipRows = [];
  if (iocItemIds.length) {
    const { rows: mRows } = await pool.query(
      `SELECT m.id, m.status, m.purged_at,
              m.explicit_confidence,
              f.key AS feed_key,
              f.name AS feed_name,
              f.default_confidence AS feed_default_confidence
       FROM ioc_feed_memberships m
       JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE m.ioc_item_id = ANY($1::bigint[]) AND m.ioc_observable_type = $2
       ORDER BY m.last_seen_in_feed DESC`,
      [iocItemIds, seedRow.observable_type]
    );
    membershipRows = mRows;
  }
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

  const [{ rows: mRows }, { rows: iocItemRows }] = await Promise.all([
    pool.query(
      `SELECT m.ioc_item_id, m.ioc_observable_type, m.status, m.explicit_confidence,
              f.key AS feed_key, f.name AS feed_name, f.default_confidence AS feed_default_confidence
       FROM ioc_feed_memberships m
       JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE m.ioc_item_id = ANY($1::bigint[])
         AND m.ioc_observable_type = ANY($2::text[])`,
      [ids, types]
    ),
    pool.query(
      `SELECT id, confidence, analyst_confidence_override, ioc_source_id, source_name
       FROM ioc_items
       WHERE id = ANY($1::bigint[])`,
      [ids]
    )
  ]);

  const byKey = new Map();
  for (const m of mRows) {
    const k = `${m.ioc_item_id}|${m.ioc_observable_type}`;
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(m);
  }

  const iocItemById = new Map();
  for (const r of iocItemRows) {
    iocItemById.set(Number(r.id), r);
  }

  const out = new Map();
  for (const it of keyed) {
    const k = `${Number(it.id)}|${String(it.observable_type)}`;
    const memberships = byKey.get(k) || [];
    const storedItem = iocItemById.get(Number(it.id));
    const itEnriched = storedItem
      ? {
          ...it,
          confidence: it.confidence ?? storedItem.confidence,
          analyst_confidence_override: it.analyst_confidence_override ?? storedItem.analyst_confidence_override,
          ioc_source_id: it.ioc_source_id ?? storedItem.ioc_source_id,
          source_name: it.source_name ?? storedItem.source_name,
        }
      : it;
    const { inherited, confidenceSourceScope } = resolveIocConfidenceFromMemberships({
      analystOverride: itEnriched.analyst_confidence_override,
      membershipRows: memberships,
      iocRows: [itEnriched],
      allowHistoricalFallback: includeInactiveMemberships
    });
    let effective = inherited.effective;
    let source = inherited.confidence_source;
    let sourceName = inherited.confidence_feed_name || inherited.confidence_source_name;
    const scope = confidenceSourceScope;
    if (!effective) {
      const hasAnySource = Number(itEnriched.active_source_count) > 0
        || filterConfidenceMemberships(memberships, { allowHistorical: true }).length > 0
        || (memberships || []).some((m) => isActiveFeedMembership(m));
      const itemStored = hasAnySource ? computeItemStoredConfidence(itEnriched) : null;
      if (itemStored) {
        effective = itemStored.effective;
        source = itemStored.confidence_source;
        sourceName = itemStored.confidence_source_name;
      }
    }
    effective = effective
      || (Number(itEnriched.active_source_count) > 0 ? normalizeConfidence(itEnriched.confidence) : null)
      || null;
    out.set(k, {
      confidence_effective: effective,
      confidence_source: source || (effective ? 'legacy_item' : 'unknown'),
      confidence_source_scope: effective ? scope : null,
      confidence_source_description: effective
        ? buildConfidenceSourceDescription(source || 'unknown', sourceName, { scope })
        : (Number(itEnriched.active_source_count) > 0 && itEnriched.source_name ? `Historical from ${itEnriched.source_name}` : 'No active source')
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
