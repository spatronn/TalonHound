/**
 * IOC confidence resolution: source → feed default → system fallback, with analyst override.
 */

import { feedKeyForSourceName } from './iocExpiration.js';

export const CONFIDENCE_LEVELS = Object.freeze(['low', 'medium', 'high']);
export const SYSTEM_FALLBACK_CONFIDENCE = 'medium';
export const MAX_CONFIDENCE_OVERRIDE_REASON_LEN = 2000;

const CONFIDENCE_RANK = Object.freeze({ low: 1, medium: 2, high: 3 });

/** @typedef {'analyst_override' | 'feed_provided' | 'feed_default' | 'system_fallback'} ConfidenceSourceKind */

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

export function computeEffectiveConfidence({
  sourceConfidence = null,
  feedDefaultConfidence = null,
  analystOverride = null,
  fallback = SYSTEM_FALLBACK_CONFIDENCE
} = {}) {
  const analyst = normalizeConfidence(analystOverride);
  if (analyst) return analyst;
  const source = normalizeConfidence(sourceConfidence);
  if (source) return source;
  const feedDefault = normalizeConfidence(feedDefaultConfidence);
  if (feedDefault) return feedDefault;
  return normalizeConfidence(fallback) || SYSTEM_FALLBACK_CONFIDENCE;
}

export function resolveConfidenceSourceKind({
  analystOverride = null,
  sourceConfidence = null,
  feedDefaultConfidence = null
} = {}) {
  if (normalizeConfidence(analystOverride)) return 'analyst_override';
  if (normalizeConfidence(sourceConfidence)) return 'feed_provided';
  if (normalizeConfidence(feedDefaultConfidence)) return 'feed_default';
  return 'system_fallback';
}

export function buildConfidenceSourceDescription(sourceKind, feedName) {
  const name = String(feedName || '').trim();
  if (sourceKind === 'analyst_override') return 'Manual override';
  if (sourceKind === 'feed_provided') return 'Feed-provided confidence';
  if (sourceKind === 'feed_default') {
    return name ? `Feed default from ${name}` : 'Feed default confidence';
  }
  return 'System fallback';
}

export function pickPrimaryIocRow(rows, seedPublicId) {
  if (!Array.isArray(rows) || !rows.length) return null;
  const seed = seedPublicId
    ? rows.find((r) => String(r.public_id || '') === String(seedPublicId))
    : null;
  return seed || rows[0];
}

export function pickHighestConfidenceRow(rows) {
  if (!Array.isArray(rows) || !rows.length) return null;
  return rows.reduce((best, row) => {
    if (!best) return row;
    const bestEff = computeEffectiveConfidence({
      sourceConfidence: best.source_confidence ?? best.confidence,
      feedDefaultConfidence: best.feed_default_confidence,
      analystOverride: best.analyst_confidence_override
    });
    const rowEff = computeEffectiveConfidence({
      sourceConfidence: row.source_confidence ?? row.confidence,
      feedDefaultConfidence: row.feed_default_confidence,
      analystOverride: row.analyst_confidence_override
    });
    return (CONFIDENCE_RANK[rowEff] || 0) > (CONFIDENCE_RANK[bestEff] || 0) ? row : best;
  }, null);
}

/**
 * Build structured confidence payload for IOC Details summary.
 * @param {object} opts
 * @param {object[]} opts.rows All ioc_items rows for the observable
 * @param {string|null} opts.seedPublicId Requested public_id
 * @param {Map<string, string>|Record<string, string>} [opts.feedNamesByKey]
 */
export function buildIocConfidenceSummary({
  rows,
  seedPublicId = null,
  feedNamesByKey = {}
}) {
  const seedRow = pickPrimaryIocRow(rows, seedPublicId);
  const baselineRow = seedRow || pickHighestConfidenceRow(rows) || rows?.[0] || null;

  const analystOverride = normalizeConfidence(seedRow?.analyst_confidence_override);
  const sourceConfidence = normalizeConfidence(baselineRow?.source_confidence);
  const feedDefaultConfidence = normalizeConfidence(baselineRow?.feed_default_confidence);

  const effective = computeEffectiveConfidence({
    sourceConfidence,
    feedDefaultConfidence,
    analystOverride: seedRow?.analyst_confidence_override,
    fallback: baselineRow?.confidence
  });

  const sourceKind = resolveConfidenceSourceKind({
    analystOverride: seedRow?.analyst_confidence_override,
    sourceConfidence: analystOverride ? null : sourceConfidence,
    feedDefaultConfidence: analystOverride ? null : feedDefaultConfidence
  });

  const feedKey = feedKeyForSourceName(baselineRow?.source_name);
  const feedName = feedKey
    ? (feedNamesByKey instanceof Map ? feedNamesByKey.get(feedKey) : feedNamesByKey[feedKey]) || baselineRow?.source_name
    : baselineRow?.source_name || null;

  const baselineEffective = analystOverride
    ? computeEffectiveConfidence({
      sourceConfidence,
      feedDefaultConfidence,
      analystOverride: null,
      fallback: baselineRow?.confidence
    })
    : null;

  const baselineSourceKind = analystOverride
    ? resolveConfidenceSourceKind({ sourceConfidence, feedDefaultConfidence })
    : null;

  return {
    effective,
    source_confidence: sourceConfidence,
    feed_default_confidence: feedDefaultConfidence,
    analyst_override: analystOverride,
    source: sourceKind,
    feed_name: feedName,
    feed_key: feedKey,
    source_description: buildConfidenceSourceDescription(sourceKind, feedName),
    overridden_by: seedRow?.overridden_by_email || seedRow?.analyst_confidence_overridden_by || null,
    overridden_at: seedRow?.analyst_confidence_overridden_at || null,
    override_reason: seedRow?.analyst_confidence_override_reason || null,
    baseline_effective: baselineEffective,
    baseline_source: baselineSourceKind,
    // Backward-compatible flat fields
    confidence: effective,
    confidence_level: effective,
    confidence_set: [...new Set(rows.map((r) => computeEffectiveConfidence({
      sourceConfidence: r.source_confidence,
      feedDefaultConfidence: r.feed_default_confidence,
      analystOverride: null,
      fallback: r.confidence
    })).filter(Boolean))].sort()
  };
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

export async function fetchFeedDefaultConfidence(client, sourceName) {
  const feedKey = feedKeyForSourceName(sourceName);
  if (!feedKey) return SYSTEM_FALLBACK_CONFIDENCE;
  try {
    const { rows } = await client.query(
      'SELECT default_confidence FROM integration_feeds WHERE key = $1 LIMIT 1',
      [feedKey]
    );
    return normalizeConfidence(rows[0]?.default_confidence) || SYSTEM_FALLBACK_CONFIDENCE;
  } catch (err) {
    if (err?.code === '42703') return SYSTEM_FALLBACK_CONFIDENCE;
    throw err;
  }
}

export async function fetchFeedNamesByKey(client) {
  const { rows } = await client.query('SELECT key, name FROM integration_feeds');
  const map = new Map();
  for (const row of rows) {
    map.set(String(row.key), String(row.name));
  }
  return map;
}

/**
 * @param {object|null|undefined} sourceConfidence Explicit entry confidence (null = none).
 * @param {object|null|undefined} legacyConfidence Deprecated alias used by older import callers.
 */
export function resolveParsedSourceConfidence(sourceConfidence, legacyConfidence) {
  if (sourceConfidence !== undefined) {
    return normalizeConfidence(sourceConfidence);
  }
  return normalizeConfidence(legacyConfidence);
}

export async function enrichIocConfidenceRows(pool, rows) {
  if (!Array.isArray(rows) || !rows.length) return rows;
  const feedDefaultBySource = new Map();
  return Promise.all(rows.map(async (row) => {
    if (normalizeConfidence(row.feed_default_confidence)) return row;
    const sourceKey = String(row.source_name || '');
    if (!feedDefaultBySource.has(sourceKey)) {
      feedDefaultBySource.set(sourceKey, await fetchFeedDefaultConfidence(pool, sourceKey));
    }
    return {
      ...row,
      feed_default_confidence: feedDefaultBySource.get(sourceKey)
    };
  }));
}

export async function buildIocConfidenceSummaryForDetails(pool, { rows, seedPublicId }) {
  const feedNamesByKey = await fetchFeedNamesByKey(pool);
  const enrichedRows = await enrichIocConfidenceRows(pool, rows);
  return buildIocConfidenceSummary({
    rows: enrichedRows,
    seedPublicId,
    feedNamesByKey
  });
}

/**
 * Resolve import-time confidence fields. Preserves analyst override on existing rows.
 * @param {object|null} existingRow
 */
export function resolveImportConfidenceFields({
  parsedSourceConfidence = null,
  feedDefaultConfidence = SYSTEM_FALLBACK_CONFIDENCE,
  existingRow = null
} = {}) {
  const sourceConfidence = normalizeConfidence(parsedSourceConfidence);
  const feedDefault = normalizeConfidence(feedDefaultConfidence) || SYSTEM_FALLBACK_CONFIDENCE;
  const analystOverride = normalizeConfidence(existingRow?.analyst_confidence_override);
  const effective = computeEffectiveConfidence({
    sourceConfidence,
    feedDefaultConfidence: feedDefault,
    analystOverride
  });

  return {
    source_confidence: sourceConfidence,
    feed_default_confidence: feedDefault,
    confidence: effective,
    analyst_confidence_override: analystOverride
  };
}

/**
 * Update confidence columns on an existing IOC row after feed re-import.
 * Preserves analyst_confidence_override when set.
 */
export async function applyIocImportConfidence(client, {
  observable,
  observableType,
  sourceName,
  parsedSourceConfidence = null
}) {
  let existing;
  try {
    const { rows } = await client.query(
      `SELECT analyst_confidence_override, confidence, source_confidence, feed_default_confidence
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

  const feedDefault = await fetchFeedDefaultConfidence(client, sourceName);
  const fields = resolveImportConfidenceFields({
    parsedSourceConfidence,
    feedDefaultConfidence: feedDefault,
    existingRow: existing
  });

  try {
    await client.query(
      `UPDATE ioc_items
       SET source_confidence = $4,
           feed_default_confidence = $5,
           confidence = $6
       WHERE observable = $1 AND observable_type = $2 AND source_name = $3
         AND analyst_confidence_override IS NULL`,
      [observable, observableType, sourceName, fields.source_confidence, fields.feed_default_confidence, fields.confidence]
    );

    if (existing.analyst_confidence_override) {
      await client.query(
        `UPDATE ioc_items
         SET source_confidence = $4,
             feed_default_confidence = $5
         WHERE observable = $1 AND observable_type = $2 AND source_name = $3`,
        [observable, observableType, sourceName, fields.source_confidence, fields.feed_default_confidence]
      );
    }
  } catch (err) {
    if (err?.code === '42703') return null;
    throw err;
  }

  return fields;
}
