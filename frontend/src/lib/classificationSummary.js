/**
 * IOC threat classification display / modal helpers.
 *
 * Effective set (server + client):
 *   (feed classifications − analyst suppressions) ∪ analyst additions
 */

/**
 * @param {Array<{value: string, label?: string}|string>|null|undefined} classifications
 * @returns {Array<{value: string, label: string|null}>}
 */
export function normalizeVisibleClassifications(classifications) {
  const list = Array.isArray(classifications) ? classifications : [];
  const seen = new Set();
  const result = [];
  for (const item of list) {
    const value = (typeof item === 'string' ? item : item?.value) || '';
    if (!value || value.toLowerCase() === 'unknown') continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const obj = typeof item === 'object' && item !== null ? item : null;
    result.push({
      value,
      label: obj ? (obj.label ?? null) : null,
      origin: obj?.origin || null,
      origins: Array.isArray(obj?.origins) ? obj.origins : null,
      source_name: obj?.source_name || null,
      active: obj?.active
    });
  }
  return result;
}

export function getFeedThreatClassifications(summary) {
  if (Array.isArray(summary?.feed_threat_classifications) && summary.feed_threat_classifications.length) {
    return normalizeVisibleClassifications(summary.feed_threat_classifications);
  }
  return normalizeVisibleClassifications(summary?.feed_intelligence?.classifications);
}

export function getAnalystThreatClassifications(summary) {
  if (Array.isArray(summary?.analyst_threat_classifications)) {
    return normalizeVisibleClassifications(summary.analyst_threat_classifications);
  }
  // Legacy: threat_classifications was analyst-only before effective bundles
  if (Array.isArray(summary?.effective_threat_classifications)) {
    return normalizeVisibleClassifications(
      (summary.effective_threat_classifications || []).filter((c) => {
        const origins = c?.origins || (c?.origin ? [c.origin] : []);
        return origins.includes('analyst') && !origins.includes('feed');
      })
    );
  }
  return normalizeVisibleClassifications(summary?.threat_classifications);
}

export function getSuppressedThreatClassifications(summary) {
  return normalizeVisibleClassifications(summary?.suppressed_threat_classifications);
}

/**
 * Card display: prefer server effective set; fall back to client-side merge for older payloads.
 */
export function getEffectiveThreatClassifications(summary) {
  if (Array.isArray(summary?.effective_threat_classifications)) {
    return normalizeVisibleClassifications(summary.effective_threat_classifications);
  }
  const feed = getFeedThreatClassifications(summary);
  const suppressed = new Set(
    getSuppressedThreatClassifications(summary).map((c) => String(c.value).toLowerCase())
  );
  const visibleFeed = feed.filter((c) => !suppressed.has(String(c.value).toLowerCase()));
  const analyst = getAnalystThreatClassifications(summary);
  const seen = new Set(visibleFeed.map((c) => String(c.value).toLowerCase()));
  const merged = [...visibleFeed];
  for (const item of analyst) {
    const key = String(item.value).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push({ ...item, origin: item.origin || 'analyst' });
  }
  return merged;
}

/** @deprecated use getEffectiveThreatClassifications */
export function getDisplayedThreatClassifications(summary) {
  return getEffectiveThreatClassifications(summary);
}

/** @deprecated feed-only extras without suppress awareness */
export function getFeedOnlyThreatClassifications(summary) {
  const effectiveKeys = new Set(
    getAnalystThreatClassifications(summary).map((c) => String(c.value).toLowerCase())
  );
  return getFeedThreatClassifications(summary).filter(
    (c) => !effectiveKeys.has(String(c.value).toLowerCase())
  );
}

export function editableThreatClassificationSlugs(summary) {
  return getEffectiveThreatClassifications(summary).map((c) => c.value);
}

/**
 * Modal view-model: checked = effective; feed provenance for labels; suppressed feed still listed unchecked.
 */
export function buildThreatClassificationModalState(summary) {
  const feed = getFeedThreatClassifications(summary);
  const analyst = getAnalystThreatClassifications(summary);
  const suppressed = getSuppressedThreatClassifications(summary);
  const effective = getEffectiveThreatClassifications(summary);
  const editableSlugs = effective.map((c) => c.value);

  const byValue = new Map();
  for (const item of feed) {
    byValue.set(String(item.value).toLowerCase(), {
      value: item.value,
      label: item.label,
      feed: true,
      source_name: item.source_name || null,
      suppressed: false
    });
  }
  for (const item of suppressed) {
    const key = String(item.value).toLowerCase();
    const prev = byValue.get(key) || {
      value: item.value,
      label: item.label,
      feed: true,
      source_name: item.source_name || null
    };
    byValue.set(key, { ...prev, suppressed: true, feed: true });
  }
  for (const item of analyst) {
    const key = String(item.value).toLowerCase();
    const prev = byValue.get(key);
    if (prev) {
      byValue.set(key, { ...prev, analyst: true });
    } else {
      byValue.set(key, {
        value: item.value,
        label: item.label,
        analyst: true,
        feed: false,
        source_name: null,
        suppressed: false
      });
    }
  }

  return {
    editableSlugs,
    feedOnly: [], // no longer a separate read-only list
    provenanceByValue: Object.fromEntries(byValue),
    presentValues: [
      ...editableSlugs,
      ...suppressed.map((c) => c.value)
    ]
  };
}

/**
 * Visible label for IOC Details classification badges (no Feed/Analyst provenance text).
 * @param {{ value?: string, label?: string|null }} classification
 * @param {(slug: string) => string} [fallbackLabel]
 */
export function formatThreatClassificationBadgeLabel(classification, fallbackLabel = null) {
  const value = String(classification?.value || '').trim();
  if (classification?.label) return String(classification.label);
  if (typeof fallbackLabel === 'function' && value) return fallbackLabel(value);
  return value || 'Unknown';
}

export function buildThreatClassificationSavePayload(draftSlugs) {
  const slugs = (Array.isArray(draftSlugs) ? draftSlugs : [])
    .map((s) => String(s || '').trim())
    .filter((s) => s && s.toLowerCase() !== 'unknown');
  const unique = [...new Set(slugs)];
  return {
    classifications: unique,
    threat_classifications: unique,
    effective_threat_classifications: unique
  };
}

/**
 * Merge dictionary options with feed/provenance entries so feed-only slugs appear as checkboxes.
 */
export function mergeThreatClassificationModalOptions(options, summary) {
  const state = buildThreatClassificationModalState(summary);
  const all = [...(options || [])];
  for (const meta of Object.values(state.provenanceByValue || {})) {
    if (!meta?.value) continue;
    if (!all.some((o) => o.value === meta.value)) {
      all.push({
        value: meta.value,
        label: meta.label || meta.value,
        provenance: meta
      });
    } else {
      const idx = all.findIndex((o) => o.value === meta.value);
      if (idx >= 0) all[idx] = { ...all[idx], provenance: meta };
    }
  }
  return all;
}
