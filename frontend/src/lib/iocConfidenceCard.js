export const CONFIDENCE_OPTIONS = Object.freeze([
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' }
]);

export function confidenceBadgeStyle(value) {
  const c = String(value || 'medium').toLowerCase();
  if (c === 'high') {
    return { bg: '#fee2e2', color: '#991b1b', border: '#fecaca' };
  }
  if (c === 'medium') {
    return { bg: '#fef3c7', color: '#92400e', border: '#fde68a' };
  }
  return { bg: '#dcfce7', color: '#166534', border: '#bbf7d0' };
}

export function confidenceLabel(value) {
  const c = String(value || '').trim().toLowerCase();
  if (!c) return '—';
  return c.charAt(0).toUpperCase() + c.slice(1);
}

/**
 * @param {object|null|undefined} detail summary.confidence_detail or data.confidence
 */
export function getIocConfidencePresentation(detail) {
  if (!detail || typeof detail !== 'object') {
    return {
      effective: null,
      effectiveLabel: '—',
      hasOverride: false,
      sourceLine: 'Source: —',
      overrideLine: null,
      reasonLine: null,
      badgeStyle: confidenceBadgeStyle('medium')
    };
  }

  const effective = detail.effective || detail.confidence || null;
  const hasOverride = Boolean(detail.analyst_override);
  const badgeStyle = confidenceBadgeStyle(effective);

  let sourceLine = 'Source: —';
  if (hasOverride) {
    const baseline = detail.baseline_effective || detail.source_confidence || detail.feed_default_confidence;
    const baselineLabel = confidenceLabel(baseline);
    const who = detail.overridden_by || 'analyst';
    const when = detail.overridden_at ? new Date(detail.overridden_at).toLocaleString() : '—';
    sourceLine = `Originally ${baselineLabel}. Changed by ${who} on ${when}.`;
  } else if (detail.source === 'feed_provided') {
    sourceLine = 'Source: Feed-provided confidence';
  } else if (detail.source === 'feed_default') {
    const feed = detail.feed_name || 'feed';
    sourceLine = `Source: Feed default from ${feed}`;
  } else if (detail.source === 'system_fallback') {
    sourceLine = 'Source: System fallback';
  } else if (detail.source_description) {
    sourceLine = `Source: ${detail.source_description}`;
  }

  const reasonLine = hasOverride && detail.override_reason
    ? `Reason: ${detail.override_reason}`
    : null;

  return {
    effective,
    effectiveLabel: confidenceLabel(effective),
    hasOverride,
    sourceLine,
    overrideLine: hasOverride ? sourceLine : null,
    reasonLine,
    badgeStyle,
    sourceDescription: detail.source_description || null
  };
}

export function formatConfidenceAuditMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') return null;
  const parts = [];
  if (metadata.old_effective_confidence != null && metadata.new_effective_confidence != null) {
    parts.push(`${metadata.old_effective_confidence} → ${metadata.new_effective_confidence}`);
  }
  if (metadata.reason) parts.push(`reason: ${metadata.reason}`);
  if (metadata.feed_name) parts.push(`feed: ${metadata.feed_name}`);
  if (metadata.user) parts.push(`by: ${metadata.user}`);
  return parts.length ? parts.join(' · ') : null;
}
