import { formatUserDateTime } from './formatDate.js';

export const CONFIDENCE_OPTIONS = Object.freeze([
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' }
]);

export function confidenceBadgeStyle(value) {
  const c = String(value || 'medium').toLowerCase();
  if (c === 'high') {
    return { bg: 'rgba(127,29,29,0.28)', color: '#fca5a5', border: 'rgba(127,29,29,0.8)' };
  }
  if (c === 'medium') {
    return { bg: 'rgba(120,53,15,0.28)', color: '#fcd34d', border: 'rgba(180,83,9,0.75)' };
  }
  return { bg: 'rgba(22,101,52,0.25)', color: '#86efac', border: 'rgba(22,101,52,0.85)' };
}

export function confidenceLabel(value) {
  const c = String(value || '').trim().toLowerCase();
  if (!c) return '—';
  return c.charAt(0).toUpperCase() + c.slice(1);
}

function formatProvenanceLabel(detail) {
  if (detail?.confidence_provenance?.label) {
    return `Source: ${detail.confidence_provenance.label}`;
  }
  if (detail?.source_description) {
    return `Source: ${detail.source_description}`;
  }
  return null;
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
  const hasOverride = Boolean(detail.analyst_override)
    || detail.source === 'analyst_override'
    || detail.confidence_source === 'analyst_override';
  const badgeStyle = confidenceBadgeStyle(effective);

  let sourceLine = 'Source: —';
  if (hasOverride) {
    const who = detail.overridden_by || detail.confidence_provenance?.overridden_by || 'analyst';
    const whenRaw = detail.overridden_at || detail.confidence_provenance?.overridden_at;
    const when = whenRaw ? formatUserDateTime(whenRaw) : null;
    if (when && when !== '-') {
      sourceLine = `Source: Analyst override by ${who} at ${when}`;
    } else {
      const baseline = detail.baseline_effective || detail.source_confidence || detail.feed_default_confidence;
      const baselineLabel = confidenceLabel(baseline);
      sourceLine = `Originally ${baselineLabel}. Changed by ${who}${whenRaw ? ` on ${formatUserDateTime(whenRaw)}` : ''}.`;
    }
  } else if (detail.source === 'feed_default') {
    const feed = detail.feed_name || detail.confidence_feed_name || detail.confidence_source_name || 'feed';
    if (detail.confidence_source_scope === 'historical') {
      sourceLine = `Source: ${feed} (historical)`;
    } else {
      sourceLine = `Source: Feed default from ${feed}`;
    }
  } else if (detail.source === 'feed_entry' || detail.confidence_source === 'feed_entry') {
    const feed = detail.confidence_source_name || detail.confidence_feed_name || detail.feed_name;
    if (detail.confidence_source_scope === 'historical' && feed) {
      sourceLine = `Source: ${feed} (historical)`;
    } else {
      sourceLine = 'Source: Feed entry confidence';
    }
  } else if (detail.source === 'ioc_source_default') {
    const srcName = detail.confidence_source_name
      || detail.confidence_provenance?.source_name
      || 'source';
    sourceLine = `Source: IOC source default from ${srcName}`;
  } else if (detail.source === 'manual_entry') {
    sourceLine = 'Source: Manual entry';
  } else if (detail.source === 'system_fallback') {
    sourceLine = 'Source: System fallback';
  } else if ((detail.source === 'unknown' || detail.confidence_source === 'unknown') && !detail.effective) {
    sourceLine = 'Source: No active source';
  } else {
    const provenanceLine = formatProvenanceLabel(detail);
    if (provenanceLine) {
      sourceLine = provenanceLine;
    } else if (detail.source === 'unknown') {
      sourceLine = 'Source: Unknown';
    }
  }

  const reasonLine = hasOverride && detail.override_reason
    ? `Reason: ${detail.override_reason}`
    : null;

  const highestActiveSourceConfidence = detail.highest_active_source_confidence || null;
  const highestActiveLabel = highestActiveSourceConfidence ? confidenceLabel(highestActiveSourceConfidence) : null;

  return {
    effective,
    effectiveLabel: confidenceLabel(effective),
    hasOverride,
    sourceLine,
    overrideLine: hasOverride ? sourceLine : null,
    reasonLine,
    badgeStyle,
    sourceDescription: detail.source_description || detail.confidence_provenance?.label || null,
    highestActiveSourceConfidence,
    highestActiveLabel,
    highestActiveBadgeStyle: highestActiveSourceConfidence ? confidenceBadgeStyle(highestActiveSourceConfidence) : null
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
