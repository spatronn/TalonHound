import { resolveIocListTimestamp } from './iocListTimestampPresentation.js';
import { formatUserDateTime } from './formatDate.js';

export const IOC_DETAIL_TIMESTAMP_CARDS = Object.freeze({
  imported: Object.freeze({
    key: 'imported',
    label: 'Inserted into Platform',
    description: 'First time this IOC was inserted into TalonHound.',
    icon: 'download'
  }),
  firstSeen: Object.freeze({
    key: 'first_seen',
    label: 'First seen in source',
    description: 'Earliest known source observation of this IOC.',
    icon: 'calendar'
  }),
  lastSeen: Object.freeze({
    key: 'last_seen',
    label: 'Last seen in source',
    description: 'Most recent source observation of this IOC, even if source metadata did not change.',
    icon: 'clock'
  })
});

/** Format detail timestamps; empty → em dash (never invent fallbacks). */
export function formatIocDetailDateTime(value) {
  if (value == null || value === '') return '—';
  const formatted = formatUserDateTime(value);
  return !formatted || formatted === '-' ? '—' : formatted;
}

/** Canonical platform insert from detail summary (API field: imported_at). */
export function resolveIocDetailImportedAt(summary = {}) {
  return resolveIocListTimestamp(summary);
}

function sameInstant(a, b) {
  if (a == null || b == null) return false;
  const ta = new Date(a).getTime();
  const tb = new Date(b).getTime();
  return Number.isFinite(ta) && Number.isFinite(tb) && ta === tb;
}

/**
 * Source footer context for a timestamp card.
 * Single matching source → its name; multiple → Across N sources; none → null.
 */
export function resolveTimestampSourceContext({
  value,
  sources = [],
  pick,
  emptyLabel = null
} = {}) {
  if (value == null || value === '') return emptyLabel;
  const list = Array.isArray(sources) ? sources : [];
  const matches = list.filter((src) => sameInstant(pick?.(src), value));
  if (matches.length === 1) {
    const name = String(matches[0]?.name || '').trim();
    return name ? `Source: ${name}` : emptyLabel;
  }
  if (matches.length > 1) {
    return `Across ${matches.length} sources`;
  }
  if (list.length === 1) {
    const name = String(list[0]?.name || '').trim();
    return name ? `Source: ${name}` : emptyLabel;
  }
  if (list.length > 1) return `Across ${list.length} sources`;
  return emptyLabel;
}

/**
 * Build the IOC Timestamps cards for Overview.
 * @param {object|null} summary
 * @param {object[]} activeSources
 * @param {object[]} historicalSources
 */
export function buildIocDetailTimestampCards(summary, activeSources = [], historicalSources = []) {
  const sources = [...(activeSources || []), ...(historicalSources || [])];
  const importedAt = resolveIocDetailImportedAt(summary || {});
  const firstSeen = summary?.first_seen_at ?? null;
  const lastSeen = summary?.last_seen_in_source ?? null;

  // Analyst lifecycle cards: Inserted / First seen / Last seen only.
  // last_changed_in_source remains on the API for compatibility but is not rendered here.
  return [
    {
      ...IOC_DETAIL_TIMESTAMP_CARDS.imported,
      value: importedAt,
      display: formatIocDetailDateTime(importedAt),
      context: 'Source: System'
    },
    {
      ...IOC_DETAIL_TIMESTAMP_CARDS.firstSeen,
      value: firstSeen,
      display: formatIocDetailDateTime(firstSeen),
      context: resolveTimestampSourceContext({
        value: firstSeen,
        sources,
        pick: (s) => s.first_seen_at
      })
    },
    {
      ...IOC_DETAIL_TIMESTAMP_CARDS.lastSeen,
      value: lastSeen,
      display: formatIocDetailDateTime(lastSeen),
      context: resolveTimestampSourceContext({
        value: lastSeen,
        sources,
        pick: (s) => s.last_seen_in_source || s.last_seen_at || null
      })
    }
  ];
}

/**
 * Membership kebab action availability for an active feed source row.
 * Invalid actions stay visible but disabled.
 */
export function getSourceMembershipActionStates(src = {}) {
  const isFeed = src.source_type === 'feed';
  const actionsEnabled = Boolean(src.actions_enabled) && isFeed;
  const status = String(src.status || 'active').toLowerCase();
  const isActive = actionsEnabled && status === 'active' && !src.purged_at;
  const hasOverride = Boolean(src.override_enabled);

  return {
    reactivate_membership: {
      type: 'reactivate_membership',
      label: 'Reactivate source',
      enabled: actionsEnabled && !isActive
    },
    custom_expire_membership: {
      type: 'custom_expire_membership',
      label: 'Custom expire',
      enabled: isActive
    },
    expire_membership: {
      type: 'expire_membership',
      label: 'Expire source',
      enabled: isActive,
      danger: true
    },
    clear_membership_override: {
      type: 'clear_membership_override',
      label: 'Clear override',
      enabled: isActive && hasOverride
    }
  };
}

/**
 * Row action for an active manual/custom source: detach it from the IOC. Distinct
 * from feed lifecycle actions and from global IOC deletion. Only offered for
 * removable (active) manual sources; feed / historical sources never get it.
 */
export function getManualSourceActionStates(src = {}) {
  const isManual = src.source_type === 'manual';
  const removable = isManual && Boolean(src.removable);
  return {
    remove_manual_source: {
      type: 'remove_manual_source',
      label: 'Remove from source',
      enabled: removable,
      danger: true
    }
  };
}

export function listSourceMembershipActions(src) {
  if (src?.source_type === 'manual') {
    const manual = getManualSourceActionStates(src);
    return [manual.remove_manual_source];
  }
  const states = getSourceMembershipActionStates(src);
  return [
    states.reactivate_membership,
    states.custom_expire_membership,
    states.expire_membership,
    states.clear_membership_override
  ];
}
