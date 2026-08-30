import { formatUserDateTime } from './formatDate.js';

export function normalizeIocLifecycleStatus(status, { suppressionActive } = {}) {
  if (suppressionActive) return 'false_positive';
  const s = String(status || 'active').trim().toLowerCase();
  if (s === 'fp' || s === 'false_positive' || s === 'suppressed') return 'false_positive';
  if (s === 'expired') return 'expired';
  if (s === 'active') return 'active';
  if (s === 'disabled') return 'disabled';
  return s || 'unknown';
}

function splitExpirationSummaryLabel(label) {
  const raw = String(label || '').trim();
  if (!raw) return { primary: null, secondary: null };
  const parts = raw.split(/\s·\s/);
  if (parts.length < 2) return { primary: raw, secondary: null };
  return { primary: parts[0], secondary: parts.slice(1).join(' · ') };
}

/**
 * Build the date-bearing secondary line for the Expiration Summary using the
 * canonical system-timezone formatter (DD/MM/YYYY, HH:mm:ss) applied to the
 * real timestamps in the payload — never the backend's truncated YYYY-MM-DD
 * label. Returns null when there is no global expiry timestamp so the caller
 * falls back to the label text (e.g. "No expiration").
 * @param {{ global_expires_at?: string|null, next_expiration_at?: string|null }|null} es
 * @returns {string|null}
 */
function buildExpirationDateSecondary(es) {
  const globalExpiresAt = es?.global_expires_at || null;
  if (!globalExpiresAt) return null;
  const nextExpirationAt = es?.next_expiration_at || null;
  if (nextExpirationAt && nextExpirationAt !== globalExpiresAt) {
    return `Next source expires ${formatUserDateTime(nextExpirationAt)}`;
  }
  return `Expires ${formatUserDateTime(globalExpiresAt)}`;
}

/**
 * @param {object|null} summary IOC details summary
 * @param {{ suppressionActive?: boolean }} opts
 * @returns {{ lifecycle: string, fields: object[], buttons: string[] }}
 */
export function getIocStatusCardPresentation(summary, { suppressionActive } = {}) {
  const lifecycle = normalizeIocLifecycleStatus(summary?.status, { suppressionActive });
  const hasOverride = Boolean(summary?.manual_status_override);
  const fields = [];
  const buttons = [];

  const statusForBadge = lifecycle === 'false_positive' ? 'false_positive' : (summary?.status || 'active');
  fields.push({
    key: 'status',
    label: 'Current Status',
    kind: 'badge',
    status: statusForBadge,
    icon: 'status'
  });

  if (lifecycle === 'active' && summary?.expires_at) {
    fields.push({
      key: 'expires_at',
      label: 'Global Expires At',
      kind: 'datetime',
      raw: summary.expires_at,
      icon: 'calendar'
    });
  } else if (lifecycle === 'active' && !summary?.expires_at) {
    fields.push({
      key: 'expires_at',
      label: 'Global Expires At',
      kind: 'text',
      value: 'No expiration',
      icon: 'calendar'
    });
  } else if (lifecycle === 'expired' && summary?.expired_at) {
    fields.push({
      key: 'expired_at',
      label: 'Expired At',
      kind: 'datetime',
      raw: summary.expired_at,
      icon: 'calendar'
    });
  } else if (lifecycle === 'expired') {
    fields.push({
      key: 'expired_at',
      label: 'Expired At',
      kind: 'text',
      value: '—',
      icon: 'calendar'
    });
  }

  const activeCount = Number(summary?.active_source_count ?? 0);
  const sourcesValue = activeCount === 1
    ? '1 active source'
    : `${activeCount} active sources`;
  fields.push({
    key: 'sources',
    label: 'Sources',
    kind: 'text',
    value: sourcesValue,
    icon: 'sources'
  });

  if (summary?.expiration_summary?.label && lifecycle === 'active') {
    const { primary, secondary } = splitExpirationSummaryLabel(summary.expiration_summary.label);
    const expirationReason = String(summary?.expiration_reason || '').trim();
    const dateSecondary = buildExpirationDateSecondary(summary.expiration_summary);
    fields.push({
      key: 'expiration_summary',
      label: 'Expiration Summary',
      kind: 'text',
      value: primary || summary.expiration_summary.label,
      secondary: expirationReason || dateSecondary || secondary || null,
      icon: 'clock'
    });
  } else if (lifecycle !== 'false_positive') {
    const expirationReason = String(summary?.expiration_reason || '').trim();
    if (expirationReason) {
      fields.push({
        key: 'expiration_summary',
        label: 'Expiration Summary',
        kind: 'text',
        value: '—',
        secondary: expirationReason,
        icon: 'clock'
      });
    }
  }

  if (summary?.reactivated_by_match_at) {
    fields.push({
      key: 'reactivated_by_match_at',
      label: 'Reactivated by match',
      kind: 'datetime',
      raw: summary.reactivated_by_match_at,
      icon: 'clock'
    });
  }

  fields.push({
    key: 'manual_override',
    label: 'Manual Override',
    kind: 'text',
    value: hasOverride ? 'Yes' : 'No',
    secondary: hasOverride ? `Status: ${summary.manual_status || '—'}` : 'No override set',
    icon: 'user'
  });

  if (!suppressionActive) {
    if (lifecycle === 'active') {
      buttons.push('custom_expire_ioc', 'expire_ioc');
      if (hasOverride) buttons.push('clear_ioc_override');
    } else if (lifecycle === 'expired') {
      buttons.push('reactivate_ioc');
      if (hasOverride) buttons.push('clear_ioc_override');
    } else if (lifecycle === 'unknown' || lifecycle === 'disabled') {
      if (hasOverride) buttons.push('clear_ioc_override');
      if (lifecycle === 'unknown' && typeof console !== 'undefined' && console.warn) {
        console.warn('[ioc-status-card] unhandled IOC lifecycle status', summary?.status);
      }
    }
  }

  return { lifecycle, fields, buttons };
}

export const IOC_STATUS_ACTION_BUTTONS = {
  reactivate_ioc: { label: 'Reactivate IOC', danger: false },
  custom_expire_ioc: { label: 'Set custom expiry', danger: false },
  expire_ioc: { label: 'Expire IOC now', danger: true },
  clear_ioc_override: { label: 'Clear override', danger: false }
};
