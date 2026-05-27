export function normalizeIocLifecycleStatus(status, { suppressionActive } = {}) {
  if (suppressionActive) return 'false_positive';
  const s = String(status || 'active').trim().toLowerCase();
  if (s === 'fp' || s === 'false_positive' || s === 'suppressed') return 'false_positive';
  if (s === 'expired') return 'expired';
  if (s === 'active') return 'active';
  if (s === 'disabled') return 'disabled';
  return s || 'unknown';
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
  fields.push({ key: 'status', label: 'Current status:', kind: 'badge', status: statusForBadge });

  if (lifecycle === 'active' && summary?.expires_at) {
    fields.push({ key: 'expires_at', label: 'Expires at:', kind: 'datetime', raw: summary.expires_at });
  } else if (lifecycle === 'expired' && summary?.expired_at) {
    fields.push({ key: 'expired_at', label: 'Expired at:', kind: 'datetime', raw: summary.expired_at });
  }

  const expirationReason = String(summary?.expiration_reason || '').trim();
  if (lifecycle !== 'false_positive' || expirationReason) {
    fields.push({
      key: 'expiration_reason',
      label: 'Expiration reason:',
      kind: 'text',
      value: expirationReason || '—'
    });
  }

  fields.push({
    key: 'manual_override',
    label: 'Manual override:',
    kind: 'text',
    value: hasOverride ? `Yes (${summary.manual_status || '—'})` : 'No'
  });

  if (!suppressionActive) {
    if (lifecycle === 'active') {
      buttons.push('custom_expire_ioc', 'expire_ioc');
      if (hasOverride) buttons.push('clear_ioc_override');
    } else if (lifecycle === 'expired') {
      buttons.push('reactivate_ioc', 'custom_expire_ioc');
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
  custom_expire_ioc: { label: 'Set custom expire date', danger: false },
  expire_ioc: { label: 'Expire IOC now', danger: true },
  clear_ioc_override: { label: 'Clear override', danger: false }
};
