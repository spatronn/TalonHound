/**
 * Helpers for Administration → Updates status display.
 */

/** @param {string|null|undefined} channel */
export function formatReleaseChannelLabel(channel) {
  const value = String(channel || '').trim().toLowerCase();
  if (!value) return '—';
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/**
 * @param {{ status?: string, error?: string|null, automaticChecksEnabled?: boolean }|null|undefined} info
 */
export function formatUpdateStatusMessage(info) {
  const status = String(info?.status || 'unknown');
  if (status === 'update_available') return 'Update available';
  if (status === 'up_to_date') return "You're up to date";
  if (info?.automaticChecksEnabled === false) {
    return 'Update status: Unknown (automatic checking is disabled)';
  }
  return 'Update status: Unknown';
}

/**
 * @param {{ status?: string, latestVersion?: string|null, currentVersion?: string|null }|null|undefined} info
 */
export function formatUpdateAvailabilityNotice(info) {
  if (String(info?.status || '') !== 'update_available') return null;
  const latest = String(info?.latestVersion || '').trim();
  if (!latest) return null;
  return `TalonHound ${latest} is available.`;
}
