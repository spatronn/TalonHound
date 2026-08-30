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
 * @param {{ status?: string, error?: string|null, automaticChecksEnabled?: boolean, latestVersion?: string|null }|null|undefined} info
 */
export function formatUpdateStatusMessage(info) {
  const status = String(info?.status || 'unknown');
  if (status === 'update_available') return 'Update available';
  if (status === 'up_to_date') return "You're up to date";
  if (status === 'development_build') {
    const latest = String(info?.latestVersion || '').trim();
    return latest
      ? `Development build — latest published release is ${latest}. Comparison is not available.`
      : 'Development build — update comparison is not available.';
  }
  if (status === 'no_release_published') {
    return 'No release is currently published for this channel.';
  }
  if (status === 'check_failed') {
    const err = String(info?.error || '').trim();
    return err ? `Update check failed: ${err}` : 'Update check failed';
  }
  if (info?.automaticChecksEnabled === false) {
    return 'Update status: Unknown (automatic checking is disabled)';
  }
  return 'Update status: Unknown';
}

/**
 * Toast / feedback copy after a manual Check for Updates.
 * @param {{ status?: string, error?: string|null, latestVersion?: string|null }|null|undefined} info
 * @returns {{ kind: 'success'|'info'|'error', message: string }}
 */
export function formatUpdateCheckFeedback(info) {
  const status = String(info?.status || 'unknown');
  if (status === 'update_available') {
    const latest = String(info?.latestVersion || '').trim();
    return {
      kind: 'success',
      message: latest ? `TalonHound ${latest} is available.` : 'Update available.'
    };
  }
  if (status === 'up_to_date') {
    return { kind: 'success', message: "You're up to date." };
  }
  if (status === 'development_build') {
    const latest = String(info?.latestVersion || '').trim();
    return {
      kind: 'info',
      message: latest
        ? `Latest published release is ${latest}. This development build cannot be compared with SemVer.`
        : 'This development build cannot be compared with SemVer. The product remains fully usable.'
    };
  }
  if (status === 'no_release_published') {
    return {
      kind: 'info',
      message: 'No release is currently published for this channel. The product remains fully usable.'
    };
  }
  if (status === 'check_failed') {
    const err = String(info?.error || '').trim();
    return {
      kind: 'error',
      message: err
        ? `${err}. The product remains fully usable.`
        : 'Update check failed. The product remains fully usable.'
    };
  }
  return {
    kind: 'info',
    message: 'Update status is unknown. The product remains fully usable.'
  };
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
