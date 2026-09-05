/**
 * Helpers for Administration → TLS Certificate panel.
 */

export function formatTlsStatusLabel(status) {
  switch (String(status || '').toLowerCase()) {
    case 'active': return 'Active';
    case 'expired': return 'Expired';
    case 'expiring_soon': return 'Expiring Soon';
    case 'invalid': return 'Invalid';
    default: return status || 'Unknown';
  }
}

export function tlsStatusTone(status) {
  switch (String(status || '').toLowerCase()) {
    case 'active': return 'ok';
    case 'expiring_soon': return 'warn';
    case 'expired':
    case 'invalid':
      return 'error';
    default:
      return 'muted';
  }
}

export function canReplaceTlsCertificate(meta) {
  return meta?.can_edit === true;
}

export function describeTlsSource(source) {
  if (String(source || '').toLowerCase() === 'custom') return 'Custom';
  return 'TalonHound Generated';
}

export async function readPemFile(file) {
  if (!file) return '';
  const text = await file.text();
  return String(text || '');
}
