/** Sidebar account presentation helpers. */

export function userInitialsFromEmail(email) {
  const local = String(email || '').trim().split('@')[0] || '';
  if (!local) return '?';
  const parts = local.split(/[._\-\s]+/).filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0][0] || ''}${parts[1][0] || ''}`.toUpperCase();
  }
  return local.slice(0, 2).toUpperCase();
}

export function formatSidebarRoleLabel(role) {
  const r = String(role || '').trim().toLowerCase();
  if (r === 'admin' || r === 'administrator') return 'Administrator';
  if (r === 'readonly' || r === 'read-only' || r === 'read_only') return 'Read-only';
  if (r === 'analyst') return 'Analyst';
  if (!r) return 'User';
  return r.charAt(0).toUpperCase() + r.slice(1);
}
