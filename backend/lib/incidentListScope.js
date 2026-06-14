/** Default list scope when no date filters: all open + closed updated in last 7 days. */
export const INCIDENTS_DEFAULT_SCOPE_WHERE =
  `(a.status = 'open' OR (a.status = 'closed' AND a.updated_at >= NOW() - INTERVAL '7 days'))`;

export function incidentMatchesDefaultScope(row, nowMs = Date.now()) {
  if (String(row?.status) === 'open') return true;
  if (String(row?.status) === 'closed') {
    const updatedAt = row?.updated_at == null ? null : new Date(row.updated_at);
    if (!updatedAt || Number.isNaN(updatedAt.getTime())) return false;
    return updatedAt.getTime() >= nowMs - 7 * 24 * 60 * 60 * 1000;
  }
  return false;
}
