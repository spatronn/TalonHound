/**
 * Central effective-status helpers for IOC suppressions.
 * Matching must only use rows with effective status = active.
 */

export const SUPPRESSION_STATUS = Object.freeze({
  ACTIVE: 'active',
  DISABLED: 'disabled',
  EXPIRED: 'expired',
  DELETED: 'deleted'
});

/** SQL fragment: row participates in suppression matching */
export const EFFECTIVE_ACTIVE_SUPPRESSION_SQL = `(
  active = TRUE
  AND deleted_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW())
)`;

/** Alias-qualified fragment for queries that use table alias `s` */
export const EFFECTIVE_ACTIVE_SUPPRESSION_SQL_S = `(
  s.active = TRUE
  AND s.deleted_at IS NULL
  AND (s.expires_at IS NULL OR s.expires_at > NOW())
)`;

/**
 * @param {{ active?: boolean, expires_at?: string|Date|null, deleted_at?: string|Date|null }} row
 * @param {Date} [now]
 * @returns {'active'|'disabled'|'expired'|'deleted'}
 */
export function computeSuppressionEffectiveStatus(row, now = new Date()) {
  if (row?.deleted_at) return SUPPRESSION_STATUS.DELETED;
  if (row?.active === false) return SUPPRESSION_STATUS.DISABLED;
  const exp = row?.expires_at ? new Date(row.expires_at) : null;
  if (exp && !Number.isNaN(exp.getTime()) && exp.getTime() <= now.getTime()) {
    return SUPPRESSION_STATUS.EXPIRED;
  }
  return SUPPRESSION_STATUS.ACTIVE;
}

/**
 * Whether a suppression row currently blocks matching.
 */
export function isSuppressionEffectivelyActive(row, now = new Date()) {
  return computeSuppressionEffectiveStatus(row, now) === SUPPRESSION_STATUS.ACTIVE;
}

/**
 * SQL CASE for list API status (never returns deleted — those are filtered out).
 */
export const SUPPRESSION_STATUS_CASE_SQL = `
  CASE
    WHEN s.active = FALSE THEN 'disabled'
    WHEN s.expires_at IS NOT NULL AND s.expires_at <= NOW() THEN 'expired'
    ELSE 'active'
  END
`;

/**
 * Normalize API/UI status filter values.
 * Accepts legacy `inactive` as `disabled`.
 */
export function normalizeSuppressionStatusFilter(raw) {
  const v = String(raw || '').trim().toLowerCase();
  if (!v || v === 'all') return 'all';
  if (v === 'inactive' || v === 'disabled') return 'disabled';
  if (v === 'active' || v === 'expired') return v;
  return 'all';
}
