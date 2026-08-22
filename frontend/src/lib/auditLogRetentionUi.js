/**
 * Pure helpers for the Audit Log Retention settings control.
 *
 * "Keep forever" is represented as `null` retention days, matching the backend
 * (system_settings.audit_log_retention_days IS NULL). Kept framework-free so the
 * destructive-reduction logic and validation are unit-testable without a DOM.
 */

export const AUDIT_RETENTION_KEEP_FOREVER = 'keep_forever';
export const AUDIT_RETENTION_CUSTOM = 'custom';

/** Preset day choices offered in the dropdown (mirrors backend presets). */
export const AUDIT_RETENTION_PRESETS = Object.freeze([90, 180, 365, 730]);

/** Sanity cap mirrored from the backend for immediate client-side feedback. */
export const AUDIT_RETENTION_MAX_DAYS = 36500;

/**
 * Map a stored retention value (days | null) to the dropdown selection token.
 * @param {number|null} days
 * @param {number[]} [presets]
 * @returns {string} 'keep_forever' | '<preset>' | 'custom'
 */
export function retentionSelectionFromDays(days, presets = AUDIT_RETENTION_PRESETS) {
  if (days == null) return AUDIT_RETENTION_KEEP_FOREVER;
  if (presets.includes(Number(days))) return String(days);
  return AUDIT_RETENTION_CUSTOM;
}

/**
 * Human-readable description of a retention value.
 * @param {number|null} days
 */
export function describeRetention(days) {
  if (days == null) return 'Keep forever';
  const n = Number(days);
  return `${n} day${n === 1 ? '' : 's'}`;
}

/**
 * Whether moving from `prevDays` to `nextDays` is a destructive reduction that
 * can permanently delete existing audit logs on the next cleanup cycle.
 *
 * - Keep forever (null) -> finite N            : destructive
 * - finite P -> finite N where N < P           : destructive
 * - finite -> Keep forever (null)              : NOT destructive (increase)
 * - finite P -> finite N where N >= P          : NOT destructive
 *
 * @param {number|null} prevDays
 * @param {number|null} nextDays
 */
export function isRetentionReduction(prevDays, nextDays) {
  if (nextDays == null) return false; // Keep forever never reduces retention
  if (prevDays == null) return true;  // finite window after "keep forever" is destructive
  return Number(nextDays) < Number(prevDays);
}

/**
 * Validate a custom day value entered in the UI. Mirrors the backend contract:
 * positive integer, no zero/negatives/decimals/non-numeric, within the cap.
 * @param {string|number} raw
 * @param {number} [max]
 * @returns {{ ok: true, days: number } | { ok: false, error: string }}
 */
export function validateCustomDays(raw, max = AUDIT_RETENTION_MAX_DAYS) {
  if (typeof raw === 'number') {
    if (!Number.isInteger(raw)) return { ok: false, error: 'Enter a whole number of days (no decimals).' };
    if (raw <= 0) return { ok: false, error: 'Enter a number of days greater than zero.' };
    if (raw > max) return { ok: false, error: `Enter at most ${max} days.` };
    return { ok: true, days: raw };
  }
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) return { ok: false, error: 'Enter a number of days.' };
  if (!/^\d+$/.test(trimmed)) return { ok: false, error: 'Enter a positive whole number of days.' };
  const days = Number(trimmed);
  if (days <= 0) return { ok: false, error: 'Enter a number of days greater than zero.' };
  if (days > max) return { ok: false, error: `Enter at most ${max} days.` };
  return { ok: true, days };
}

/**
 * Resolve the effective target retention (days | null) from a selection token
 * and the custom-input value. Returns validation errors for the custom case.
 * @param {string} selection
 * @param {string|number} customRaw
 * @param {number} [max]
 * @returns {{ ok: true, days: number|null } | { ok: false, error: string }}
 */
export function resolveTargetDays(selection, customRaw, max = AUDIT_RETENTION_MAX_DAYS) {
  if (selection === AUDIT_RETENTION_KEEP_FOREVER) return { ok: true, days: null };
  if (selection === AUDIT_RETENTION_CUSTOM) {
    const v = validateCustomDays(customRaw, max);
    return v.ok ? { ok: true, days: v.days } : v;
  }
  const n = Number(selection);
  if (!Number.isFinite(n) || n <= 0) return { ok: false, error: 'Select a valid retention period.' };
  return { ok: true, days: n };
}
