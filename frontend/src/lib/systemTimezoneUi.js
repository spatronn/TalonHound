/**
 * Pure helpers for the Settings → System Timezone control.
 *
 * Mutation permission is decided by the backend (`can_edit` from
 * GET /api/system/timezone), which resolves users.is_system_admin.
 * The frontend must not invent a separate role model.
 */

import { formatUserDateTime } from './formatDate.js';

/** Em dash placeholder for missing timestamps (never Invalid Date / NaN / epoch). */
export const TIMESTAMP_PLACEHOLDER = '—';

/**
 * Whether the Change System Timezone control should be shown.
 * @param {{ can_edit?: boolean } | null | undefined} timezoneInfo
 */
export function canChangeSystemTimezone(timezoneInfo) {
  return Boolean(timezoneInfo?.can_edit);
}

/**
 * Present `current_utc_time` (a genuine UTC instant from the backend, e.g.
 * "2026-08-25T17:13:25.000Z") in the canonical UI format, rendered in UTC so
 * the wall-clock stays the real UTC time — never the configured system zone.
 * @param {{ current_utc_time?: string|null } | null | undefined} timezoneInfo
 * @returns {string} "DD/MM/YYYY, HH:mm:ss" or the em-dash placeholder.
 */
export function formatCurrentUtc(timezoneInfo) {
  const raw = timezoneInfo?.current_utc_time;
  if (!raw) return TIMESTAMP_PLACEHOLDER;
  return formatUserDateTime(raw, 'UTC');
}

/**
 * Present `current_system_time` (an offset-bearing instant for the configured
 * system timezone, e.g. "2026-08-25T20:13:25+03:00") in the canonical UI format
 * rendered in the active system timezone. Browser timezone is never used.
 * @param {{ current_system_time?: string|null, active_system_timezone?: string|null, system_timezone?: string|null } | null | undefined} timezoneInfo
 * @returns {string} "DD/MM/YYYY, HH:mm:ss" or the em-dash placeholder.
 */
export function formatCurrentSystemTime(timezoneInfo) {
  const raw = timezoneInfo?.current_system_time;
  if (!raw) return TIMESTAMP_PLACEHOLDER;
  const tz = timezoneInfo?.active_system_timezone || timezoneInfo?.system_timezone || undefined;
  return formatUserDateTime(raw, tz);
}
