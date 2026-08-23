/**
 * Pure helpers for the Settings → System Timezone control.
 *
 * Mutation permission is decided by the backend (`can_edit` from
 * GET /api/system/timezone), which resolves users.is_system_admin.
 * The frontend must not invent a separate role model.
 */

/**
 * Whether the Change System Timezone control should be shown.
 * @param {{ can_edit?: boolean } | null | undefined} timezoneInfo
 */
export function canChangeSystemTimezone(timezoneInfo) {
  return Boolean(timezoneInfo?.can_edit);
}
