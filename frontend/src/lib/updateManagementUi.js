/**
 * Settings → Updates visibility vs management capability.
 *
 * Product update *management* is System Administrator only
 * (users.is_system_admin via /api/auth/me isSystemAdmin). Role=admin is not
 * sufficient. Username, email, user id, and other admin permissions must not
 * be used as a proxy.
 *
 * The Updates *section* is discoverable to any authenticated Administrator so
 * the product feature is visible; management actions stay gated.
 *
 * Authorization state is asynchronous. Privileged requests and enabled
 * controls require System Administrator status to be positively known.
 */

/** Visible copy when an Administrator cannot manage updates. */
export const UPDATE_MANAGEMENT_RESTRICTED_MESSAGE =
  'Update management is restricted to the System Administrator.';

/** Tooltip / title for disabled update-management controls. */
export const UPDATE_MANAGEMENT_DISABLED_HINT =
  'Only the System Administrator can manage updates.';

/**
 * @param {{ authState?: string, isSystemAdmin?: boolean } | null | undefined} session
 */
export function canManageProductUpdates(session) {
  if (!session || session.authState !== 'authed') return false;
  return session.isSystemAdmin === true;
}

/**
 * Whether Settings should show the Updates section (discoverability).
 * Authenticated Administrators (role=admin) see it; management stays separate.
 * @param {{ authState?: string, isAdmin?: boolean } | null | undefined} session
 */
export function canSeeProductUpdatesSection(session) {
  if (!session || session.authState !== 'authed') return false;
  return session.isAdmin === true;
}

/**
 * Whether the frontend may call GET /api/system/updates.
 * Unauthorized callers must not fire the request and ignore a 403.
 * @param {{ authState?: string, isSystemAdmin?: boolean } | null | undefined} session
 */
export function shouldFetchUpdateStatus(session) {
  return canManageProductUpdates(session);
}

/**
 * @param {{ authState?: string, isSystemAdmin?: boolean, isAdmin?: boolean } | null | undefined} session
 */
export function settingsLifecycleVisibility(session) {
  const manage = canManageProductUpdates(session);
  const see = canSeeProductUpdatesSection(session);
  return {
    showInstalledVersion: true,
    showUpdatesSection: see,
    showCheckForUpdates: see,
    checkForUpdatesEnabled: manage,
    showUpgradeCliInstruction: manage,
    showReleaseNotesControl: manage,
    showUpdateAvailabilityNotice: manage,
    fetchUpdateStatus: manage,
    updatesReadOnly: see && !manage
  };
}
