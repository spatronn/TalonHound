import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canManageProductUpdates,
  canSeeProductUpdatesSection,
  settingsLifecycleVisibility,
  shouldFetchUpdateStatus,
  UPDATE_MANAGEMENT_DISABLED_HINT,
  UPDATE_MANAGEMENT_RESTRICTED_MESSAGE
} from './updateManagementUi.js';

const SYS = Object.freeze({ authState: 'authed', isSystemAdmin: true, isAdmin: true });
const NORMAL_ADMIN = Object.freeze({ authState: 'authed', isSystemAdmin: false, isAdmin: true });
const LOADING_DEFAULTS = Object.freeze({ authState: 'loading', isSystemAdmin: false, isAdmin: true });
const LOADING_STALE_TRUE = Object.freeze({ authState: 'loading', isSystemAdmin: true, isAdmin: true });
const READONLY = Object.freeze({ authState: 'authed', isSystemAdmin: false, isAdmin: false });

test('System Administrator sees Updates controls after auth is known', () => {
  const v = settingsLifecycleVisibility(SYS);
  assert.equal(v.showInstalledVersion, true);
  assert.equal(v.showUpdatesSection, true);
  assert.equal(v.showCheckForUpdates, true);
  assert.equal(v.checkForUpdatesEnabled, true);
  assert.equal(v.showUpgradeCliInstruction, true);
  assert.equal(v.showReleaseNotesControl, true);
  assert.equal(v.showUpdateAvailabilityNotice, true);
  assert.equal(v.fetchUpdateStatus, true);
  assert.equal(v.updatesReadOnly, false);
  assert.equal(shouldFetchUpdateStatus(SYS), true);
  assert.equal(canManageProductUpdates(SYS), true);
  assert.equal(canSeeProductUpdatesSection(SYS), true);
});

test('normal Administrator sees Updates section read-only — no privileged fetch', () => {
  const v = settingsLifecycleVisibility(NORMAL_ADMIN);
  assert.equal(v.showInstalledVersion, true);
  assert.equal(v.showUpdatesSection, true);
  assert.equal(v.showCheckForUpdates, true);
  assert.equal(v.checkForUpdatesEnabled, false);
  assert.equal(v.showUpgradeCliInstruction, false);
  assert.equal(v.showReleaseNotesControl, false);
  assert.equal(v.showUpdateAvailabilityNotice, false);
  assert.equal(v.fetchUpdateStatus, false);
  assert.equal(v.updatesReadOnly, true);
  assert.equal(shouldFetchUpdateStatus(NORMAL_ADMIN), false);
  assert.equal(canManageProductUpdates(NORMAL_ADMIN), false);
  assert.equal(canSeeProductUpdatesSection(NORMAL_ADMIN), true);
  assert.match(UPDATE_MANAGEMENT_RESTRICTED_MESSAGE, /System Administrator/);
  assert.match(UPDATE_MANAGEMENT_DISABLED_HINT, /System Administrator can manage updates/);
});

test('loading auth state never enables management or fetches (no privilege flicker)', () => {
  assert.equal(canManageProductUpdates(LOADING_DEFAULTS), false);
  assert.equal(canManageProductUpdates(LOADING_STALE_TRUE), false);
  assert.equal(canManageProductUpdates({ authState: 'anon', isSystemAdmin: true }), false);
  assert.equal(canManageProductUpdates(null), false);
  assert.equal(canManageProductUpdates({}), false);
  assert.equal(shouldFetchUpdateStatus(LOADING_DEFAULTS), false);
  assert.equal(canSeeProductUpdatesSection(LOADING_DEFAULTS), false);
  assert.equal(canSeeProductUpdatesSection(LOADING_STALE_TRUE), false);
  assert.equal(settingsLifecycleVisibility(LOADING_DEFAULTS).showInstalledVersion, true);
  assert.equal(settingsLifecycleVisibility(LOADING_DEFAULTS).showUpdatesSection, false);
  assert.equal(settingsLifecycleVisibility(LOADING_DEFAULTS).checkForUpdatesEnabled, false);
  assert.equal(settingsLifecycleVisibility(LOADING_DEFAULTS).fetchUpdateStatus, false);
});

test('role=admin and other identity fields do not grant update management', () => {
  assert.equal(
    canManageProductUpdates({
      authState: 'authed',
      isAdmin: true,
      isSystemAdmin: false,
      userId: 1,
      userEmail: 'admin@talonhound.local',
      role: 'admin'
    }),
    false
  );
  assert.equal(canManageProductUpdates(READONLY), false);
  assert.equal(canSeeProductUpdatesSection(READONLY), false);
  assert.equal(settingsLifecycleVisibility(READONLY).showUpdatesSection, false);
  assert.equal(canManageProductUpdates({ authState: 'authed', isSystemAdmin: 'true' }), false);
});
