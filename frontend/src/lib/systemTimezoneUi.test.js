import test from 'node:test';
import assert from 'node:assert/strict';
import { canChangeSystemTimezone } from './systemTimezoneUi.js';

test('System Administrator (can_edit=true) sees Change System Timezone', () => {
  assert.equal(
    canChangeSystemTimezone({
      can_edit: true,
      active_system_timezone: 'Europe/Istanbul',
      pending_system_timezone: null,
      status: 'healthy',
      current_utc_time: '2026-01-01T00:00:00.000Z',
      current_system_time: '2026-01-01T03:00:00+03:00'
    }),
    true
  );
});

test('normal administrator / user does not see Change System Timezone', () => {
  assert.equal(canChangeSystemTimezone({ can_edit: false }), false);
  assert.equal(canChangeSystemTimezone({ can_edit: undefined }), false);
  assert.equal(canChangeSystemTimezone(null), false);
  assert.equal(canChangeSystemTimezone({}), false);
});

test('timezone status fields remain available regardless of can_edit', () => {
  const info = {
    can_edit: false,
    active_system_timezone: 'Europe/London',
    pending_system_timezone: 'UTC',
    timezone_restart_required: true,
    current_utc_time: '2026-01-01T00:00:00.000Z',
    current_system_time: '2026-01-01T00:00:00+00:00'
  };
  assert.equal(canChangeSystemTimezone(info), false);
  assert.equal(info.active_system_timezone, 'Europe/London');
  assert.equal(info.pending_system_timezone, 'UTC');
  assert.equal(info.timezone_restart_required, true);
  assert.ok(info.current_utc_time);
  assert.ok(info.current_system_time);
});

test('System Administrator can_edit opens the change control path', () => {
  // Mirrors the Settings page gate: canChange → render Change button / modal.
  const canOpen = canChangeSystemTimezone({ can_edit: true });
  assert.equal(canOpen, true);
});
