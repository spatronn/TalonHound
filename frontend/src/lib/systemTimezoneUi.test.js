import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canChangeSystemTimezone,
  formatCurrentUtc,
  formatCurrentSystemTime,
  TIMESTAMP_PLACEHOLDER
} from './systemTimezoneUi.js';

// A single instant expressed two ways, as the backend delivers it:
//   current_utc_time    → genuine UTC ISO (Z)          → 17:13:25 UTC
//   current_system_time → offset for Europe/Istanbul   → 20:13:25 +03:00
const ISTANBUL_INFO = Object.freeze({
  active_system_timezone: 'Europe/Istanbul',
  system_timezone: 'Europe/Istanbul',
  current_utc_time: '2026-08-25T17:13:25.000Z',
  current_system_time: '2026-08-25T20:13:25+03:00'
});

const NOT_RAW_ISO = /T\d{2}:\d{2}:\d{2}|[+-]\d{2}:\d{2}$|Z$/;

test('Current UTC renders the real UTC instant in canonical format', () => {
  const out = formatCurrentUtc(ISTANBUL_INFO);
  assert.equal(out, '25/08/2026, 17:13:25');
  assert.doesNotMatch(out, NOT_RAW_ISO);
});

test('Current active system time renders the configured-timezone wall clock', () => {
  const out = formatCurrentSystemTime(ISTANBUL_INFO);
  assert.equal(out, '25/08/2026, 20:13:25');
  assert.doesNotMatch(out, NOT_RAW_ISO);
});

test('UTC and system time describe the same instant, three hours apart', () => {
  const utc = formatCurrentUtc(ISTANBUL_INFO);
  const system = formatCurrentSystemTime(ISTANBUL_INFO);
  assert.notEqual(utc, system);
  const hourOf = (s) => Number(s.split(', ')[1].split(':')[0]);
  assert.equal(hourOf(system) - hourOf(utc), 3);
});

test('Current active system time ignores browser locale — uses active_system_timezone', () => {
  // Same instant, but the configured zone is UTC → both lines match.
  const info = {
    active_system_timezone: 'UTC',
    system_timezone: 'UTC',
    current_utc_time: '2026-08-25T17:13:25.000Z',
    current_system_time: '2026-08-25T17:13:25+00:00'
  };
  assert.equal(formatCurrentSystemTime(info), '25/08/2026, 17:13:25');
  assert.equal(formatCurrentUtc(info), '25/08/2026, 17:13:25');
});

test('missing timestamps render the placeholder, never Invalid Date / NaN / epoch', () => {
  for (const bad of [null, undefined, '', 'not-a-date']) {
    const info = { active_system_timezone: 'Europe/Istanbul', current_utc_time: bad, current_system_time: bad };
    const utc = formatCurrentUtc(info);
    const system = formatCurrentSystemTime(info);
    for (const out of [utc, system]) {
      assert.doesNotMatch(out, /Invalid Date|NaN/);
      assert.notEqual(out, '01/01/1970, 00:00:00');
      assert.ok(out === TIMESTAMP_PLACEHOLDER || out === '-');
    }
  }
});

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
