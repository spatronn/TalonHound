import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertValidIanaTimezone,
  isValidIanaTimezone,
  formatTimestampWithOffset,
  getTimezoneOffsetMs,
  convertPayloadTimestamps,
  resolveScheduleTimezone,
  readBootstrapTimezoneCandidate,
  requestSystemTimezoneChange,
  promotePendingSystemTimezone,
  completeInitialSetup,
  clearSystemTimeCache,
  SystemTimeError
} from './systemTime.js';

test('assertValidIanaTimezone accepts IANA zones', () => {
  assert.equal(assertValidIanaTimezone('Europe/Istanbul'), 'Europe/Istanbul');
  assert.equal(assertValidIanaTimezone('Europe/London'), 'Europe/London');
  assert.equal(assertValidIanaTimezone('UTC'), 'UTC');
});

test('assertValidIanaTimezone rejects fixed offsets and garbage', () => {
  assert.throws(() => assertValidIanaTimezone('UTC+3'), (err) => err instanceof SystemTimeError);
  assert.throws(() => assertValidIanaTimezone('GMT+1'), (err) => err instanceof SystemTimeError);
  assert.throws(() => assertValidIanaTimezone('Not/AZone'), (err) => err.code === 'INVALID_TIMEZONE');
  assert.equal(isValidIanaTimezone('UTC+3'), false);
});

test('formatTimestampWithOffset includes offset for Europe/Istanbul (no DST)', () => {
  const out = formatTimestampWithOffset('2026-07-26T11:24:06.000Z', 'Europe/Istanbul');
  assert.equal(out, '2026-07-26T14:24:06+03:00');
});

test('formatTimestampWithOffset handles Europe/London DST', () => {
  const summer = formatTimestampWithOffset('2026-07-26T11:24:06.000Z', 'Europe/London');
  assert.equal(summer, '2026-07-26T12:24:06+01:00');
  const winter = formatTimestampWithOffset('2026-01-15T11:24:06.000Z', 'Europe/London');
  assert.equal(winter, '2026-01-15T11:24:06+00:00');
});

test('getTimezoneOffsetMs is positive east of UTC', () => {
  const ms = getTimezoneOffsetMs(new Date('2026-07-26T12:00:00.000Z'), 'Europe/Istanbul');
  assert.equal(ms, 3 * 60 * 60 * 1000);
});

test('convertPayloadTimestamps rewrites Date and ISO Z strings', () => {
  const payload = {
    created_at: new Date('2026-07-26T11:24:06.000Z'),
    note: 'keep',
    nested: { at: '2026-07-26T11:24:06.000Z' }
  };
  const out = convertPayloadTimestamps(payload, 'Europe/Istanbul');
  assert.equal(out.created_at, '2026-07-26T14:24:06+03:00');
  assert.equal(out.nested.at, '2026-07-26T14:24:06+03:00');
  assert.equal(out.note, 'keep');
});

test('resolveScheduleTimezone uses active timezone when runtime ready', () => {
  assert.equal(
    resolveScheduleTimezone({
      initial_setup_completed: true,
      timezone_configuration_required: false,
      active_system_timezone: 'Europe/London'
    }),
    'Europe/London'
  );
});

test('readBootstrapTimezoneCandidate prefers SYSTEM_TIMEZONE and never invents UTC', () => {
  assert.deepEqual(
    readBootstrapTimezoneCandidate({}),
    { timezone: null, source: null, invalid: null }
  );
  assert.equal(
    readBootstrapTimezoneCandidate({ SYSTEM_TIMEZONE: 'Europe/Istanbul' }).timezone,
    'Europe/Istanbul'
  );
  assert.equal(
    readBootstrapTimezoneCandidate({
      INTEGRATION_SCHEDULE_TIMEZONE: 'Europe/London'
    }).timezone,
    'Europe/London'
  );
  assert.equal(
    readBootstrapTimezoneCandidate({ TZ: 'Europe/Berlin' }).timezone,
    null
  );
  assert.equal(
    readBootstrapTimezoneCandidate({
      TZ: 'Europe/Berlin',
      TALONHOUND_USE_TZ_AS_SYSTEM: '1'
    }).timezone,
    'Europe/Berlin'
  );
  assert.equal(
    readBootstrapTimezoneCandidate({ SYSTEM_TIMEZONE: 'UTC+3' }).invalid,
    'UTC+3'
  );
});

function mockDb(state) {
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM system_settings') && s.includes('SELECT')) {
        return {
          rows: [{
            initial_setup_completed: state.initial_setup_completed,
            timezone_configuration_required: state.timezone_configuration_required || false,
            active_system_timezone: state.active_system_timezone,
            pending_system_timezone: state.pending_system_timezone,
            timezone_restart_required: state.timezone_restart_required || false,
            timezone_config_version: state.timezone_config_version || 1,
            active_timezone_config_version: state.active_timezone_config_version || 1,
            adoption_source: state.adoption_source || 'initial_setup',
            initial_setup_completed_at: null,
            timezone_change_requested_at: state.timezone_change_requested_at || null,
            timezone_change_requested_by: state.timezone_change_requested_by || null,
            timezone_promoted_at: null,
            timezone_updated_at: null,
            timezone_updated_by: null
          }]
        };
      }
      if (s.includes('UPDATE system_settings') && s.includes('SET pending_system_timezone = $2')) {
        state.pending_system_timezone = params[1];
        state.timezone_restart_required = true;
        state.timezone_config_version = (state.timezone_config_version || 1) + 1;
        state.timezone_change_requested_by = params[2];
        return { rows: [] };
      }
      if (s.includes('SET active_system_timezone = pending_system_timezone')) {
        if (!state.timezone_restart_required || state.pending_system_timezone !== params[1]) {
          return { rows: [] };
        }
        state.active_system_timezone = state.pending_system_timezone;
        state.pending_system_timezone = null;
        state.timezone_restart_required = false;
        state.active_timezone_config_version = state.timezone_config_version;
        return {
          rows: [{
            initial_setup_completed: true,
            timezone_configuration_required: false,
            active_system_timezone: state.active_system_timezone,
            pending_system_timezone: null,
            timezone_restart_required: false,
            timezone_config_version: state.timezone_config_version,
            active_timezone_config_version: state.active_timezone_config_version,
            adoption_source: 'initial_setup'
          }]
        };
      }
      if (s.includes('SET active_system_timezone = $2') && s.includes('initial_setup_completed = TRUE')) {
        state.active_system_timezone = params[1];
        state.initial_setup_completed = true;
        state.timezone_configuration_required = false;
        state.pending_system_timezone = null;
        state.timezone_restart_required = false;
        return { rows: [] };
      }
      return { rows: [] };
    }
  };
}

test('timezone change sets pending without changing active', async () => {
  clearSystemTimeCache();
  const state = {
    initial_setup_completed: true,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: null,
    timezone_restart_required: false,
    timezone_config_version: 1,
    active_timezone_config_version: 1
  };
  const db = mockDb(state);
  const next = await requestSystemTimezoneChange(db, 'Europe/London', {
    confirm: true,
    updatedBy: 'admin@example.com'
  });
  assert.equal(state.active_system_timezone, 'Europe/Istanbul');
  assert.equal(state.pending_system_timezone, 'Europe/London');
  assert.equal(state.timezone_restart_required, true);
  assert.equal(next.active_system_timezone, 'Europe/Istanbul');
  assert.equal(next.pending_system_timezone, 'Europe/London');
});

test('same timezone again does not create pending restart', async () => {
  clearSystemTimeCache();
  const state = {
    initial_setup_completed: true,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: null,
    timezone_restart_required: false
  };
  const next = await requestSystemTimezoneChange(mockDb(state), 'Europe/Istanbul', {
    confirm: true,
    updatedBy: 'admin@example.com'
  });
  assert.equal(next.noop, true);
  assert.equal(state.pending_system_timezone, null);
  assert.equal(state.timezone_restart_required, false);
});

test('second pending change replaces previous pending', async () => {
  clearSystemTimeCache();
  const state = {
    initial_setup_completed: true,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: 'Europe/London',
    timezone_restart_required: true,
    timezone_config_version: 2
  };
  await requestSystemTimezoneChange(mockDb(state), 'America/New_York', {
    confirm: true,
    updatedBy: 'admin@example.com'
  });
  assert.equal(state.active_system_timezone, 'Europe/Istanbul');
  assert.equal(state.pending_system_timezone, 'America/New_York');
  assert.equal(state.timezone_restart_required, true);
});

test('promotePendingSystemTimezone moves pending to active', async () => {
  clearSystemTimeCache();
  const state = {
    initial_setup_completed: true,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: 'Europe/London',
    timezone_restart_required: true,
    timezone_config_version: 3,
    active_timezone_config_version: 2
  };
  const result = await promotePendingSystemTimezone(mockDb(state));
  assert.equal(result.status, 'promoted');
  assert.equal(state.active_system_timezone, 'Europe/London');
  assert.equal(state.pending_system_timezone, null);
  assert.equal(state.timezone_restart_required, false);
});

test('promotePendingSystemTimezone is noop when restart not required', async () => {
  clearSystemTimeCache();
  const state = {
    initial_setup_completed: true,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: 'Europe/London',
    timezone_restart_required: false,
    timezone_config_version: 3,
    active_timezone_config_version: 2
  };
  const result = await promotePendingSystemTimezone(mockDb(state));
  assert.equal(result.status, 'noop');
  assert.equal(state.active_system_timezone, 'Europe/Istanbul');
  assert.equal(state.pending_system_timezone, 'Europe/London');
});

test('promotePendingSystemTimezone is noop when pending is null', async () => {
  clearSystemTimeCache();
  const state = {
    initial_setup_completed: true,
    active_system_timezone: 'UTC',
    pending_system_timezone: null,
    timezone_restart_required: true
  };
  const result = await promotePendingSystemTimezone(mockDb(state));
  assert.equal(result.status, 'noop');
  assert.equal(state.active_system_timezone, 'UTC');
});

test('resolveScheduleTimezone keeps using active while pending exists', () => {
  assert.equal(
    resolveScheduleTimezone({
      initial_setup_completed: true,
      timezone_configuration_required: false,
      active_system_timezone: 'Europe/Istanbul',
      pending_system_timezone: 'Europe/London',
      timezone_restart_required: true
    }),
    'Europe/Istanbul'
  );
});

test('completeInitialSetup activates timezone with no pending', async () => {
  clearSystemTimeCache();
  const state = {
    initial_setup_completed: false,
    active_system_timezone: null,
    pending_system_timezone: null,
    timezone_configuration_required: false
  };
  const cfg = await completeInitialSetup(mockDb(state), 'UTC', { completedBy: 'user' });
  assert.equal(state.active_system_timezone, 'UTC');
  assert.equal(state.initial_setup_completed, true);
  assert.equal(cfg.pending_system_timezone, null);
});
