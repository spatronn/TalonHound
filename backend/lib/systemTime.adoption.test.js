import test from 'node:test';
import assert from 'node:assert/strict';
import {
  adoptSystemTimezoneFromBootstrap,
  clearSystemTimeCache,
  readBootstrapTimezoneCandidate
} from '../lib/systemTime.js';

/**
 * Lightweight in-memory stand-in for pool+client used by adoptSystemTimezoneFromBootstrap.
 */
function createAdoptionHarness({ existing = true, initial = {} } = {}) {
  const state = {
    initial_setup_completed: false,
    timezone_configuration_required: false,
    active_system_timezone: null,
    pending_system_timezone: null,
    timezone_restart_required: false,
    timezone_config_version: 0,
    active_timezone_config_version: 0,
    adoption_source: null,
    ...initial
  };

  const client = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('BEGIN') || s.includes('COMMIT') || s.includes('ROLLBACK') || s.includes('pg_advisory')) {
        return { rows: [] };
      }
      if (s.includes('to_regclass')) return { rows: [{ reg: 'system_settings' }] };
      if (s.includes('INSERT INTO system_settings')) return { rows: [] };
      if (s.includes('FROM users')) return { rows: existing ? [{ '?column?': 1 }] : [] };
      if (s.includes('FROM ioc_items')) return { rows: [] };
      if (s.includes('FROM system_settings') && s.includes('SELECT')) {
        return {
          rows: [{
            ...state,
            initial_setup_completed_at: null,
            timezone_change_requested_at: null,
            timezone_change_requested_by: null,
            timezone_promoted_at: null,
            timezone_updated_at: null,
            timezone_updated_by: null
          }]
        };
      }
      if (s.includes('timezone_configuration_required = TRUE')) {
        state.timezone_configuration_required = true;
        state.initial_setup_completed = false;
        state.active_system_timezone = null;
        return { rows: [] };
      }
      if (s.includes('active_system_timezone = $2') && s.includes('adoption_source = $3')) {
        // only when incomplete
        if (state.initial_setup_completed) return { rows: [] };
        state.active_system_timezone = params[1];
        state.adoption_source = params[2];
        state.initial_setup_completed = true;
        state.timezone_configuration_required = false;
        state.timezone_config_version = 1;
        state.active_timezone_config_version = 1;
        return { rows: [] };
      }
      if (s.includes('timezone_configuration_required = FALSE') && s.includes('initial_setup_completed = FALSE')) {
        state.timezone_configuration_required = false;
        return { rows: [] };
      }
      return { rows: [] };
    },
    release() {}
  };

  const pool = {
    async connect() { return client; },
    async query(sql, params) { return client.query(sql, params); }
  };

  return { pool, state };
}

test('empty install stays setup-required (no UTC adoption)', async () => {
  clearSystemTimeCache();
  const { pool, state } = createAdoptionHarness({ existing: false });
  const result = await adoptSystemTimezoneFromBootstrap(pool, {
    env: {},
    logger: { info() {}, warn() {} }
  });
  assert.equal(result.status, 'fresh_setup_required');
  assert.equal(state.initial_setup_completed, false);
  assert.equal(state.active_system_timezone, null);
});

test('existing install + SYSTEM_TIMEZONE=Europe/Istanbul adopts Istanbul', async () => {
  clearSystemTimeCache();
  const { pool, state } = createAdoptionHarness({ existing: true });
  const result = await adoptSystemTimezoneFromBootstrap(pool, {
    env: { SYSTEM_TIMEZONE: 'Europe/Istanbul' },
    logger: { info() {}, warn() {} }
  });
  assert.equal(result.status, 'adopted');
  assert.equal(state.active_system_timezone, 'Europe/Istanbul');
  assert.equal(state.initial_setup_completed, true);
  assert.match(state.adoption_source, /bootstrap:SYSTEM_TIMEZONE/);
});

test('existing install + SYSTEM_TIMEZONE=Europe/London adopts London', async () => {
  clearSystemTimeCache();
  const { pool, state } = createAdoptionHarness({ existing: true });
  const result = await adoptSystemTimezoneFromBootstrap(pool, {
    env: { SYSTEM_TIMEZONE: 'Europe/London' },
    logger: { info() {}, warn() {} }
  });
  assert.equal(result.status, 'adopted');
  assert.equal(state.active_system_timezone, 'Europe/London');
});

test('existing install + no env does not fall back to UTC', async () => {
  clearSystemTimeCache();
  const { pool, state } = createAdoptionHarness({ existing: true });
  const result = await adoptSystemTimezoneFromBootstrap(pool, {
    env: {},
    logger: { info() {}, warn() {} }
  });
  assert.equal(result.status, 'configuration_required');
  assert.equal(state.active_system_timezone, null);
  assert.equal(state.timezone_configuration_required, true);
  assert.notEqual(state.active_system_timezone, 'UTC');
});

test('existing install + invalid bootstrap → configuration required', async () => {
  clearSystemTimeCache();
  const { pool, state } = createAdoptionHarness({ existing: true });
  const result = await adoptSystemTimezoneFromBootstrap(pool, {
    env: { SYSTEM_TIMEZONE: 'UTC+3' },
    logger: { info() {}, warn() {} }
  });
  assert.equal(result.status, 'configuration_required');
  assert.equal(state.timezone_configuration_required, true);
});

test('bootstrap adoption is idempotent and does not overwrite DB timezone', async () => {
  clearSystemTimeCache();
  const { pool, state } = createAdoptionHarness({
    existing: true,
    initial: {
      initial_setup_completed: true,
      active_system_timezone: 'Europe/Istanbul',
      adoption_source: 'initial_setup',
      timezone_config_version: 1,
      active_timezone_config_version: 1
    }
  });
  const result = await adoptSystemTimezoneFromBootstrap(pool, {
    env: { SYSTEM_TIMEZONE: 'Europe/London' },
    logger: { info() {}, warn() {} }
  });
  assert.equal(result.status, 'unchanged');
  assert.equal(state.active_system_timezone, 'Europe/Istanbul');
});

test('readBootstrap never invents UTC from empty env', () => {
  assert.equal(readBootstrapTimezoneCandidate({}).timezone, null);
});
