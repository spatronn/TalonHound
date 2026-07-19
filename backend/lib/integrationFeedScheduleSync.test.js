import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getUsomFullReconciliationScheduleConfig,
  syncIntegrationFeedSchedules
} from './integrationFeedScheduleSync.js';

function mockPool(rows) {
  return {
    async query(sql) {
      if (String(sql).includes('custom_threat_feeds')) return { rows: [] };
      return { rows };
    }
  };
}

function mockQueue(repeatables = []) {
  const added = [];
  const removed = [];
  return {
    added,
    removed,
    async getRepeatableJobs() { return repeatables; },
    async add(name, data, options) {
      added.push({ name, data, options });
      return { id: options.jobId };
    },
    async removeRepeatableByKey(key) { removed.push(key); }
  };
}

test('USOM gets stable incremental and weekly full schedule identities', async () => {
  const previous = {
    enabled: process.env.USOM_FULL_RECONCILIATION_ENABLED,
    cron: process.env.USOM_FULL_RECONCILIATION_CRON,
    timezone: process.env.USOM_FULL_RECONCILIATION_TIMEZONE
  };
  delete process.env.USOM_FULL_RECONCILIATION_ENABLED;
  delete process.env.USOM_FULL_RECONCILIATION_CRON;
  delete process.env.USOM_FULL_RECONCILIATION_TIMEZONE;
  try {
    const queue = mockQueue();
    const result = await syncIntegrationFeedSchedules(
      mockPool([
        { key: 'usom-trcert', schedule_cron: '0 * * * *' },
        { key: 'et-blockrules', schedule_cron: '0 * * * *' }
      ]),
      queue,
      { logPrefix: '[test]' }
    );

    assert.deepEqual(result, { active: 2, schedules: 3 });
    const usom = queue.added.filter((entry) => entry.data.integration_key === 'usom-trcert');
    assert.equal(usom.length, 2);
    assert.deepEqual(
      usom.map((entry) => entry.options.jobId).sort(),
      ['usom-trcert-full-reconciliation-scheduled', 'usom-trcert-scheduled']
    );
    const full = usom.find((entry) => entry.data.run_mode === 'full_reconciliation');
    assert.equal(full.data.triggeredBy, 'scheduler:full_reconciliation');
    assert.deepEqual(full.options.repeat, {
      pattern: '0 3 * * 0',
      tz: 'Europe/Istanbul',
      key: 'integration-schedule:usom-trcert::full_reconciliation'
    });
    const incremental = usom.find((entry) => entry.data.run_mode === 'incremental');
    assert.equal(incremental.options.repeat.key, 'integration-schedule:usom-trcert::incremental');

    const blockrules = queue.added.find((entry) => entry.data.integration_key === 'et-blockrules');
    assert.equal(blockrules.options.jobId, 'et-blockrules-scheduled');
    assert.equal(blockrules.data.run_mode, 'incremental');
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      const envKey = key === 'enabled'
        ? 'USOM_FULL_RECONCILIATION_ENABLED'
        : key === 'cron'
          ? 'USOM_FULL_RECONCILIATION_CRON'
          : 'USOM_FULL_RECONCILIATION_TIMEZONE';
      if (value == null) delete process.env[envKey];
      else process.env[envKey] = value;
    }
  }
});

test('full reconciliation schedule can be disabled without affecting incremental', async () => {
  const config = getUsomFullReconciliationScheduleConfig({
    USOM_FULL_RECONCILIATION_ENABLED: 'false'
  });
  assert.equal(config.enabled, false);

  const previous = process.env.USOM_FULL_RECONCILIATION_ENABLED;
  process.env.USOM_FULL_RECONCILIATION_ENABLED = 'false';
  try {
    const queue = mockQueue([
      {
        key: 'repeat:full',
        id: 'usom-trcert-full-reconciliation-scheduled',
        name: 'usom-import',
        pattern: '0 3 * * 0',
        tz: 'Europe/Istanbul'
      }
    ]);
    await syncIntegrationFeedSchedules(
      mockPool([{ key: 'usom-trcert', schedule_cron: '0 * * * *' }]),
      queue,
      { logPrefix: '[test]' }
    );
    assert.deepEqual(queue.removed, ['repeat:full']);
    assert.equal(queue.added.length, 1);
    assert.equal(queue.added[0].options.jobId, 'usom-trcert-scheduled');
  } finally {
    if (previous == null) delete process.env.USOM_FULL_RECONCILIATION_ENABLED;
    else process.env.USOM_FULL_RECONCILIATION_ENABLED = previous;
  }
});
