import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getUsomFullReconciliationScheduleConfig,
  syncIntegrationFeedSchedules,
  syncCustomThreatFeedSchedules,
  customFeedRepeatableKey,
  collectLiveScheduleIdentities,
  evaluateRepeatableStall,
  STALLED_REPEATABLE_GRACE_MS,
  CUSTOM_THREAT_FEED_JOB
} from './integrationFeedScheduleSync.js';

function mockPool(rows, customRows = []) {
  return {
    async query(sql) {
      if (String(sql).includes('custom_threat_feeds')) return { rows: customRows };
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

/** Queue mock that also exposes waiting/active/delayed live jobs for recovery tests. */
function mockRecoveryQueue(repeatables = [], live = {}) {
  const q = mockQueue(repeatables);
  q.getWaiting = async () => live.waiting || [];
  q.getActive = async () => live.active || [];
  q.getDelayed = async () => live.delayed || [];
  return q;
}

const HOUR_MS = 3600_000;
function liveJob(integrationKey, runMode = 'incremental') {
  return { data: { integration_key: integrationKey, run_mode: runMode } };
}

test('Case A — healthy future repeatable is left untouched (no remove/recreate)', async () => {
  const now = Date.now();
  const queue = mockRecoveryQueue([
    { key: 'integration-schedule:urlhaus-abusech::incremental', id: undefined, name: 'urlhaus-import', pattern: '0 * * * *', next: now + HOUR_MS }
  ]);
  await syncIntegrationFeedSchedules(
    mockPool([{ key: 'urlhaus-abusech', schedule_cron: '0 * * * *' }]),
    queue,
    { logPrefix: '[test]' }
  );
  assert.deepEqual(queue.removed, []);
  assert.deepEqual(queue.added, []);
});

test('Case B — stalled repeatable with no live iteration is removed and re-armed', async () => {
  const now = Date.now();
  const queue = mockRecoveryQueue([
    { key: 'integration-schedule:urlhaus-abusech::incremental', id: undefined, name: 'urlhaus-import', pattern: '0 * * * *', next: now - 2 * HOUR_MS }
  ]);
  await syncIntegrationFeedSchedules(
    mockPool([{ key: 'urlhaus-abusech', schedule_cron: '0 * * * *' }]),
    queue,
    { logPrefix: '[test]' }
  );
  assert.deepEqual(queue.removed, ['integration-schedule:urlhaus-abusech::incremental']);
  assert.equal(queue.added.length, 1);
  assert.equal(queue.added[0].data.integration_key, 'urlhaus-abusech');
  assert.equal(queue.added[0].options.repeat.key, 'integration-schedule:urlhaus-abusech::incremental');
});

test('Case C — overdue repeatable with an active iteration is NOT re-armed', async () => {
  const now = Date.now();
  const queue = mockRecoveryQueue(
    [{ key: 'integration-schedule:threatfox-abusech::incremental', id: undefined, name: 'threatfox-import', pattern: '0 * * * *', next: now - 2 * HOUR_MS }],
    { active: [liveJob('threatfox-abusech')] }
  );
  await syncIntegrationFeedSchedules(
    mockPool([{ key: 'threatfox-abusech', schedule_cron: '0 * * * *' }]),
    queue,
    { logPrefix: '[test]' }
  );
  assert.deepEqual(queue.removed, []);
  assert.deepEqual(queue.added, []);
});

test('Case D — overdue repeatable with a waiting iteration is NOT re-armed', async () => {
  const now = Date.now();
  const queue = mockRecoveryQueue(
    [{ key: 'integration-schedule:threatfox-abusech::incremental', id: undefined, name: 'threatfox-import', pattern: '0 * * * *', next: now - 2 * HOUR_MS }],
    { waiting: [liveJob('threatfox-abusech')] }
  );
  await syncIntegrationFeedSchedules(
    mockPool([{ key: 'threatfox-abusech', schedule_cron: '0 * * * *' }]),
    queue,
    { logPrefix: '[test]' }
  );
  assert.deepEqual(queue.removed, []);
  assert.deepEqual(queue.added, []);
});

test('Case E — overdue repeatable with a delayed iteration is NOT re-armed', async () => {
  const now = Date.now();
  const queue = mockRecoveryQueue(
    [{ key: 'integration-schedule:threatfox-abusech::incremental', id: undefined, name: 'threatfox-import', pattern: '0 * * * *', next: now - 2 * HOUR_MS }],
    { delayed: [liveJob('threatfox-abusech')] }
  );
  await syncIntegrationFeedSchedules(
    mockPool([{ key: 'threatfox-abusech', schedule_cron: '0 * * * *' }]),
    queue,
    { logPrefix: '[test]' }
  );
  assert.deepEqual(queue.removed, []);
  assert.deepEqual(queue.added, []);
});

test('Case F — USOM recovers through the generic path (no USOM-only special-case needed)', async () => {
  const prev = process.env.USOM_FULL_RECONCILIATION_ENABLED;
  process.env.USOM_FULL_RECONCILIATION_ENABLED = 'false';
  try {
    const now = Date.now();
    const queue = mockRecoveryQueue([
      { key: 'integration-schedule:usom-trcert::incremental', id: undefined, name: 'usom-import', pattern: '0 * * * *', next: now - 2 * HOUR_MS }
    ]);
    await syncIntegrationFeedSchedules(
      mockPool([{ key: 'usom-trcert', schedule_cron: '0 * * * *' }]),
      queue,
      { logPrefix: '[test]' }
    );
    assert.deepEqual(queue.removed, ['integration-schedule:usom-trcert::incremental']);
    const usom = queue.added.filter((e) => e.data.integration_key === 'usom-trcert');
    assert.equal(usom.length, 1);
    assert.equal(usom[0].options.repeat.key, 'integration-schedule:usom-trcert::incremental');
  } finally {
    if (prev == null) delete process.env.USOM_FULL_RECONCILIATION_ENABLED;
    else process.env.USOM_FULL_RECONCILIATION_ENABLED = prev;
  }
});

test('Case G — another built-in feed (EmergingThreats daily) recovers the same way', async () => {
  const now = Date.now();
  const queue = mockRecoveryQueue([
    { key: 'integration-schedule:et-blockrules::incremental', id: undefined, name: 'hourly-import', pattern: '0 0 * * *', tz: 'Europe/Istanbul', next: now - 26 * HOUR_MS }
  ]);
  await syncIntegrationFeedSchedules(
    mockPool([{ key: 'et-blockrules', schedule_cron: '0 0 * * *' }]),
    queue,
    { logPrefix: '[test]' }
  );
  assert.deepEqual(queue.removed, ['integration-schedule:et-blockrules::incremental']);
  assert.equal(queue.added.length, 1);
  assert.equal(queue.added[0].data.integration_key, 'et-blockrules');
});

test('Case H — schedule mismatch is still replaced (no regression) even when future', async () => {
  const now = Date.now();
  const queue = mockRecoveryQueue([
    { key: 'integration-schedule:urlhaus-abusech::incremental', id: undefined, name: 'urlhaus-import', pattern: '30 * * * *', next: now + HOUR_MS }
  ]);
  await syncIntegrationFeedSchedules(
    mockPool([{ key: 'urlhaus-abusech', schedule_cron: '0 * * * *' }]),
    queue,
    { logPrefix: '[test]' }
  );
  assert.deepEqual(queue.removed, ['integration-schedule:urlhaus-abusech::incremental']);
  assert.equal(queue.added.length, 1);
});

test('collectLiveScheduleIdentities tolerates a queue without live-job getters', async () => {
  const set = await collectLiveScheduleIdentities(mockQueue([]));
  assert.equal(set.size, 0);
});

test('evaluateRepeatableStall honours grace and live-iteration guard', () => {
  const now = 1_000_000_000_000;
  // future next → not stalled
  assert.equal(evaluateRepeatableStall({ next: now + HOUR_MS }, 'x::incremental', new Set(), now).stalled, false);
  // within grace → not stalled
  assert.equal(evaluateRepeatableStall({ next: now - (STALLED_REPEATABLE_GRACE_MS - 1) }, 'x::incremental', new Set(), now).stalled, false);
  // safely overdue, no live → stalled
  assert.equal(evaluateRepeatableStall({ next: now - 5 * HOUR_MS }, 'x::incremental', new Set(), now).stalled, true);
  // safely overdue but live → not stalled
  assert.equal(
    evaluateRepeatableStall({ next: now - 5 * HOUR_MS }, 'x::incremental', new Set(['x::incremental']), now).stalled,
    false
  );
  // non-finite next → not stalled
  assert.equal(evaluateRepeatableStall({ next: undefined }, 'x::incremental', new Set(), now).stalled, false);
});

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

test('custom feeds get a stable integration-schedule repeat key', async () => {
  const queue = mockQueue();
  const custom = [
    { key: 'ctf-aaaa', schedule_cron: '0 0 * * *' },
    { key: 'ctf-bbbb', schedule_cron: '0 0 * * *' },
    { key: 'ctf-cccc', schedule_cron: '0 0 * * *' }
  ];
  await syncCustomThreatFeedSchedules(mockPool([], custom), queue, { logPrefix: '[test]' });
  assert.equal(queue.added.length, 3);
  assert.deepEqual(
    queue.added.map((entry) => entry.options.repeat.key).sort(),
    [
      customFeedRepeatableKey('ctf-aaaa'),
      customFeedRepeatableKey('ctf-bbbb'),
      customFeedRepeatableKey('ctf-cccc')
    ].sort()
  );
  assert.ok(queue.added.every((entry) => entry.name === CUSTOM_THREAT_FEED_JOB));
  assert.ok(queue.added.every((entry) => entry.data.run_mode === 'incremental'));
});

test('stable custom repeatables are not deleted and recreated every scheduler tick', async () => {
  const custom = [
    { key: 'ctf-one', schedule_cron: '0 0 * * *' },
    { key: 'ctf-two', schedule_cron: '0 0 * * *' }
  ];
  const first = mockQueue();
  await syncCustomThreatFeedSchedules(mockPool([], custom), first, { logPrefix: '[test]' });
  assert.equal(first.added.length, 2);

  const repeatables = first.added.map((entry) => ({
    key: entry.options.repeat.key,
    id: entry.options.jobId,
    name: entry.name,
    pattern: entry.options.repeat.pattern,
    tz: entry.options.repeat.tz || '',
    next: Date.now() + 3600_000
  }));
  const second = mockQueue(repeatables);
  await syncCustomThreatFeedSchedules(mockPool([], custom), second, { logPrefix: '[test]' });
  assert.deepEqual(second.removed, []);
  assert.deepEqual(second.added, []);
});

test('legacy unmapped custom hash keys are replaced with stable keys once', async () => {
  const custom = [{ key: 'ctf-legacy', schedule_cron: '0 0 * * *' }];
  const queue = mockQueue([
    {
      key: 'fc328681c34f463c3ffb28f1e40ccf18',
      name: CUSTOM_THREAT_FEED_JOB,
      pattern: '0 0 * * *',
      tz: 'UTC',
      next: Date.now() + 3600_000
    }
  ]);
  await syncCustomThreatFeedSchedules(mockPool([], custom), queue, { logPrefix: '[test]' });
  assert.deepEqual(queue.removed, ['fc328681c34f463c3ffb28f1e40ccf18']);
  assert.equal(queue.added.length, 1);
  assert.equal(queue.added[0].options.repeat.key, customFeedRepeatableKey('ctf-legacy'));
  assert.equal(queue.added[0].options.jobId, 'ctf-legacy-scheduled');
});

test('scheduler enqueues every due custom feed without waiting for a previous sync to finish', async () => {
  let processed = 0;
  const queue = mockQueue();
  queue.waitUntilFinished = async () => { processed += 1; };
  queue.process = async () => { processed += 1; };
  const custom = [
    { key: 'ctf-1', schedule_cron: '0 0 * * *' },
    { key: 'ctf-2', schedule_cron: '0 0 * * *' },
    { key: 'ctf-3', schedule_cron: '0 0 * * *' }
  ];
  await syncCustomThreatFeedSchedules(mockPool([], custom), queue, { logPrefix: '[test]' });
  assert.equal(queue.added.length, 3);
  assert.equal(processed, 0);
  assert.deepEqual(
    queue.added.map((entry) => entry.data.integration_key).sort(),
    ['ctf-1', 'ctf-2', 'ctf-3']
  );
});
