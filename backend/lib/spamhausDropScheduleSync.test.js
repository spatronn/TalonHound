import test from 'node:test';
import assert from 'node:assert/strict';
import {
  syncSpamhausDropSchedule,
  SPAMHAUS_DROP_JOB_NAME,
  SPAMHAUS_DROP_JOB_ID,
  spamhausDropScheduleIdentity
} from './spamhausDropScheduleSync.js';
import { STALLED_REPEATABLE_GRACE_MS } from './integrationFeedScheduleSync.js';
import {
  syncFileArtifactReconciliationSchedule,
  FILE_ARTIFACT_RECON_JOB_NAME,
  FILE_ARTIFACT_RECON_JOB_ID,
  FILE_ARTIFACT_RECON_CRON,
  fileArtifactScheduleIdentity
} from './fileArtifactReconciliationScheduleSync.js';

const HOUR_MS = 3600_000;

function mockSpamhausPool({ enabled = true, sync_interval_hours = 24 } = {}) {
  return {
    async query() {
      return {
        rows: [{
          enabled,
          timeout_ms: 30000,
          config: { sync_interval_hours }
        }]
      };
    }
  };
}

function mockQueue(repeatables = [], live = {}) {
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
    async removeRepeatableByKey(key) { removed.push(key); },
    async getWaiting() { return live.waiting || []; },
    async getActive() { return live.active || []; },
    async getDelayed() { return live.delayed || []; }
  };
}

function liveJob(integrationKey) {
  return { data: { integration_key: integrationKey, run_mode: 'incremental' } };
}

test('spamhaus: healthy matching pattern + future next → unchanged (no remove)', async () => {
  const now = Date.now();
  const queue = mockQueue([{
    key: 'spamhaus-key',
    id: SPAMHAUS_DROP_JOB_ID,
    name: SPAMHAUS_DROP_JOB_NAME,
    pattern: '0 0 * * *',
    next: now + HOUR_MS
  }]);
  const result = await syncSpamhausDropSchedule(mockSpamhausPool(), queue, { logPrefix: '[test]' });
  assert.equal(result.active, true);
  assert.deepEqual(queue.removed, []);
  assert.deepEqual(queue.added, []);
});

test('spamhaus: stalled (past next, no live) → remove + re-add', async () => {
  const now = Date.now();
  const queue = mockQueue([{
    key: 'spamhaus-key',
    id: SPAMHAUS_DROP_JOB_ID,
    name: SPAMHAUS_DROP_JOB_NAME,
    pattern: '0 0 * * *',
    next: now - (STALLED_REPEATABLE_GRACE_MS + HOUR_MS)
  }]);
  const result = await syncSpamhausDropSchedule(mockSpamhausPool(), queue, { logPrefix: '[test]' });
  assert.equal(result.active, true);
  assert.deepEqual(queue.removed, ['spamhaus-key']);
  assert.equal(queue.added.length, 1);
  assert.equal(queue.added[0].data.integration_key, 'spamhaus-drop');
  assert.equal(queue.added[0].options.jobId, SPAMHAUS_DROP_JOB_ID);
});

test('spamhaus: past next but live delayed identity → NOT duplicated', async () => {
  const now = Date.now();
  const queue = mockQueue(
    [{
      key: 'spamhaus-key',
      id: SPAMHAUS_DROP_JOB_ID,
      name: SPAMHAUS_DROP_JOB_NAME,
      pattern: '0 0 * * *',
      next: now - (STALLED_REPEATABLE_GRACE_MS + HOUR_MS)
    }],
    { delayed: [liveJob('spamhaus-drop')] }
  );
  const result = await syncSpamhausDropSchedule(mockSpamhausPool(), queue, { logPrefix: '[test]' });
  assert.equal(result.active, true);
  assert.deepEqual(queue.removed, []);
  assert.deepEqual(queue.added, []);
});

test('spamhaus schedule identity matches collectLiveScheduleIdentities keying', () => {
  assert.equal(spamhausDropScheduleIdentity(), 'spamhaus-drop::incremental');
});

test('file-artifact: healthy matching pattern + future next → unchanged', async () => {
  const prev = process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
  process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = '1';
  try {
    const now = Date.now();
    const queue = mockQueue([{
      key: 'file-artifact-key',
      id: FILE_ARTIFACT_RECON_JOB_ID,
      name: FILE_ARTIFACT_RECON_JOB_NAME,
      pattern: FILE_ARTIFACT_RECON_CRON,
      next: now + HOUR_MS
    }]);
    const result = await syncFileArtifactReconciliationSchedule({}, queue, { logPrefix: '[test]' });
    assert.equal(result.active, true);
    assert.deepEqual(queue.removed, []);
    assert.deepEqual(queue.added, []);
  } finally {
    if (prev == null) delete process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    else process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = prev;
  }
});

test('file-artifact: stalled (past next, no live) → remove + re-add', async () => {
  const prev = process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
  process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = '1';
  try {
    const now = Date.now();
    const queue = mockQueue([{
      key: 'file-artifact-key',
      id: FILE_ARTIFACT_RECON_JOB_ID,
      name: FILE_ARTIFACT_RECON_JOB_NAME,
      pattern: FILE_ARTIFACT_RECON_CRON,
      next: now - (STALLED_REPEATABLE_GRACE_MS + HOUR_MS)
    }]);
    const result = await syncFileArtifactReconciliationSchedule({}, queue, { logPrefix: '[test]' });
    assert.equal(result.active, true);
    assert.deepEqual(queue.removed, ['file-artifact-key']);
    assert.equal(queue.added.length, 1);
    assert.equal(queue.added[0].data.integration_key, 'file-artifact');
  } finally {
    if (prev == null) delete process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    else process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = prev;
  }
});

test('file-artifact: past next but live delayed identity → NOT duplicated', async () => {
  const prev = process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
  process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = '1';
  try {
    const now = Date.now();
    const queue = mockQueue(
      [{
        key: 'file-artifact-key',
        id: FILE_ARTIFACT_RECON_JOB_ID,
        name: FILE_ARTIFACT_RECON_JOB_NAME,
        pattern: FILE_ARTIFACT_RECON_CRON,
        next: now - (STALLED_REPEATABLE_GRACE_MS + HOUR_MS)
      }],
      { delayed: [liveJob('file-artifact')] }
    );
    const result = await syncFileArtifactReconciliationSchedule({}, queue, { logPrefix: '[test]' });
    assert.equal(result.active, true);
    assert.deepEqual(queue.removed, []);
    assert.deepEqual(queue.added, []);
  } finally {
    if (prev == null) delete process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    else process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = prev;
  }
});

test('file-artifact schedule identity matches collectLiveScheduleIdentities keying', () => {
  assert.equal(fileArtifactScheduleIdentity(), 'file-artifact::incremental');
});
