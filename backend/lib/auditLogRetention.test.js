import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseAuditLogRetentionInput,
  deleteAuditLogsOlderThanBatch,
  runAuditLogRetentionCleanup,
  getAuditLogRetentionConfig,
  setAuditLogRetention,
  AUDIT_LOG_RETENTION_DEFAULT_DAYS,
  AUDIT_LOG_RETENTION_MAX_DAYS,
  AUDIT_LOG_RETENTION_PRESET_DAYS
} from './auditLogRetention.js';

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

test('parse accepts documented preset values', () => {
  for (const days of AUDIT_LOG_RETENTION_PRESET_DAYS) {
    const r = parseAuditLogRetentionInput({ retention_days: days });
    assert.deepEqual(r, { ok: true, keepForever: false, days });
  }
});

test('parse accepts a positive custom integer', () => {
  assert.deepEqual(parseAuditLogRetentionInput({ retention_days: 45 }), { ok: true, keepForever: false, days: 45 });
  // numeric string form is coerced
  assert.deepEqual(parseAuditLogRetentionInput({ retention_days: '45' }), { ok: true, keepForever: false, days: 45 });
});

test('parse treats keep_forever / null as Keep forever', () => {
  assert.deepEqual(parseAuditLogRetentionInput({ keep_forever: true }), { ok: true, keepForever: true, days: null });
  assert.deepEqual(parseAuditLogRetentionInput({ mode: 'keep_forever' }), { ok: true, keepForever: true, days: null });
  assert.deepEqual(parseAuditLogRetentionInput({ retention_days: null }), { ok: true, keepForever: true, days: null });
});

test('parse rejects zero, negatives, decimals and non-numeric', () => {
  assert.equal(parseAuditLogRetentionInput({ retention_days: 0 }).ok, false);
  assert.equal(parseAuditLogRetentionInput({ retention_days: -5 }).ok, false);
  assert.equal(parseAuditLogRetentionInput({ retention_days: 30.5 }).ok, false);
  assert.equal(parseAuditLogRetentionInput({ retention_days: '30.5' }).ok, false);
  assert.equal(parseAuditLogRetentionInput({ retention_days: 'abc' }).ok, false);
  assert.equal(parseAuditLogRetentionInput({ retention_days: '' }).ok, false);
  assert.equal(parseAuditLogRetentionInput({}).ok, false);
});

test('parse rejects values beyond the sanity cap', () => {
  assert.equal(parseAuditLogRetentionInput({ retention_days: AUDIT_LOG_RETENTION_MAX_DAYS }).ok, true);
  assert.equal(parseAuditLogRetentionInput({ retention_days: AUDIT_LOG_RETENTION_MAX_DAYS + 1 }).ok, false);
});

// ---------------------------------------------------------------------------
// Config read / write against a fake singleton row
// ---------------------------------------------------------------------------

function fakeSettingsDb(initial = {}) {
  const row = {
    audit_log_retention_days: AUDIT_LOG_RETENTION_DEFAULT_DAYS,
    audit_log_retention_updated_at: null,
    audit_log_retention_updated_by: null,
    audit_log_retention_last_run_at: null,
    ...initial
  };
  return {
    row,
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('SELECT audit_log_retention_days')) {
        return { rows: [{ ...row }] };
      }
      if (s.startsWith('INSERT INTO system_settings')) {
        return { rows: [] };
      }
      if (s.includes('UPDATE system_settings') && s.includes('audit_log_retention_days = $2')) {
        row.audit_log_retention_days = params[1];
        row.audit_log_retention_updated_by = params[2];
        row.audit_log_retention_updated_at = new Date();
        return { rows: [] };
      }
      if (s.includes('audit_log_retention_last_run_at = NOW()')) {
        row.audit_log_retention_last_run_at = new Date();
        return { rows: [] };
      }
      throw new Error(`unexpected sql: ${s}`);
    }
  };
}

test('default retention config is 365', async () => {
  const db = fakeSettingsDb();
  const cfg = await getAuditLogRetentionConfig(db);
  assert.equal(cfg.retentionDays, 365);
  assert.equal(cfg.keepForever, false);
});

test('setAuditLogRetention persists a finite value and Keep forever', async () => {
  const db = fakeSettingsDb();
  let cfg = await setAuditLogRetention(db, { days: 90, updatedBy: 'admin@x' });
  assert.equal(cfg.retentionDays, 90);
  assert.equal(cfg.keepForever, false);
  assert.equal(db.row.audit_log_retention_updated_by, 'admin@x');

  cfg = await setAuditLogRetention(db, { days: null, updatedBy: 'admin@x' });
  assert.equal(cfg.retentionDays, null);
  assert.equal(cfg.keepForever, true);
});

// ---------------------------------------------------------------------------
// Batch deletion semantics
// ---------------------------------------------------------------------------

/**
 * Fake pool whose audit_logs holds rows with a created_at age (days). Batch
 * DELETE removes up to batchSize rows strictly older than the cutoff.
 */
function fakeCleanupPool({ retentionDays, rows, lastRunAt = null, lockAcquired = true }) {
  // rows: array of ageDays (age relative to NOW)
  let store = [...rows];
  const calls = { batches: 0, deleted: 0, unlocked: false };
  const settingsRow = {
    audit_log_retention_days: retentionDays,
    audit_log_retention_updated_at: null,
    audit_log_retention_updated_by: null,
    audit_log_retention_last_run_at: lastRunAt
  };

  async function query(sql, params = []) {
    const s = String(sql);
    if (s.includes('pg_try_advisory_lock')) return { rows: [{ ok: lockAcquired }] };
    if (s.includes('pg_advisory_unlock')) { calls.unlocked = true; return { rows: [{}] }; }
    if (s.includes('SELECT audit_log_retention_days')) return { rows: [{ ...settingsRow }] };
    if (s.includes('make_interval') && s.includes('AS cutoff')) {
      return { rows: [{ cutoff: new Date(Date.now() - Number(params[0]) * 86400000) }] };
    }
    if (s.includes('audit_log_retention_last_run_at = NOW()')) {
      settingsRow.audit_log_retention_last_run_at = new Date();
      return { rows: [] };
    }
    if (s.includes('DELETE FROM audit_logs')) {
      const days = Number(params[0]);
      const batchSize = Number(params[1]);
      const doomedIdx = [];
      for (let i = 0; i < store.length && doomedIdx.length < batchSize; i += 1) {
        if (store[i] > days) doomedIdx.push(i);
      }
      const set = new Set(doomedIdx);
      store = store.filter((_, i) => !set.has(i));
      calls.batches += 1;
      calls.deleted += doomedIdx.length;
      return { rowCount: doomedIdx.length };
    }
    throw new Error(`unexpected sql: ${s}`);
  }

  return {
    calls,
    remaining: () => store,
    async connect() { return { query, release() {} }; },
    query
  };
}

const silentLogger = { info() {}, log() {}, warn() {}, error() {} };

test('cleanup deletes across multiple bounded batches', async () => {
  // 23 rows older than the 30-day cutoff, plus 5 newer rows that must remain.
  const rows = [];
  for (let i = 0; i < 23; i += 1) rows.push(40); // 40 days old > 30 => delete
  for (let i = 0; i < 5; i += 1) rows.push(10);  // 10 days old < 30 => keep
  const pool = fakeCleanupPool({ retentionDays: 30, rows });

  const res = await runAuditLogRetentionCleanup(pool, { batchSize: 10, minIntervalMs: 0, logger: silentLogger });

  assert.equal(res.skipped, false);
  assert.equal(res.deleted, 23);
  assert.equal(res.batches, 3); // 10 + 10 + 3
  assert.deepEqual(pool.remaining(), [10, 10, 10, 10, 10]);
  assert.equal(pool.calls.unlocked, true);
});

test('boundary rows exactly at the cutoff are not deleted (strictly older only)', async () => {
  // age === retentionDays must survive (created_at < NOW() - N days is strict).
  const pool = fakeCleanupPool({ retentionDays: 30, rows: [30, 30, 31] });
  const res = await runAuditLogRetentionCleanup(pool, { batchSize: 100, minIntervalMs: 0, logger: silentLogger });
  assert.equal(res.deleted, 1);
  assert.deepEqual(pool.remaining().sort(), [30, 30]);
});

test('Keep forever performs no deletion', async () => {
  const pool = fakeCleanupPool({ retentionDays: null, rows: [999, 999, 999] });
  const res = await runAuditLogRetentionCleanup(pool, { batchSize: 10, minIntervalMs: 0, logger: silentLogger });
  assert.equal(res.skipped, true);
  assert.equal(res.reason, 'keep_forever');
  assert.equal(pool.calls.batches, 0);
  assert.deepEqual(pool.remaining(), [999, 999, 999]);
});

test('daily gate skips when a recent run exists', async () => {
  const pool = fakeCleanupPool({ retentionDays: 30, rows: [40, 40], lastRunAt: new Date() });
  const res = await runAuditLogRetentionCleanup(pool, { batchSize: 10, minIntervalMs: 24 * 3600 * 1000, logger: silentLogger });
  assert.equal(res.skipped, true);
  assert.equal(res.reason, 'not_due');
  assert.equal(pool.calls.batches, 0);
});

test('cleanup is a no-op when the advisory lock is held elsewhere', async () => {
  const pool = fakeCleanupPool({ retentionDays: 30, rows: [40, 40], lockAcquired: false });
  const res = await runAuditLogRetentionCleanup(pool, { batchSize: 10, minIntervalMs: 0, logger: silentLogger });
  assert.equal(res.skipped, true);
  assert.equal(res.reason, 'locked');
  assert.equal(pool.calls.batches, 0);
});

test('deleteAuditLogsOlderThanBatch forwards days + batchSize to SQL and returns rowCount', async () => {
  let captured = null;
  const db = {
    async query(sql, params) {
      captured = { sql: String(sql), params };
      return { rowCount: 7 };
    }
  };
  const n = await deleteAuditLogsOlderThanBatch(db, { days: 90, batchSize: 500 });
  assert.equal(n, 7);
  assert.match(captured.sql, /make_interval\(days => \$1::int\)/);
  assert.match(captured.sql, /FOR UPDATE SKIP LOCKED/);
  assert.deepEqual(captured.params, [90, 500]);
});
