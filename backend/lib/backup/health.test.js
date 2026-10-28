import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import { evaluateBackupHealth, readFilesystemCapacity, systemHealthEntries } from './health.js';
import { resolveOverallSystemHealth } from '../systemHealth.js';

const NOW = new Date('2026-10-28T12:00:00Z');
const CFG = {
  enabled: true,
  minRetained: 2,
  maxAgeHours: 192,
  retentionDays: 30,
  diskWarnFreePercent: 10,
  inodeWarnFreePercent: 5
};

function point(daysAgo, extra = {}) {
  const at = new Date(NOW.getTime() - daysAgo * 86_400_000).toISOString();
  return {
    backup_id: `b-${daysAgo}`,
    status: 'completed',
    verify_status: 'passed',
    created_at: at,
    completed_at: at,
    archive_size_bytes: 1_000,
    ...extra
  };
}

const roomy = { total_bytes: 100_000, free_bytes: 50_000, free_percent: 50, inodes_free_percent: 60 };
const codes = (r) => r.warnings.map((w) => w.code).sort();

test('healthy installation has no warnings', () => {
  const r = evaluateBackupHealth({ cfg: CFG, completed: [point(1), point(8)], capacity: roomy, now: NOW });
  assert.equal(r.recovery_points, 2);
  assert.deepEqual(r.warnings, []);
});

test('no or too few verified backups', () => {
  assert.deepEqual(codes(evaluateBackupHealth({ cfg: CFG, completed: [], now: NOW })), ['no_recovery_point']);
  assert.deepEqual(
    codes(evaluateBackupHealth({ cfg: CFG, completed: [point(1), point(2, { verify_status: 'failed' })], now: NOW })),
    ['insufficient_recovery_points']
  );
});

test('failed latest backup and overdue newest backup', () => {
  const r = evaluateBackupHealth({
    cfg: CFG,
    completed: [point(9), point(16)],
    latestFinished: { status: 'failed' },
    now: NOW
  });
  assert.deepEqual(codes(r), ['backup_overdue', 'last_backup_failed']);
  const disabled = evaluateBackupHealth({ cfg: { ...CFG, enabled: false }, completed: [point(9), point(16)], now: NOW });
  assert.deepEqual(codes(disabled), []);
});

test('expired backups beyond the minimum signal a failing retention sweep', () => {
  const r = evaluateBackupHealth({ cfg: CFG, completed: [point(1), point(8), point(40)], now: NOW });
  assert.deepEqual(codes(r), ['retention_overdue']);
  // The minimum is kept regardless of age, so old-but-required points are fine.
  const kept = evaluateBackupHealth({ cfg: { ...CFG, maxAgeHours: 0 }, completed: [point(40), point(50)], now: NOW });
  assert.deepEqual(codes(kept), []);
});

test('disk, inode and stale staging warnings', () => {
  const lowPct = evaluateBackupHealth({
    cfg: CFG,
    completed: [point(1), point(8)],
    capacity: { ...roomy, free_bytes: 9_000, free_percent: 9 },
    now: NOW
  });
  assert.equal(lowPct.warnings[0].code, 'low_disk_space');
  assert.equal(lowPct.warnings[0].severity, 'warning');

  const tooSmallForNext = evaluateBackupHealth({
    cfg: CFG,
    completed: [point(1, { archive_size_bytes: 40_000 }), point(8)],
    capacity: roomy,
    now: NOW
  });
  assert.equal(tooSmallForNext.warnings[0].severity, 'critical');

  const r = evaluateBackupHealth({
    cfg: CFG,
    completed: [point(1), point(8)],
    capacity: { ...roomy, inodes_free_percent: 2 },
    staleTemp: { stale: 1, stale_bytes: 10 },
    now: NOW
  });
  assert.deepEqual(codes(r), ['low_inodes', 'stale_temp_artifacts']);
});

test('readFilesystemCapacity reads a real directory and tolerates a missing one', async () => {
  const cap = await readFilesystemCapacity(os.tmpdir());
  assert.ok(cap.total_bytes > 0);
  assert.ok(cap.free_bytes >= 0 && cap.free_bytes <= cap.total_bytes);
  assert.equal(await readFilesystemCapacity('/definitely/not/here/th'), null);
});

test('system health rows: storage counts toward overall, backups never do', () => {
  const fresh = evaluateBackupHealth({ cfg: CFG, completed: [], capacity: roomy, now: NOW });
  const [storage, backups] = systemHealthEntries({ ...fresh, capacity: roomy });
  assert.equal(storage.status, 'healthy');
  assert.equal(backups.status, 'degraded');
  assert.equal(backups.reason, 'no_recovery_point');
  // A fresh install without a backup yet is not a degraded system.
  assert.equal(resolveOverallSystemHealth({ core: [storage, backups] }).status, 'healthy');

  const full = { ...roomy, free_bytes: 1, free_percent: 0.1 };
  const tight = evaluateBackupHealth({ cfg: CFG, completed: [point(1), point(8)], capacity: full, now: NOW });
  const [disk] = systemHealthEntries({ ...tight, capacity: full });
  assert.equal(disk.status, 'unhealthy');
  assert.equal(disk.reason, 'low_disk_space');
  assert.equal(resolveOverallSystemHealth({ core: [disk] }).status, 'degraded');

  const [unknown] = systemHealthEntries({ recovery_points: 0, warnings: [], capacity: null });
  assert.equal(unknown.status, 'unknown');
  assert.equal(resolveOverallSystemHealth({ core: [unknown] }).status, 'healthy');
});

test('warns when the newest verified backup lacks Threat Library files that exist', () => {
  const legacy = point(1);
  const full = point(1, { manifest: { format_version: 3, components: { threat_library: { file_count: 3, bytes: 9 } } } });
  const codes2 = (r) => r.warnings.map((w) => w.code);
  assert.ok(
    codes2(evaluateBackupHealth({ cfg: CFG, completed: [legacy, point(8)], threatLibraryArtifactCount: 5, now: NOW }))
      .includes('latest_backup_without_threat_library')
  );
  assert.deepEqual(codes2(evaluateBackupHealth({ cfg: CFG, completed: [full, point(8)], threatLibraryArtifactCount: 5, now: NOW })), []);
  // nothing to back up yet: a database-only backup is complete
  assert.deepEqual(codes2(evaluateBackupHealth({ cfg: CFG, completed: [legacy, point(8)], threatLibraryArtifactCount: 0, now: NOW })), []);
});
