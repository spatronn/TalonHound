import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { classifyBackupTempEntry, sweepStaleBackupTemp } from './tempSweep.js';

const HOUR = 3_600_000;

async function makeBackupDir() {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-bk-sweep-'));
  await fs.promises.mkdir(path.join(dir, '.tmp'), { recursive: true });
  return dir;
}

async function age(p, hours) {
  const t = new Date(Date.now() - hours * HOUR);
  await fs.promises.utimes(p, t, t);
}

test('classifyBackupTempEntry recognises only the runBackup staging layouts', () => {
  assert.deepEqual(classifyBackupTempEntry('backup-20261025-142808-dc9efaf2-4242', true), {
    kind: 'work_dir',
    backupId: 'backup-20261025-142808-dc9efaf2'
  });
  assert.deepEqual(
    classifyBackupTempEntry('.partial-backup-20261025-142808-dc9efaf2.tar.gz.4242.1761402488000', false),
    { kind: 'partial_archive', backupId: 'backup-20261025-142808-dc9efaf2' }
  );
  assert.equal(classifyBackupTempEntry('operator-notes', true), null);
  assert.equal(classifyBackupTempEntry('restore.sql', false), null);
  assert.equal(classifyBackupTempEntry('backup-20261025-142808-dc9efaf2-4242', false), null);
});

test('sweep removes stale staging of finished backups and keeps everything else', async () => {
  const dir = await makeBackupDir();
  const tmp = path.join(dir, '.tmp');
  try {
    const staleWork = path.join(tmp, 'backup-20261001-000000-aaaaaaaa-11');
    await fs.promises.mkdir(path.join(staleWork, 'database'), { recursive: true });
    await fs.promises.writeFile(path.join(staleWork, 'database', 'postgres.dump'), Buffer.alloc(2048));
    await age(staleWork, 8);

    const stalePartial = path.join(tmp, '.partial-backup-20261001-000000-aaaaaaaa.tar.gz.11.1');
    await fs.promises.writeFile(stalePartial, Buffer.alloc(512));
    await age(stalePartial, 8);

    const activeWork = path.join(tmp, 'backup-20261002-000000-bbbbbbbb-12');
    await fs.promises.mkdir(activeWork);
    await age(activeWork, 8);

    const freshWork = path.join(tmp, 'backup-20261003-000000-cccccccc-13');
    await fs.promises.mkdir(freshWork);

    const unknown = path.join(tmp, 'keep-me.txt');
    await fs.promises.writeFile(unknown, 'operator file');
    await age(unknown, 48);

    const result = await sweepStaleBackupTemp(dir, {
      activeBackupIds: new Set(['backup-20261002-000000-bbbbbbbb'])
    });

    assert.equal(result.deleted, 2);
    assert.equal(result.deleted_bytes, 2048 + 512);
    assert.equal(result.protected, 2);
    assert.equal(result.unknown, 1);
    assert.equal(fs.existsSync(staleWork), false);
    assert.equal(fs.existsSync(stalePartial), false);
    assert.equal(fs.existsSync(activeWork), true);
    assert.equal(fs.existsSync(freshWork), true);
    assert.equal(fs.existsSync(unknown), true);
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }
});

test('dry run reports stale staging without deleting it', async () => {
  const dir = await makeBackupDir();
  try {
    const stale = path.join(dir, '.tmp', '.partial-backup-20261001-000000-aaaaaaaa.tar.gz.enc.9.1');
    await fs.promises.writeFile(stale, Buffer.alloc(100));
    await age(stale, 10);
    const result = await sweepStaleBackupTemp(dir, { apply: false });
    assert.equal(result.stale, 1);
    assert.equal(result.stale_bytes, 100);
    assert.equal(result.deleted, 0);
    assert.equal(fs.existsSync(stale), true);
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }
});

test('missing .tmp directory is not an error', async () => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-bk-sweep-empty-'));
  try {
    const result = await sweepStaleBackupTemp(dir);
    assert.equal(result.deleted, 0);
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }
});
