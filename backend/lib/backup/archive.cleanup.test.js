import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createTarGzAtomic } from './archive.js';

// Failure injection for archive packing: a failed or interrupted pack must not
// leave .partial-* archives behind in BACKUP_DIR/.tmp.

async function stagingFixture() {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-pack-fail-'));
  const bundleDir = path.join(root, 'work', 'backup-20261028-000000-abcdef01');
  await fs.promises.mkdir(bundleDir, { recursive: true });
  await fs.promises.writeFile(path.join(bundleDir, 'manifest.json'), '{}');
  const tmpDir = path.join(root, '.tmp');
  // Another process's in-flight archive must survive our failure cleanup.
  await fs.promises.mkdir(tmpDir, { recursive: true });
  const foreign = path.join(tmpDir, '.partial-backup-20261028-000000-ffffffff.tar.gz.99999.1');
  await fs.promises.writeFile(foreign, 'other process');
  return { root, bundleDir, tmpDir, foreign, finalPath: path.join(root, 'work', 'backup-20261028-000000-abcdef01.tar.gz') };
}

test('createTarGzAtomic removes its partial archive when tar fails mid-write', async () => {
  const fx = await stagingFixture();
  try {
    let calls = 0;
    const runTar = async (args) => {
      calls += 1;
      await fs.promises.writeFile(args[1], Buffer.alloc(4096)); // partial output, then failure
      throw Object.assign(new Error('tar exited 2: disk full'), { code: 'ARCHIVE_FAILED' });
    };
    await assert.rejects(createTarGzAtomic(fx.bundleDir, fx.finalPath, { tmpDir: fx.tmpDir, runTar }), /disk full/);
    assert.equal(calls, 2);
    assert.deepEqual(await fs.promises.readdir(fx.tmpDir), [path.basename(fx.foreign)]);
    assert.equal(fs.existsSync(fx.finalPath), false);
  } finally {
    await fs.promises.rm(fx.root, { recursive: true, force: true });
  }
});

test('createTarGzAtomic removes its partial archive when the final rename fails', async () => {
  const fx = await stagingFixture();
  try {
    const runTar = async (args) => fs.promises.writeFile(args[1], Buffer.alloc(128));
    // Destination directory missing -> rename throws ENOENT after a complete archive was written.
    const unreachable = path.join(fx.root, 'missing-dir', 'backup.tar.gz');
    await assert.rejects(createTarGzAtomic(fx.bundleDir, unreachable, { tmpDir: fx.tmpDir, runTar }));
    assert.deepEqual(await fs.promises.readdir(fx.tmpDir), [path.basename(fx.foreign)]);
  } finally {
    await fs.promises.rm(fx.root, { recursive: true, force: true });
  }
});
