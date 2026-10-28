import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { copyThreatLibraryArtifacts, listReferencedArtifacts, THREAT_LIBRARY_INDEX_FILE } from './threatLibraryComponent.js';
import {
  abortThreatLibraryRestore,
  commitThreatLibraryRestore,
  previousDirFor,
  stageThreatLibraryRestore,
  stagingDirFor
} from './threatLibraryRestore.js';

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const listFiles = (dir) => {
  const out = [];
  const walk = (d, rel) => {
    if (!fs.existsSync(d)) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), r);
      else out.push(r);
    }
  };
  walk(dir, '');
  return out.sort();
};

/** A bundle built from a "backup-time" storage root, plus a separate live root to restore into. */
async function fixture() {
  const base = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-tl-restore-'));
  const source = path.join(base, 'source');
  const live = path.join(base, 'live');
  const bundleDir = path.join(base, 'bundle');
  const rows = [];
  for (const [id, body, ext] of [[21, '<html>a</html>', '.html'], [22, '%PDF-1.4 b', '.pdf']]) {
    const buf = Buffer.from(body);
    const key = `reports/${id}/${sha(buf)}${ext}`;
    fs.mkdirSync(path.join(source, 'reports', String(id)), { recursive: true });
    fs.writeFileSync(path.join(source, key), buf);
    rows.push({ id, report_id: id, storage_key: key, sha256: sha(buf) });
  }
  const client = {
    async query(sql) {
      if (String(sql).includes('to_regclass')) return { rows: [{ present: true }] };
      return { rows };
    }
  };
  fs.mkdirSync(bundleDir, { recursive: true });
  const copied = await copyThreatLibraryArtifacts({
    entries: await listReferencedArtifacts(client),
    storageRoot: source,
    bundleDir
  });
  const manifest = {
    format_version: 3,
    components: { threat_library: { file_count: copied.fileCount, bytes: copied.totalBytes } }
  };
  // Live store currently holds different content (e.g. a newer report).
  fs.mkdirSync(path.join(live, 'reports', '99'), { recursive: true });
  fs.writeFileSync(path.join(live, 'reports', '99', 'newer.html'), 'newer');
  return { base, live, bundleDir, manifest, rows, cleanup: () => fs.promises.rm(base, { recursive: true, force: true }) };
}

test('stage then commit restores every file with checksums and keeps the previous tree for rollback', async () => {
  const fx = await fixture();
  try {
    const staged = await stageThreatLibraryRestore({ ...fx, storageRoot: fx.live, restoreId: 'r1' });
    assert.equal(staged.staged, 2);
    // staging never touches the live tree
    assert.deepEqual(listFiles(path.join(fx.live, 'reports')), ['99/newer.html']);

    const committed = await commitThreatLibraryRestore({ storageRoot: fx.live, restoreId: 'r1' });
    assert.equal(committed.previous, '.reports-pre-restore-r1');
    const restored = listFiles(path.join(fx.live, 'reports'));
    assert.deepEqual(restored, fx.rows.map((r) => r.storage_key.replace('reports/', '')).sort());
    for (const r of fx.rows) {
      const file = path.join(fx.live, r.storage_key);
      assert.equal(sha(fs.readFileSync(file)), r.sha256, 'restored file matches database sha256');
      if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o640);
    }
    assert.deepEqual(listFiles(previousDirFor(fx.live, 'r1')), ['99/newer.html']);
    assert.equal(fs.existsSync(stagingDirFor(fx.live, 'r1')), false);
  } finally {
    await fx.cleanup();
  }
});

test('a damaged bundle fails staging and leaves the live tree untouched', async () => {
  const fx = await fixture();
  try {
    const victim = path.join(fx.bundleDir, 'files/threat-library', fx.rows[1].storage_key);
    fs.writeFileSync(victim, 'corrupted');
    await assert.rejects(
      stageThreatLibraryRestore({ ...fx, storageRoot: fx.live, restoreId: 'r2' }),
      (err) => err.code === 'TL_ARTIFACT_CORRUPT'
    );
    assert.deepEqual(listFiles(path.join(fx.live, 'reports')), ['99/newer.html']);
    assert.equal(fs.existsSync(stagingDirFor(fx.live, 'r2')), false);
    await assert.rejects(commitThreatLibraryRestore({ storageRoot: fx.live, restoreId: 'r2' }), (e) => e.code === 'RESTORE_NOT_STAGED');
  } finally {
    await fx.cleanup();
  }
});

test('insufficient free space is detected before anything is written', async () => {
  const fx = await fixture();
  try {
    await assert.rejects(
      stageThreatLibraryRestore({ ...fx, storageRoot: fx.live, restoreId: 'r3', statfs: async () => ({ bavail: 1, bsize: 1 }) }),
      (err) => err.code === 'RESTORE_DISK_SPACE'
    );
    assert.equal(fs.existsSync(stagingDirFor(fx.live, 'r3')), false);
  } finally {
    await fx.cleanup();
  }
});

test('an interrupted restore (staged, database restore failed) is discarded by abort', async () => {
  const fx = await fixture();
  try {
    await stageThreatLibraryRestore({ ...fx, storageRoot: fx.live, restoreId: 'r4' });
    await abortThreatLibraryRestore({ storageRoot: fx.live, restoreId: 'r4' });
    assert.equal(fs.existsSync(stagingDirFor(fx.live, 'r4')), false);
    assert.deepEqual(listFiles(path.join(fx.live, 'reports')), ['99/newer.html']);
  } finally {
    await fx.cleanup();
  }
});

test('a legacy bundle has no Threat Library component to restore', async () => {
  const fx = await fixture();
  try {
    await assert.rejects(
      stageThreatLibraryRestore({ ...fx, manifest: { format_version: 2, components: {} }, storageRoot: fx.live, restoreId: 'r5' }),
      (err) => err.code === 'TL_COMPONENT_MISSING'
    );
  } finally {
    await fx.cleanup();
  }
});

test('malicious index paths and restore ids are rejected before any write', async () => {
  const fx = await fixture();
  try {
    const indexPath = path.join(fx.bundleDir, THREAT_LIBRARY_INDEX_FILE);
    const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
    index.files[0].key = '../../../../tmp/evil.html';
    fs.writeFileSync(indexPath, JSON.stringify(index));
    await assert.rejects(
      stageThreatLibraryRestore({ ...fx, storageRoot: fx.live, restoreId: 'r6' }),
      (err) => err.code === 'TL_INDEX_INVALID'
    );
    assert.equal(fs.existsSync(stagingDirFor(fx.live, 'r6')), false);
    assert.throws(() => stagingDirFor(fx.live, '../escape'), /Invalid restore id/);
  } finally {
    await fx.cleanup();
  }
});

test('commit refuses to overwrite an existing rollback copy', async () => {
  const fx = await fixture();
  try {
    await stageThreatLibraryRestore({ ...fx, storageRoot: fx.live, restoreId: 'r7' });
    fs.mkdirSync(previousDirFor(fx.live, 'r7'));
    await assert.rejects(commitThreatLibraryRestore({ storageRoot: fx.live, restoreId: 'r7' }), (e) => e.code === 'RESTORE_PREVIOUS_EXISTS');
    assert.deepEqual(listFiles(path.join(fx.live, 'reports')), ['99/newer.html']);
  } finally {
    await fx.cleanup();
  }
});
