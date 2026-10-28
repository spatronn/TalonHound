import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  auditArtifactConsistency,
  deleteReportArtifacts,
  resolveStoragePath,
  storeArtifactBuffer
} from './artifactStore.js';
import { deleteThreatReport } from './store.js';

async function withStorage(fn) {
  const prev = process.env.THREAT_LIBRARY_STORAGE_DIR;
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-tl-store-'));
  process.env.THREAT_LIBRARY_STORAGE_DIR = root;
  try {
    await fn(root);
  } finally {
    if (prev === undefined) delete process.env.THREAT_LIBRARY_STORAGE_DIR;
    else process.env.THREAT_LIBRARY_STORAGE_DIR = prev;
    await fs.promises.rm(root, { recursive: true, force: true });
  }
}

const filesUnder = (dir) => (fs.existsSync(dir) ? fs.readdirSync(dir) : []);

test('re-storing identical source content (refetch, retry, re-import) adds no files', async () => {
  await withStorage(async (root) => {
    const html = Buffer.from('<html><body>IOC 1.2.3.4</body></html>');
    const first = await storeArtifactBuffer(42, html, { fileName: 'source.html', ext: '.html' });
    for (let i = 0; i < 5; i += 1) {
      const again = await storeArtifactBuffer(42, html, { fileName: 'source.html', ext: '.html' });
      assert.equal(again.storageKey, first.storageKey);
    }
    assert.deepEqual(filesUnder(path.join(root, 'reports', '42')), [path.basename(first.storageKey)]);
  });
});

test('changed source content is a new content-addressed file in the same report directory', async () => {
  await withStorage(async (root) => {
    const a = await storeArtifactBuffer(7, Buffer.from('v1'), { ext: '.html' });
    const b = await storeArtifactBuffer(7, Buffer.from('v2'), { ext: '.html' });
    assert.notEqual(a.storageKey, b.storageKey);
    assert.equal(filesUnder(path.join(root, 'reports', '7')).length, 2);
  });
});

test('report deletion removes the report directory and only that directory', async () => {
  await withStorage(async (root) => {
    await storeArtifactBuffer(10, Buffer.from('ten'), { ext: '.pdf' });
    await storeArtifactBuffer(11, Buffer.from('eleven'), { ext: '.pdf' });
    const queries = [];
    const pool = { query: async (sql, params) => { queries.push([String(sql).trim(), params]); return { rows: [] }; } };

    await deleteThreatReport(pool, 10);

    assert.equal(fs.existsSync(path.join(root, 'reports', '10')), false);
    assert.equal(filesUnder(path.join(root, 'reports', '11')).length, 1);
    assert.ok(queries.some(([q, p]) => /^DELETE FROM threat_report_artifacts/.test(q) && p[0] === 10));
    assert.ok(queries.some(([q]) => /^UPDATE threat_reports SET deleted_at/.test(q)));
    // Deleting again (retry after a partial failure) is harmless.
    await deleteReportArtifacts(10);
  });
});

test('storage keys cannot escape the storage root', () => {
  assert.throws(() => resolveStoragePath('reports/../../etc/passwd'), /storage key|escape/i);
  assert.throws(() => resolveStoragePath('reports/1/../../x'), /storage key|escape/i);
});

test('consistency audit reports unreferenced files and missing artifacts without changing anything', async () => {
  await withStorage(async (root) => {
    const kept = await storeArtifactBuffer(1, Buffer.from('kept'), { ext: '.html' });
    const orphan = await storeArtifactBuffer(2, Buffer.from('orphan-bytes'), { ext: '.html' });
    const report = await auditArtifactConsistency([kept.storageKey, 'reports/3/missing.pdf']);
    assert.equal(report.files, 2);
    assert.deepEqual(report.unreferenced, [{ key: orphan.storageKey, bytes: 12 }]);
    assert.deepEqual(report.missing, ['reports/3/missing.pdf']);
    assert.ok(fs.existsSync(path.join(root, orphan.storageKey)), 'audit is read-only');

    const clean = await auditArtifactConsistency([kept.storageKey, orphan.storageKey]);
    assert.equal(clean.unreferenced.length + clean.missing.length, 0);
  });
});

test('consistency audit tolerates an empty install', async () => {
  await withStorage(async () => {
    const report = await auditArtifactConsistency([]);
    assert.deepEqual(report, { files: 0, bytes: 0, unreferenced: [], unreferenced_bytes: 0, missing: [] });
  });
});
