import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import {
  THREAT_LIBRARY_ARTIFACT_LOCK,
  THREAT_LIBRARY_INDEX_FILE,
  captureThreatLibrarySnapshot,
  copyThreatLibraryArtifacts,
  listReferencedArtifacts,
  normalizeArtifactKey,
  threatLibraryComponentSummary,
  verifyThreatLibraryComponent
} from './threatLibraryComponent.js';

const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function tmpdir(prefix) {
  return fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
}

/** Write a content-addressed artifact the way artifactStore does. */
async function putArtifact(root, reportId, content, ext) {
  const buf = Buffer.from(content);
  const key = `reports/${reportId}/${sha(buf)}${ext}`;
  await fs.promises.mkdir(path.join(root, 'reports', String(reportId)), { recursive: true });
  await fs.promises.writeFile(path.join(root, key), buf);
  return { key, sha256: sha(buf), bytes: buf.length };
}

function rowsClient(rows, { tablePresent = true } = {}) {
  const queries = [];
  return {
    queries,
    async query(sql, params) {
      const s = String(sql);
      queries.push(s.trim().split('\n')[0]);
      if (s.includes('to_regclass')) return { rows: [{ present: tablePresent }] };
      if (s.includes('pg_export_snapshot')) return { rows: [{ snapshot: '00000003-0000001B-1' }] };
      if (s.includes('FROM threat_report_artifacts')) return { rows };
      return { rows: [], params };
    }
  };
}

async function fixture() {
  const storage = await tmpdir('th-tl-src-');
  const work = await tmpdir('th-tl-bundle-');
  const html1 = await putArtifact(storage, 11, '<html>report eleven</html>', '.html');
  const html2 = await putArtifact(storage, 12, '<html>report twelve</html>', '.html');
  const pdf = await putArtifact(storage, 13, '%PDF-1.7 fake pdf bytes', '.pdf');
  const rows = [
    { id: 1, report_id: 11, storage_key: html1.key, sha256: html1.sha256 },
    { id: 2, report_id: 12, storage_key: html2.key, sha256: html2.sha256 },
    { id: 3, report_id: 13, storage_key: pdf.key, sha256: pdf.sha256 }
  ];
  const cleanup = async () => {
    await fs.promises.rm(storage, { recursive: true, force: true });
    await fs.promises.rm(work, { recursive: true, force: true });
  };
  return { storage, work, html1, html2, pdf, rows, cleanup };
}

async function collect(fx, rows = fx.rows, bundleName = 'b1') {
  const bundleDir = path.join(fx.work, bundleName);
  await fs.promises.mkdir(bundleDir, { recursive: true });
  const entries = await listReferencedArtifacts(rowsClient(rows));
  const result = await copyThreatLibraryArtifacts({ entries, storageRoot: fx.storage, bundleDir });
  return { bundleDir, result };
}

test('copies HTML and PDF sources with an index whose counts, sizes and checksums match', async () => {
  const fx = await fixture();
  try {
    const { bundleDir, result } = await collect(fx);
    assert.equal(result.fileCount, 3);
    assert.equal(result.totalBytes, fx.html1.bytes + fx.html2.bytes + fx.pdf.bytes);
    assert.deepEqual(result.relPaths.sort(), [fx.html1, fx.html2, fx.pdf].map((a) => `files/threat-library/${a.key}`).sort());
    const index = JSON.parse(fs.readFileSync(path.join(bundleDir, THREAT_LIBRARY_INDEX_FILE), 'utf8'));
    assert.equal(index.file_count, 3);
    assert.ok(index.files.every((f) => f.key.startsWith('reports/') && !path.isAbsolute(f.key)));
    const pdfEntry = index.files.find((f) => f.key === fx.pdf.key);
    assert.deepEqual(pdfEntry.report_ids, [13]);
    const v = await verifyThreatLibraryComponent(bundleDir, { file_count: 3, bytes: result.totalBytes });
    assert.equal(v.ok, true, v.error);
  } finally {
    await fx.cleanup();
  }
});

test('an install without Threat Library artifacts produces an empty, valid component', async () => {
  const fx = await fixture();
  try {
    const { bundleDir, result } = await collect(fx, []);
    assert.equal(result.fileCount, 0);
    assert.equal(result.totalBytes, 0);
    assert.equal((await verifyThreatLibraryComponent(bundleDir, { file_count: 0, bytes: 0 })).ok, true);
    // pre-Threat-Library schema
    assert.deepEqual(await listReferencedArtifacts(rowsClient([], { tablePresent: false })), []);
  } finally {
    await fx.cleanup();
  }
});

test('repeated backups of unchanged sources produce identical indexes', async () => {
  const fx = await fixture();
  try {
    const a = await collect(fx, fx.rows, 'a');
    const b = await collect(fx, fx.rows, 'b');
    assert.deepEqual(a.result.index, b.result.index);
  } finally {
    await fx.cleanup();
  }
});

test('rows sharing a storage key are backed up once with every owner recorded', async () => {
  const fx = await fixture();
  try {
    const rows = [...fx.rows, { id: 9, report_id: 11, storage_key: fx.html1.key, sha256: fx.html1.sha256 }];
    const { result } = await collect(fx, rows);
    assert.equal(result.fileCount, 3);
    assert.deepEqual(result.index.files.find((f) => f.key === fx.html1.key).artifact_ids, [1, 9]);
  } finally {
    await fx.cleanup();
  }
});

test('a missing referenced file fails the component with the exact key', async () => {
  const fx = await fixture();
  try {
    await fs.promises.rm(path.join(fx.storage, fx.html2.key));
    await assert.rejects(collect(fx), (err) => err.code === 'TL_ARTIFACT_MISSING' && err.details.keys[0] === fx.html2.key);
  } finally {
    await fx.cleanup();
  }
});

test('a corrupted file (content no longer matches its sha256) fails the component', async () => {
  const fx = await fixture();
  try {
    await fs.promises.writeFile(path.join(fx.storage, fx.pdf.key), 'tampered');
    await assert.rejects(collect(fx), (err) => err.code === 'TL_ARTIFACT_CORRUPT' && err.details.keys.includes(fx.pdf.key));
  } finally {
    await fx.cleanup();
  }
});

test('a database sha256 that disagrees with the file fails even when the name matches', async () => {
  const fx = await fixture();
  try {
    const rows = fx.rows.map((r) => (r.id === 1 ? { ...r, sha256: 'f'.repeat(64) } : r));
    await assert.rejects(collect(fx, rows), (err) => err.code === 'TL_ARTIFACT_CORRUPT');
  } finally {
    await fx.cleanup();
  }
});

test('a read failure (permission denied) fails the component and leaves no partial copy', async () => {
  const fx = await fixture();
  try {
    const bundleDir = path.join(fx.work, 'perm');
    const entries = await listReferencedArtifacts(rowsClient(fx.rows));
    const openRead = (src) => {
      if (src.endsWith('.pdf')) {
        const r = new Readable({ read() {} });
        process.nextTick(() => r.destroy(Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' })));
        return r;
      }
      return fs.createReadStream(src);
    };
    await assert.rejects(
      copyThreatLibraryArtifacts({ entries, storageRoot: fx.storage, bundleDir, openRead }),
      (err) => err.code === 'TL_ARTIFACT_UNREADABLE' && /EACCES/.test(err.message)
    );
    assert.equal(fs.existsSync(path.join(bundleDir, 'files/threat-library', fx.pdf.key)), false);
  } finally {
    await fx.cleanup();
  }
});

test('unsafe storage keys are refused before any file is touched', async () => {
  for (const key of ['../etc/passwd', '/etc/passwd', 'reports/1/../../x', 'reports/abc/f.html', 'reports/1/.hidden', 'other/1/x.html']) {
    assert.equal(normalizeArtifactKey(key), null, key);
  }
  assert.equal(normalizeArtifactKey('reports\\7\\a.html'), 'reports/7/a.html');
  await assert.rejects(
    listReferencedArtifacts(rowsClient([{ id: 5, report_id: 1, storage_key: '../../etc/shadow', sha256: null }])),
    (err) => err.code === 'TL_ARTIFACT_UNSAFE_KEY'
  );
});

test('verification detects missing, damaged, undeclared and duplicate entries and count drift', async () => {
  const fx = await fixture();
  try {
    const { bundleDir, result } = await collect(fx);
    const comp = { file_count: 3, bytes: result.totalBytes };
    const base = path.join(bundleDir, 'files/threat-library');
    const indexPath = path.join(bundleDir, THREAT_LIBRARY_INDEX_FILE);
    const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));

    assert.equal((await verifyThreatLibraryComponent(bundleDir, { ...comp, file_count: 4 })).errorCode, 'TL_COUNT_MISMATCH');
    assert.equal((await verifyThreatLibraryComponent(bundleDir, { ...comp, bytes: 1 })).errorCode, 'TL_COUNT_MISMATCH');

    await fs.promises.writeFile(path.join(base, 'reports', 'stray.txt'), 'x');
    assert.equal((await verifyThreatLibraryComponent(bundleDir, comp)).errorCode, 'TL_INDEX_INVALID');
    await fs.promises.rm(path.join(base, 'reports', 'stray.txt'));

    const dup = { ...index, files: [...index.files, index.files[0]] };
    fs.writeFileSync(indexPath, JSON.stringify(dup));
    assert.match((await verifyThreatLibraryComponent(bundleDir, comp)).error, /Duplicate/);

    const evil = { ...index, files: [{ ...index.files[0], key: 'reports/1/../../../etc/passwd' }] };
    fs.writeFileSync(indexPath, JSON.stringify(evil));
    assert.match((await verifyThreatLibraryComponent(bundleDir, comp)).error, /Unsafe/);

    fs.writeFileSync(indexPath, JSON.stringify(index));
    await fs.promises.appendFile(path.join(base, fx.html1.key), 'x');
    assert.equal((await verifyThreatLibraryComponent(bundleDir, comp)).errorCode, 'TL_ARTIFACT_CORRUPT');

    await fs.promises.rm(path.join(base, fx.html1.key));
    assert.equal((await verifyThreatLibraryComponent(bundleDir, comp)).errorCode, 'TL_ARTIFACT_MISSING');

    await fs.promises.rm(indexPath);
    assert.equal((await verifyThreatLibraryComponent(bundleDir, comp)).errorCode, 'TL_INDEX_MISSING');
  } finally {
    await fx.cleanup();
  }
});

test('snapshot capture holds the artifact lock only around snapshot + copy, and releases on failure', async () => {
  const fx = await fixture();
  try {
    const client = rowsClient(fx.rows);
    const bundleDir = path.join(fx.work, 'snap');
    const cap = await captureThreatLibrarySnapshot(client, { storageRoot: fx.storage, bundleDir });
    assert.equal(cap.snapshot, '00000003-0000001B-1');
    assert.equal(cap.fileCount, 3);
    const order = client.queries.map((q) => q.replace(/\s+/g, ' '));
    const idx = (needle) => order.findIndex((q) => q.includes(needle));
    assert.ok(idx('pg_advisory_lock(') < idx('BEGIN ISOLATION LEVEL REPEATABLE READ'));
    assert.ok(idx('BEGIN ISOLATION') < idx('pg_export_snapshot'));
    assert.ok(idx('FROM threat_report_artifacts') < idx('pg_advisory_unlock('));
    // the snapshot transaction stays open for pg_dump until release()
    assert.equal(idx('ROLLBACK'), -1);
    await cap.release();
    await cap.release();
    assert.equal(order.length + 1, client.queries.length, 'release is idempotent');

    // failure while copying: lock released and snapshot rolled back
    await fs.promises.rm(path.join(fx.storage, fx.pdf.key));
    const failing = rowsClient(fx.rows);
    await assert.rejects(
      captureThreatLibrarySnapshot(failing, { storageRoot: fx.storage, bundleDir: path.join(fx.work, 'snap2') }),
      (err) => err.code === 'TL_ARTIFACT_MISSING'
    );
    assert.ok(failing.queries.some((q) => q.includes('pg_advisory_unlock')));
    assert.ok(failing.queries.some((q) => q.includes('ROLLBACK')));
    assert.ok(failing.queries.every((q) => !q.includes('lock_shared')));
    assert.equal(typeof THREAT_LIBRARY_ARTIFACT_LOCK, 'string');
  } finally {
    await fx.cleanup();
  }
});

test('manifest summary distinguishes format 3 from legacy backups', () => {
  assert.deepEqual(threatLibraryComponentSummary({ components: { threat_library: { file_count: 4, bytes: 99 } } }), {
    included: true,
    file_count: 4,
    bytes: 99
  });
  assert.deepEqual(threatLibraryComponentSummary({ format_version: 2, components: { postgres: {} } }), {
    included: false,
    file_count: null,
    bytes: null
  });
  assert.equal(threatLibraryComponentSummary(null).included, false);
});
