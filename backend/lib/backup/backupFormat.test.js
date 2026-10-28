import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { assertSafeTarMembers } from './archive.js';
import { writeChecksumsFile } from './checksums.js';
import { BACKUP_FORMAT_VERSION, BACKUP_INCLUDED } from './config.js';
import { buildManifest, parseManifest } from './manifest.js';
import { verifyBundleDirectory } from './verify.js';

async function bundle({ manifest, withTl = false }) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-bk-format-'));
  await fs.promises.mkdir(path.join(dir, 'database'), { recursive: true });
  await fs.promises.writeFile(path.join(dir, 'database', 'postgres.dump'), 'PGDMP fake');
  const rels = ['database/postgres.dump'];
  if (withTl) {
    await fs.promises.mkdir(path.join(dir, 'files', 'threat-library'), { recursive: true });
    await fs.promises.writeFile(
      path.join(dir, 'files/threat-library/index.json'),
      JSON.stringify({ format: 1, layout: 'content-addressed', file_count: 0, total_bytes: 0, files: [] })
    );
    rels.push('files/threat-library/index.json');
  }
  await writeChecksumsFile(dir, rels);
  await fs.promises.writeFile(path.join(dir, 'manifest.json'), JSON.stringify(manifest));
  return dir;
}

test('new backups are format 3 and declare Threat Library artifacts', () => {
  assert.equal(BACKUP_FORMAT_VERSION, 3);
  assert.ok(BACKUP_INCLUDED.includes('threat_library_artifacts'));
  const m = buildManifest({
    backupId: 'backup-x',
    components: { postgresBytes: 10, filesBytes: 5, threatLibrary: { fileCount: 2, totalBytes: 5 } }
  });
  assert.equal(m.format_version, 3);
  assert.deepEqual(m.components.threat_library, {
    path: 'files/threat-library/',
    index: 'files/threat-library/index.json',
    file_count: 2,
    bytes: 5,
    storage_root: 'THREAT_LIBRARY_STORAGE_DIR',
    layout: 'content-addressed'
  });
  assert.equal(m.component_sizes.files_bytes, 5);
  assert.ok(!JSON.stringify(m).includes('/data/'), 'no absolute host paths in the manifest');
});

test('legacy format 2 (PostgreSQL-only) bundles still verify and report no Threat Library files', async () => {
  const dir = await bundle({
    manifest: { format_version: 2, backup_id: 'backup-legacy', application: 'TalonHound', components: { postgres: { file: 'database/postgres.dump' } } }
  });
  try {
    const r = await verifyBundleDirectory(dir, { skipPgRestoreList: true });
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.threatLibrary, { included: false, file_count: null, bytes: null });
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true });
  }
});

test('format 3 bundles must carry a valid Threat Library component', async () => {
  const missing = await bundle({ manifest: { format_version: 3, backup_id: 'b3', components: { postgres: {} } } });
  const ok = await bundle({
    withTl: true,
    manifest: { format_version: 3, backup_id: 'b3ok', components: { postgres: {}, threat_library: { file_count: 0, bytes: 0 } } }
  });
  try {
    assert.equal((await verifyBundleDirectory(missing, { skipPgRestoreList: true })).errorCode, 'TL_COMPONENT_MISSING');
    const r = await verifyBundleDirectory(ok, { skipPgRestoreList: true });
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.threatLibrary, { included: true, file_count: 0, bytes: 0 });
  } finally {
    await fs.promises.rm(missing, { recursive: true, force: true });
    await fs.promises.rm(ok, { recursive: true, force: true });
  }
});

test('unsupported future format versions are refused', () => {
  assert.throws(() => parseManifest({ format_version: 4, backup_id: 'x' }), /Unsupported backup format version: 4/);
  assert.equal(parseManifest({ format_version: 2, backup_id: 'x' }).format_version, 2);
});

test('archives with duplicate, absolute or traversal members are rejected', () => {
  assert.throws(
    () => assertSafeTarMembers(['b/', 'b/files/threat-library/reports/1/a.html', 'b/files/threat-library/reports/1/a.html']),
    /Duplicate archive member/
  );
  assert.throws(() => assertSafeTarMembers(['b/', 'b/x/', 'b/x']), /Duplicate/);
  assert.throws(() => assertSafeTarMembers(['b/files/../../etc/cron.d/x']), /Unsafe/);
  assert.throws(() => assertSafeTarMembers(['/etc/passwd']), /Unsafe/);
  assert.doesNotThrow(() => assertSafeTarMembers(['b/', 'b/manifest.json', 'b/files/threat-library/index.json']));
});
