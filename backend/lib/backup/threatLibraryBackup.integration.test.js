// Real PostgreSQL + pg_dump/pg_restore. Run against a migrated throwaway database:
//   ALLOW_BACKUP_DB_TESTS=1 DB_HOST=... DB_USER=... DB_PASSWORD=... DB_NAME=... \
//     node --test lib/backup/threatLibraryBackup.integration.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import pg from 'pg';
import { createBackupRow, getBackupById } from './backupStore.js';
import { generateBackupId } from './ids.js';
import { executeBackupJob } from './runBackup.js';
import { verifyBackupArchive } from './verify.js';
import { THREAT_LIBRARY_ARTIFACT_LOCK, captureThreatLibrarySnapshot } from './threatLibraryComponent.js';
import { storeArtifactBuffer } from '../threatLibrary/artifactStore.js';
import { createThreatReport, deleteThreatReport, insertArtifact } from '../threatLibrary/store.js';

const enabled =
  process.env.ALLOW_BACKUP_DB_TESTS === '1' &&
  spawnSync('pg_dump', ['--version']).status === 0 &&
  spawnSync('pg_restore', ['--version']).status === 0;
const skip = enabled ? false : 'set ALLOW_BACKUP_DB_TESTS=1 with pg_dump/pg_restore and a migrated database';
// CI sets REQUIRE_BACKUP_DB_TESTS=1 so a missing precondition fails instead of skipping.
const required = process.env.REQUIRE_BACKUP_DB_TESTS === '1';

test('backup integration preconditions', { skip: required ? false : 'not required' }, () => {
  assert.ok(enabled, 'ALLOW_BACKUP_DB_TESTS=1, pg_dump and pg_restore are required');
});

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function makePool() {
  return new pg.Pool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    max: 6
  });
}

async function withEnv(t, fn) {
  const base = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-tl-backup-it-'));
  const prev = { BACKUP_DIR: process.env.BACKUP_DIR, THREAT_LIBRARY_STORAGE_DIR: process.env.THREAT_LIBRARY_STORAGE_DIR };
  process.env.BACKUP_DIR = path.join(base, 'backups');
  process.env.THREAT_LIBRARY_STORAGE_DIR = path.join(base, 'tl');
  const pool = makePool();
  const reports = [];
  const backups = [];
  try {
    // Backups copy every referenced artifact; files owned by other data in a
    // shared database are not in this test's temporary storage root.
    const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM threat_report_artifacts WHERE storage_key IS NOT NULL');
    if (rows[0].n > 0) {
      assert.ok(!required, `database already references ${rows[0].n} Threat Library files`);
      t.skip(`database already references ${rows[0].n} Threat Library files; use a dedicated migrated database`);
      return;
    }
    await fn({ pool, base, reports, backups });
  } finally {
    for (const id of reports) {
      await pool.query('DELETE FROM threat_report_artifacts WHERE report_id = $1', [id]).catch(() => {});
      await pool.query('DELETE FROM threat_library_jobs WHERE report_id = $1', [id]).catch(() => {});
      await pool.query('DELETE FROM threat_reports WHERE id = $1', [id]).catch(() => {});
    }
    for (const id of backups) await pool.query('DELETE FROM system_backups WHERE id = $1', [id]).catch(() => {});
    await pool.end();
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await fs.promises.rm(base, { recursive: true, force: true });
  }
}

async function seedReport(pool, reports, artifacts) {
  const report = await createThreatReport(pool, {
    title: `backup-it ${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: `https://example.test/${crypto.randomUUID()}`,
    import_status: 'ready',
    analysis_status: 'ready'
  });
  reports.push(Number(report.id));
  const stored = [];
  for (const [content, ext, type] of artifacts) {
    const s = await storeArtifactBuffer(report.id, Buffer.from(content), { ext });
    await insertArtifact(pool, report.id, {
      artifact_type: type,
      file_name: `source${ext}`,
      size_bytes: s.sizeBytes,
      sha256: s.sha256,
      storage_key: s.storageKey
    });
    stored.push(s);
  }
  return { report, stored };
}

async function runBackup(pool, backups) {
  const row = await createBackupRow(pool, { backupId: generateBackupId(), triggerType: 'manual' });
  backups.push(row.id);
  await executeBackupJob(pool, row.id, { logger: {} });
  return getBackupById(pool, row.id);
}

async function iocAndReviewFingerprint(pool) {
  const { rows } = await pool.query(
    `SELECT (SELECT COUNT(*) FROM ioc_items)::bigint AS iocs,
            (SELECT COALESCE(md5(string_agg(id::text || ':' || COALESCE(review_status, ''), ',' ORDER BY id)), '')
               FROM threat_report_candidates) AS reviews`
  );
  return rows[0];
}

test('complete backup: database + Threat Library files from one snapshot, verified and sized', { skip }, async (t) => {
  await withEnv(t, async ({ pool, reports, backups }) => {
    const a = await seedReport(pool, reports, [['<html>one</html>', '.html', 'url_fetch']]);
    const b = await seedReport(pool, reports, [['%PDF-1.7 two', '.pdf', 'pdf_upload'], ['<html>two</html>', '.html', 'url_fetch']]);
    const before = await iocAndReviewFingerprint(pool);

    const row = await runBackup(pool, backups);
    assert.equal(row.status, 'completed', `${row.error_code}: ${row.error_message}`);
    assert.equal(row.verify_status, 'passed');
    assert.equal(row.manifest.format_version, 3);
    const tl = row.manifest.components.threat_library;
    const ours = [...a.stored, ...b.stored];
    assert.ok(tl.file_count >= ours.length);
    assert.ok(Number(row.files_size_bytes) > 0);
    assert.equal(Number(row.files_size_bytes), tl.bytes);

    const verified = await verifyBackupArchive(path.join(process.env.BACKUP_DIR, row.archive_filename));
    assert.equal(verified.ok, true, verified.error);
    assert.equal(verified.threatLibrary.file_count, tl.file_count);

    // Repeating the backup with unchanged sources yields the same file set.
    const again = await runBackup(pool, backups);
    assert.equal(again.status, 'completed');
    assert.equal(again.manifest.components.threat_library.bytes, tl.bytes);
    assert.deepEqual(await iocAndReviewFingerprint(pool), before, 'backups never change IOC or review data');
  });
});

test('report deletion waits for the snapshot copy and cannot remove files a snapshot references', { skip }, async (t) => {
  await withEnv(t, async ({ pool, base, reports }) => {
    const { report, stored } = await seedReport(pool, reports, [['<html>deleted-later</html>', '.html', 'url_fetch']]);
    const client = await pool.connect();
    try {
      await client.query('SELECT pg_advisory_lock(hashtext($1)::bigint)', [THREAT_LIBRARY_ARTIFACT_LOCK]);
      let finished = false;
      const deleting = deleteThreatReport(pool, report.id).then(() => { finished = true; });
      await new Promise((r) => setTimeout(r, 400));
      assert.equal(finished, false, 'delete blocks while a backup holds the artifact lock');
      assert.ok(fs.existsSync(path.join(process.env.THREAT_LIBRARY_STORAGE_DIR, stored[0].storageKey)));
      await client.query('SELECT pg_advisory_unlock(hashtext($1)::bigint)', [THREAT_LIBRARY_ARTIFACT_LOCK]);
      await deleting;
      assert.equal(fs.existsSync(path.join(process.env.THREAT_LIBRARY_STORAGE_DIR, stored[0].storageKey)), false);
    } finally {
      client.release();
    }

    // Snapshot first, delete after: the snapshot still sees the row and the copy holds the file.
    const second = await seedReport(pool, reports, [['<html>snapshot-isolated</html>', '.html', 'url_fetch']]);
    const snapClient = await pool.connect();
    const bundleDir = path.join(base, 'bundle');
    try {
      const cap = await captureThreatLibrarySnapshot(snapClient, {
        storageRoot: process.env.THREAT_LIBRARY_STORAGE_DIR,
        bundleDir
      });
      await deleteThreatReport(pool, second.report.id);
      const { rows } = await snapClient.query('SELECT COUNT(*)::int AS n FROM threat_report_artifacts WHERE report_id = $1', [
        second.report.id
      ]);
      assert.equal(rows[0].n, 1, 'exported snapshot still references the deleted report');
      const copied = path.join(bundleDir, 'files/threat-library', second.stored[0].storageKey);
      assert.equal(sha(fs.readFileSync(copied)), second.stored[0].sha256);
      await cap.release();
    } finally {
      snapClient.release();
    }
  });
});

test('a corrupt artifact fails the backup, publishes nothing and keeps the previous archive', { skip }, async (t) => {
  await withEnv(t, async ({ pool, reports, backups }) => {
    const { stored } = await seedReport(pool, reports, [['<html>will-be-damaged</html>', '.html', 'url_fetch']]);
    const good = await runBackup(pool, backups);
    assert.equal(good.status, 'completed');
    const goodArchive = path.join(process.env.BACKUP_DIR, good.archive_filename);
    const goodSha = sha(fs.readFileSync(goodArchive));

    fs.writeFileSync(path.join(process.env.THREAT_LIBRARY_STORAGE_DIR, stored[0].storageKey), 'damaged');
    const bad = await runBackup(pool, backups);
    assert.equal(bad.status, 'failed');
    assert.equal(bad.error_code, 'TL_ARTIFACT_CORRUPT');
    assert.equal(bad.archive_filename, null);
    assert.deepEqual(
      fs.readdirSync(process.env.BACKUP_DIR).filter((f) => f.endsWith('.tar.gz')),
      [good.archive_filename]
    );
    assert.equal(sha(fs.readFileSync(goodArchive)), goodSha);
    assert.deepEqual(fs.readdirSync(path.join(process.env.BACKUP_DIR, '.tmp')), [], 'failed job left no staging');
  });
});
