// End-to-end backup job runner (shared by worker and CLI).

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  getBackupConfig,
  ensureBackupDir,
  loadEncryptionKey,
  BACKUP_INCLUDED,
  BACKUP_EXCLUDED
} from './config.js';
import { generateBackupId, archiveFilenameFor } from './ids.js';
import { buildManifest } from './manifest.js';
import { getProductVersionInfo } from '../productVersion.js';
import { writeChecksumsFile, sha256File } from './checksums.js';
import { createTarGzAtomic, safeRmRf, safeUnlink } from './archive.js';
import { encryptFile } from './encryption.js';
import { assertPgClientTools, runPgDump } from './pgDump.js';
import { verifyBundleDirectory } from './verify.js';
import { createStorageProvider } from './storage/local.js';
import { redactErrorMessage } from './pathSafety.js';
import {
  claimBackup,
  markVerifying,
  markCompleted,
  markFailed
} from './backupStore.js';
import { getLatestMigrationMeta } from '../migrationFiles.js';

function gitSha() {
  try {
    const r = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
    if (r.status === 0) return String(r.stdout || '').trim() || null;
  } catch {
    /* ignore */
  }
  return process.env.GIT_SHA || process.env.SOURCE_COMMIT || null;
}

async function readSchemaVersion(db) {
  try {
    // Public schema version follows repository migration files, not legacy DB history rows.
    const dir = path.join(process.cwd(), 'migrations');
    const { latestMigrationFile } = await getLatestMigrationMeta(dir);
    return latestMigrationFile || null;
  } catch {
    return null;
  }
}

async function readPgVersion(db) {
  try {
    const { rows } = await db.query('SHOW server_version');
    return rows[0]?.server_version || null;
  } catch {
    return null;
  }
}

function writeReadme(bundleDir, backupId) {
  const text = `TalonHound backup bundle
========================
backup_id: ${backupId}

Contents:
- database/postgres.dump  (pg_dump custom format)
- manifest.json
- checksums.sha256

Redis, .env, TLS certs, and regenerable IOC search exports are excluded.

Restore (destructive; host CLI only — stops writer services):

  ./scripts/restore-stack.sh --backup-id ${backupId} --confirm
  # or from an external archive:
  # ./scripts/restore-stack.sh --file /path/to/${backupId}.tar.gz --confirm
`;
  return fs.promises.writeFile(path.join(bundleDir, 'README.txt'), text, 'utf8');
}

/**
 * Execute a queued backup row end-to-end.
 * @returns {Promise<object>} completed or failed row
 */
export async function executeBackupJob(db, rowId, { logger = console } = {}) {
  const cfg = getBackupConfig();
  const started = Date.now();
  const row = await claimBackup(db, rowId);
  if (!row) {
    logger.warn?.(`[backup] claim lost or not claimable id=${rowId}`);
    return null;
  }

  const backupId = row.backup_id;
  ensureBackupDir(cfg.backupDir);
  const storage = createStorageProvider(cfg.backupDir);
  await storage.ensureReady();

  const workRoot = path.join(cfg.backupDir, '.tmp', `${backupId}-${process.pid}`);
  const bundleDir = path.join(workRoot, backupId);

  try {
    await assertPgClientTools();
    await fs.promises.mkdir(path.join(bundleDir, 'database'), { recursive: true });

    const dumpPath = path.join(bundleDir, 'database', 'postgres.dump');
    logger.info?.(`[backup] backup_id=${backupId} pg_dump starting`);
    await runPgDump({
      ...cfg.db,
      outPath: dumpPath,
      timeoutMs: cfg.pgDumpTimeoutMs
    });
    const databaseSizeBytes = (await fs.promises.stat(dumpPath)).size;
    if (databaseSizeBytes <= 0) {
      throw Object.assign(new Error('Empty postgres dump'), { code: 'PG_DUMP_FAILED' });
    }

    await writeChecksumsFile(bundleDir, ['database/postgres.dump']);
    await writeReadme(bundleDir, backupId);

    const schemaVersion = await readSchemaVersion(db);
    const postgresVersion = await readPgVersion(db);
    const dumpChecksum = await sha256File(dumpPath);

    let manifest = buildManifest({
      backupId,
      createdAt: new Date().toISOString(),
      gitSha: gitSha(),
      appVersion: getProductVersionInfo().version,
      schemaVersion,
      postgresVersion,
      triggerType: row.trigger_type,
      result: 'completed',
      encrypted: Boolean(cfg.encryptionEnabled),
      components: { postgresBytes: databaseSizeBytes, filesBytes: 0 },
      checksums: { 'database/postgres.dump': dumpChecksum },
      included: [...BACKUP_INCLUDED],
      excluded: [...BACKUP_EXCLUDED]
    });
    await fs.promises.writeFile(
      path.join(bundleDir, 'manifest.json'),
      JSON.stringify(manifest, null, 2) + '\n',
      'utf8'
    );

    await markVerifying(db, row.id);
    const verified = await verifyBundleDirectory(bundleDir);
    if (!verified.ok) {
      throw Object.assign(new Error(verified.error || 'Verification failed'), {
        code: verified.errorCode || 'VERIFY_FAILED'
      });
    }

    const plainName = archiveFilenameFor(backupId, { encrypted: false });
    const plainPath = path.join(workRoot, plainName);
    const packed = await createTarGzAtomic(bundleDir, plainPath, {
      tmpDir: path.join(cfg.backupDir, '.tmp')
    });

    let finalLocal = packed.path;
    let finalName = plainName;
    let encrypted = false;

    if (cfg.encryptionEnabled) {
      const key = loadEncryptionKey(cfg);
      finalName = archiveFilenameFor(backupId, { encrypted: true });
      const encPath = path.join(workRoot, finalName);
      await encryptFile(packed.path, encPath, key);
      await safeUnlink(packed.path);
      finalLocal = encPath;
      encrypted = true;
    }

    const finalChecksum = await sha256File(finalLocal);
    const finalSize = (await fs.promises.stat(finalLocal)).size;
    // Atomic place into storage root
    const placed = await storage.putFile(finalLocal, finalName);

    manifest = {
      ...manifest,
      encrypted,
      component_sizes: {
        ...manifest.component_sizes,
        archive_bytes: placed.sizeBytes
      },
      checksums: {
        ...manifest.checksums,
        archive: finalChecksum
      }
    };

    const completed = await markCompleted(db, row.id, {
      archivePath: placed.absolutePath,
      archiveFilename: finalName,
      archiveSizeBytes: placed.sizeBytes || finalSize,
      checksumSha256: finalChecksum,
      databaseSizeBytes,
      filesSizeBytes: 0,
      encrypted,
      manifest,
      durationMs: Date.now() - started
    });

    logger.info?.(
      `[backup] backup_id=${backupId} completed size=${placed.sizeBytes} duration_ms=${Date.now() - started}`
    );
    return completed;
  } catch (err) {
    const code = err.code || 'BACKUP_FAILED';
    const message = redactErrorMessage(err.message || 'Backup failed');
    logger.error?.(`[backup] backup_id=${backupId} failed code=${code} msg=${message}`);
    return markFailed(db, row.id, { errorCode: code, errorMessage: message });
  } finally {
    await safeRmRf(workRoot);
  }
}

export { generateBackupId };
