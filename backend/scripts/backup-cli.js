#!/usr/bin/env node
// CLI for backup operations. Restore execute is delegated to host shell script.
import '../lib/ensure-db-password.js';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import {
  getBackupConfig,
  executeBackupJob,
  verifyBackupArchive,
  generateBackupId
} from '../lib/backup/index.js';
import { loadEncryptionKey } from '../lib/backup/config.js';
import {
  createBackupRow,
  listBackups,
  getBackupByBackupId,
  countActiveBackups
} from '../lib/backup/backupStore.js';
import { assertCanStartBackup } from '../lib/backup/operationLock.js';
import { buildRestoreCliCommand } from '../lib/backup/restoreCli.js';
import { runRetentionSweep } from '../routes/backups.js';
import { createAuditLogService } from '../lib/auditLogService.js';

const { Pool } = pg;

function parseArgs(argv) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.flags.json = true;
    else if (a === '--confirm') out.flags.confirm = true;
    else if (a.startsWith('--backup-id=')) out.flags.backupId = a.slice('--backup-id='.length);
    else if (a === '--backup-id') out.flags.backupId = argv[++i];
    else if (a.startsWith('-')) out.flags[a.replace(/^--?/, '')] = true;
    else out._.push(a);
  }
  return out;
}

function print(obj, asJson) {
  if (asJson) console.log(JSON.stringify(obj, null, 2));
  else if (typeof obj === 'string') console.log(obj);
  else console.log(JSON.stringify(obj, null, 2));
}

async function withPool(fn) {
  const pool = new Pool({
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'demo',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'demo'
  });
  try {
    return await fn(pool);
  } finally {
    await pool.end();
  }
}

async function cmdCreate(args) {
  const cfg = getBackupConfig();
  return withPool(async (pool) => {
    const active = await countActiveBackups(pool);
    assertCanStartBackup(active, cfg.maxConcurrent);
    const backupId = generateBackupId();
    const row = await createBackupRow(pool, {
      backupId,
      triggerType: 'manual',
      createdByEmail: 'cli',
      encrypted: cfg.encryptionEnabled
    });
    // Run inline (CLI does not require BullMQ worker)
    const result = await executeBackupJob(pool, row.id, { logger: console });
    print(
      {
        ok: result?.status === 'completed',
        backup_id: result?.backup_id || backupId,
        status: result?.status,
        archive_filename: result?.archive_filename,
        archive_size_bytes: result?.archive_size_bytes,
        error_code: result?.error_code,
        error_message: result?.error_message
      },
      args.flags.json
    );
    process.exit(result?.status === 'completed' ? 0 : 1);
  });
}

async function cmdList(args) {
  return withPool(async (pool) => {
    const rows = await listBackups(pool, { limit: 100, offset: 0 });
    if (args.flags.json) {
      print(rows, true);
      return;
    }
    for (const r of rows) {
      console.log(
        `${r.created_at?.toISOString?.() || r.created_at}\t${r.backup_id}\t${r.trigger_type}\t${r.status}\t${r.archive_size_bytes || '-'}\t${r.verify_status || '-'}`
      );
    }
  });
}

async function cmdVerify(args) {
  const backupId = args.flags.backupId;
  if (!backupId) {
    console.error('Usage: backup:verify --backup-id <id>');
    process.exit(2);
  }
  return withPool(async (pool) => {
    const row = await getBackupByBackupId(pool, backupId);
    if (!row || row.status !== 'completed' || !row.archive_path) {
      console.error(`Backup not found or not completed: ${backupId}`);
      process.exit(1);
    }
    let key = null;
    if (row.encrypted) key = loadEncryptionKey();
    const result = await verifyBackupArchive(row.archive_path, { encryptionKey: key });
    print({ backup_id: backupId, ...result, ok: result.ok }, args.flags.json);
    process.exit(result.ok ? 0 : 1);
  });
}

async function cmdRetention(args) {
  return withPool(async (pool) => {
    const audit = createAuditLogService(pool);
    const results = await runRetentionSweep(pool, audit, { logger: console });
    print({ deleted: results.filter((r) => r.ok).length, results }, args.flags.json);
  });
}

async function cmdRestore(args) {
  // Does NOT execute restore — prints the privileged CLI command.
  const backupId = args.flags.backupId;
  if (!backupId) {
    console.error('Usage: backup:restore --backup-id <id> --confirm');
    process.exit(2);
  }
  if (!args.flags.confirm) {
    console.error('Refusing to proceed without --confirm');
    console.error(`Dry-run command: ${buildRestoreCliCommand(backupId)}`);
    process.exit(2);
  }
  // Still require an extra confirmation phrase via env or refuse to shell out from Node
  // when not on host with docker compose. Print exact host command.
  const cmd = buildRestoreCliCommand(backupId);
  print(
    {
      message: 'Execute this on the Docker Compose host (API does not run pg_restore):',
      command: cmd,
      note: 'Requires writer services stop/start privileges.'
    },
    args.flags.json
  );
  if (!args.flags.json) {
    console.error('\nThis Node CLI will not invoke docker compose restore for safety.');
    console.error('Run the command above from the repository root on the host.');
  }
  process.exit(0);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] || 'help';
  switch (cmd) {
    case 'create':
      return cmdCreate(args);
    case 'list':
      return cmdList(args);
    case 'verify':
      return cmdVerify(args);
    case 'retention':
      return cmdRetention(args);
    case 'restore':
      return cmdRestore(args);
    default:
      console.log(`Usage: backup-cli.js <create|list|verify|retention|restore> [--json] [--backup-id ID] [--confirm]`);
      process.exit(cmd === 'help' ? 0 : 2);
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
