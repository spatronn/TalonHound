import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { registerBackupRoutes } from './backups.js';
import { buildRestoreCliCommand } from '../lib/backup/restoreCli.js';

const ANALYST = { role: 'analyst', id: 11, email: 'a@example.com', username: 'a@example.com' };
const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com', username: 'admin@example.com' };

function createMockPool(backups) {
  let seq = 1;
  return {
    async query(sql, params = []) {
      const s = String(sql);

      if (s.includes('INSERT INTO system_backups')) {
        const id = `00000000-0000-4000-8000-${String(seq++).padStart(12, '0')}`;
        const row = {
          id,
          backup_id: params[0],
          trigger_type: params[1],
          encrypted: params[2],
          created_by_id: params[3],
          created_by_email: params[4],
          status: 'queued',
          started_at: null,
          completed_at: null,
          duration_ms: null,
          archive_path: null,
          archive_filename: null,
          archive_size_bytes: null,
          checksum_sha256: null,
          database_size_bytes: null,
          files_size_bytes: 0,
          error_code: null,
          error_message: null,
          verified_at: null,
          verify_status: null,
          verify_error: null,
          manifest: null,
          job_id: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        backups.set(id, row);
        return { rows: [row], rowCount: 1 };
      }

      if (s.includes("status IN ('queued', 'running', 'verifying')") && s.includes('COUNT')) {
        const n = [...backups.values()].filter((r) =>
          ['queued', 'running', 'verifying'].includes(r.status)
        ).length;
        return { rows: [{ n }], rowCount: 1 };
      }

      if (s.includes('COUNT(*)::int AS n') && s.includes('system_backups')) {
        const n = [...backups.values()].filter((r) => r.status !== 'deleted').length;
        return { rows: [{ n }], rowCount: 1 };
      }

      if (s.includes('SUM(archive_size_bytes)')) {
        const n = [...backups.values()]
          .filter((r) => r.status === 'completed')
          .reduce((a, r) => a + Number(r.archive_size_bytes || 0), 0);
        return { rows: [{ n }], rowCount: 1 };
      }

      if (s.includes('SET job_id')) {
        const row = backups.get(params[0]);
        if (row) row.job_id = params[1];
        return { rows: [], rowCount: 1 };
      }

      if (s.includes('FROM system_backups WHERE id = $1')) {
        const row = backups.get(params[0]) || null;
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }

      if (s.includes('FROM system_backups') && s.includes("status = 'completed'") && s.includes('LIMIT 1')) {
        const row = [...backups.values()]
          .filter((r) => r.status === 'completed')
          .sort((a, b) => String(b.completed_at).localeCompare(String(a.completed_at)))[0];
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }

      if (s.includes('FROM system_backups WHERE status = \'completed\'')) {
        return { rows: [...backups.values()].filter((r) => r.status === 'completed'), rowCount: 0 };
      }

      if (s.includes('FROM system_backups') && s.includes("status <> 'deleted'")) {
        let rows = [...backups.values()].filter((r) => r.status !== 'deleted');
        rows.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
        if (s.includes('LIMIT')) {
          const limit = params[params.length - 2];
          const offset = params[params.length - 1];
          rows = rows.slice(offset, offset + limit);
        }
        return { rows, rowCount: rows.length };
      }

      if (s.includes("SET status = 'deleted'")) {
        const row = backups.get(params[0]);
        if (!row || !['completed', 'failed', 'interrupted'].includes(row.status)) {
          return { rows: [], rowCount: 0 };
        }
        row.status = 'deleted';
        row.archive_path = null;
        return { rows: [row], rowCount: 1 };
      }

      if (s.includes('SET verify_status')) {
        const row = backups.get(params[0]);
        if (!row) return { rows: [], rowCount: 0 };
        row.verify_status = params[1];
        row.verify_error = params[2];
        if (params[3]) row.checksum_sha256 = params[3];
        row.verified_at = new Date().toISOString();
        return { rows: [row], rowCount: 1 };
      }

      return { rows: [], rowCount: 0 };
    }
  };
}

async function withApp(fn, { user = ADMIN, backupDir } = {}) {
  const dir = backupDir || (await fs.promises.mkdtemp(path.join(os.tmpdir(), 'th-bk-api-')));
  process.env.BACKUP_DIR = dir;
  const backups = new Map();
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user']
      ? JSON.parse(String(req.headers['x-test-user']))
      : user;
    next();
  });
  const pool = createMockPool(backups);
  const backupQueue = { add: async () => ({ id: 'job-1' }) };
  const auditLogService = { auditSuccess: async () => {}, auditFailure: async () => {} };
  registerBackupRoutes(app, pool, { backupQueue, auditLogService });
  const server = app.listen(0);
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  try {
    await fn({ base, backups, dir, port });
  } finally {
    await new Promise((r) => server.close(r));
    await fs.promises.rm(dir, { recursive: true, force: true });
  }
}

function authHeaders(user) {
  return {
    'Content-Type': 'application/json',
    'x-test-user': JSON.stringify(user)
  };
}

test('non-admin cannot start backup', async () => {
  await withApp(async ({ base }) => {
    const res = await fetch(`${base}/api/backups`, {
      method: 'POST',
      headers: authHeaders(ANALYST)
    });
    assert.equal(res.status, 403);
  }, { user: ANALYST });
});

test('manual backup creates queued job', async () => {
  await withApp(async ({ base, backups }) => {
    const res = await fetch(`${base}/api/backups`, {
      method: 'POST',
      headers: authHeaders(ADMIN)
    });
    assert.equal(res.status, 202);
    const body = await res.json();
    assert.ok(body.backup_id);
    assert.equal(body.status, 'queued');
    assert.equal(backups.size, 1);
  });
});

test('concurrent second backup is rejected', async () => {
  await withApp(async ({ base, backups }) => {
    const first = await fetch(`${base}/api/backups`, { method: 'POST', headers: authHeaders(ADMIN) });
    assert.equal(first.status, 202);
    const row = [...backups.values()][0];
    row.status = 'running';
    const second = await fetch(`${base}/api/backups`, { method: 'POST', headers: authHeaders(ADMIN) });
    assert.equal(second.status, 409);
  });
});

test('download path traversal via filename is blocked', async () => {
  await withApp(async ({ base, backups, dir }) => {
    const id = '00000000-0000-4000-8000-000000000099';
    const evilName = '../evil.tar.gz';
    backups.set(id, {
      id,
      backup_id: 'backup-20260725-120000-aabbcc',
      trigger_type: 'manual',
      status: 'completed',
      archive_filename: evilName,
      archive_path: path.join(dir, evilName),
      archive_size_bytes: 10,
      encrypted: false,
      created_at: new Date().toISOString()
    });
    const res = await fetch(`${base}/api/backups/${id}/download`, {
      headers: authHeaders(ADMIN)
    });
    assert.ok([400, 404].includes(res.status));
  });
});

test('delete rejects active backup', async () => {
  await withApp(async ({ base, backups }) => {
    const id = '00000000-0000-4000-8000-000000000088';
    backups.set(id, {
      id,
      backup_id: 'backup-20260725-120000-active1',
      status: 'running',
      trigger_type: 'manual',
      created_at: new Date().toISOString()
    });
    const res = await fetch(`${base}/api/backups/${id}`, {
      method: 'DELETE',
      headers: authHeaders(ADMIN)
    });
    assert.equal(res.status, 409);
  });
});

test('GUI restore endpoints are removed', async () => {
  await withApp(async ({ base }) => {
    const id = '00000000-0000-4000-8000-000000000077';
    const prepare = await fetch(`${base}/api/backups/${id}/restore/prepare`, {
      method: 'POST',
      headers: authHeaders(ADMIN)
    });
    assert.equal(prepare.status, 404);

    const confirm = await fetch(`${base}/api/backups/${id}/restore/confirm`, {
      method: 'POST',
      headers: authHeaders(ADMIN),
      body: JSON.stringify({ restore_id: id, confirmation: 'RESTORE' })
    });
    assert.equal(confirm.status, 404);

    const getRestore = await fetch(`${base}/api/backups/restores/${id}`, {
      headers: authHeaders(ADMIN)
    });
    assert.equal(getRestore.status, 404);
  });
});

test('buildRestoreCliCommand documents host script', () => {
  const cmd = buildRestoreCliCommand('backup-20260725-120000-aabbcc');
  assert.match(cmd, /restore-stack\.sh/);
  assert.match(cmd, /--backup-id backup-20260725-120000-aabbcc/);
  assert.match(cmd, /--confirm/);
});

test('status endpoint is admin-only and returns safe schedule fields', async () => {
  await withApp(async ({ base }) => {
    const denied = await fetch(`${base}/api/backups/status`, { headers: authHeaders(ANALYST) });
    assert.equal(denied.status, 403);

    const res = await fetch(`${base}/api/backups/status`, { headers: authHeaders(ADMIN) });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(typeof body.enabled, 'boolean');
    assert.ok(body.cron);
    assert.ok(body.timezone);
    assert.ok(body.schedule_summary);
    assert.equal(body.storage_provider, 'local');
    assert.equal(typeof body.encryption_enabled, 'boolean');
    assert.equal(typeof body.retention_days, 'number');
    assert.equal(body.encryption_key_file, undefined);
    assert.equal(body.backup_dir, undefined);
    const raw = JSON.stringify(body);
    assert.ok(!raw.includes('PGPASSWORD'));
  }, { user: ANALYST });
});
