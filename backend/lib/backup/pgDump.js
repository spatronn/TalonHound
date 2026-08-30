// pg_dump / pg_restore wrappers. Never put password on argv — use PGPASSWORD env.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { createWriteStream } from 'node:fs';
import { redactErrorMessage } from './pathSafety.js';

function whichBinary(name) {
  return new Promise((resolve) => {
    const child = spawn(process.platform === 'win32' ? 'where' : 'which', [name], {
      stdio: ['ignore', 'pipe', 'ignore']
    });
    let out = '';
    child.stdout?.on('data', (d) => { out += d.toString(); });
    child.on('close', (code) => resolve(code === 0 ? out.trim().split(/\r?\n/)[0] : null));
    child.on('error', () => resolve(null));
  });
}

export async function assertPgClientTools() {
  const dump = await whichBinary('pg_dump');
  const restore = await whichBinary('pg_restore');
  if (!dump) {
    const err = new Error('pg_dump binary not found');
    err.code = 'PG_DUMP_MISSING';
    throw err;
  }
  if (!restore) {
    const err = new Error('pg_restore binary not found');
    err.code = 'PG_DUMP_MISSING';
    throw err;
  }
  return { pgDump: dump, pgRestore: restore };
}

/**
 * Run pg_dump -Fc to outPath. Transaction-consistent custom format.
 */
export function runPgDump({ host, port, user, password, database, outPath, timeoutMs = 7_200_000 }) {
  return new Promise((resolve, reject) => {
    const args = [
      '-h', String(host),
      '-p', String(port),
      '-U', String(user),
      '-d', String(database),
      '-Fc',
      '--no-password'
    ];
    const env = { ...process.env, PGPASSWORD: password == null ? '' : String(password) };
    const child = spawn('pg_dump', args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = createWriteStream(outPath);
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      fail(Object.assign(new Error('pg_dump timed out'), { code: 'PG_DUMP_FAILED' }));
    }, timeoutMs);

    function fail(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      out.destroy();
      fs.unlink(outPath, () => {});
      reject(err);
    }

    child.stdout.pipe(out);
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      if (err.code === 'ENOENT') {
        fail(Object.assign(new Error('pg_dump binary not found'), { code: 'PG_DUMP_MISSING' }));
      } else {
        fail(Object.assign(err, { code: 'PG_DUMP_FAILED' }));
      }
    });
    out.on('error', (err) => {
      const code = err.code === 'ENOSPC' ? 'DISK_FULL' : err.code === 'EACCES' ? 'PERMISSION' : 'PG_DUMP_FAILED';
      fail(Object.assign(new Error(redactErrorMessage(err.message)), { code }));
    });
    child.on('close', (code) => {
      if (settled) return;
      clearTimeout(timer);
      out.end(() => {
        if (code !== 0) {
          const msg = redactErrorMessage(stderr || `pg_dump exited ${code}`);
          const errCode = /could not connect|connection refused|timeout/i.test(stderr)
            ? 'PG_CONNECTION'
            : 'PG_DUMP_FAILED';
          fail(Object.assign(new Error(msg), { code: errCode, stderr }));
          return;
        }
        settled = true;
        resolve({ outPath, stderr: redactErrorMessage(stderr) });
      });
    });
  });
}

/** pg_restore --list to validate a custom-format dump is readable. */
export function pgRestoreList(dumpPath, { host, port, user, password, timeoutMs = 120_000 } = {}) {
  return new Promise((resolve, reject) => {
    const args = ['--list', dumpPath];
    // --list does not need a live DB connection for custom-format files
    const env = { ...process.env };
    if (password != null) env.PGPASSWORD = String(password);
    const child = spawn('pg_restore', args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(Object.assign(new Error('pg_restore --list timed out'), { code: 'VERIFY_FAILED' }));
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      if (err.code === 'ENOENT') {
        reject(Object.assign(new Error('pg_restore binary not found'), { code: 'PG_DUMP_MISSING' }));
      } else reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(Object.assign(new Error(redactErrorMessage(stderr || `pg_restore --list exited ${code}`)), {
          code: 'VERIFY_FAILED',
          stderr
        }));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

export function dumpContainsExpectedObjects(listStdout, expected = ['TABLE DATA', 'schema_migrations', 'users']) {
  const text = String(listStdout || '');
  const missing = [];
  for (const token of expected) {
    if (!text.includes(token)) missing.push(token);
  }
  return { ok: missing.length === 0, missing };
}
