// Tar.gz archive create / extract helpers (Node zlib + tar via child_process or manual).
// Prefer system `tar` when available; fall back to a minimal gzip+tar via `tar` CLI.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createReadStream, createWriteStream } from 'node:fs';
import { createGzip, createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { sha256File } from './checksums.js';

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      ...opts
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => { stdout += d.toString(); });
    child.stderr?.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve({ stdout, stderr, code });
      else {
        const err = new Error(`${cmd} exited ${code}: ${stderr || stdout}`);
        err.code = 'ARCHIVE_FAILED';
        err.stderr = stderr;
        reject(err);
      }
    });
  });
}

/**
 * Reject ZipSlip / unsafe members before extract (aligned with scripts/lib/backup-common.sh).
 * @param {string[]} members from listTarGz
 */
export function assertSafeTarMembers(members) {
  const list = Array.isArray(members) ? members : [];
  for (const raw of list) {
    const name = String(raw || '').replace(/\\/g, '/');
    if (!name) continue;
    if (name.startsWith('/') || /^[A-Za-z]:\//.test(name) || name.includes('://')) {
      const err = new Error(`Unsafe archive member rejected: ${name}`);
      err.code = 'UNSAFE_ARCHIVE_MEMBER';
      throw err;
    }
    if (name.split('/').some((p) => p === '..')) {
      const err = new Error(`Unsafe archive member rejected: ${name}`);
      err.code = 'UNSAFE_ARCHIVE_MEMBER';
      throw err;
    }
  }
}

/**
 * Pack directory `bundleDir` (which should be named backup-...) into a temporary
 * .tar.gz under tmpDir, then atomically rename to finalPath.
 */
export async function createTarGzAtomic(bundleDir, finalPath, { tmpDir } = {}) {
  const parent = path.dirname(finalPath);
  const stagingTmp = tmpDir || path.join(parent, '.tmp');
  await fs.promises.mkdir(stagingTmp, { recursive: true });
  const tmpArchive = path.join(
    stagingTmp,
    `.partial-${path.basename(finalPath)}.${process.pid}.${Date.now()}`
  );

  const bundleParent = path.dirname(bundleDir);
  const bundleName = path.basename(bundleDir);

  try {
    // GNU/BSD tar: create gzip archive of the single top-level directory
    await run('tar', ['-czf', tmpArchive, '-C', bundleParent, bundleName]);
  } catch (firstErr) {
    // Windows host without tar may fail; try with --force-local
    try {
      await run('tar', ['-czf', tmpArchive, '-C', bundleParent, bundleName]);
    } catch {
      throw firstErr;
    }
  }

  // Never leave a partial file at the final name
  await fs.promises.rename(tmpArchive, finalPath);
  const size = (await fs.promises.stat(finalPath)).size;
  if (size <= 0) {
    await fs.promises.unlink(finalPath).catch(() => {});
    throw Object.assign(new Error('Archive size is zero'), { code: 'ARCHIVE_FAILED' });
  }
  const checksum = await sha256File(finalPath);
  return { path: finalPath, size, checksum };
}

/** Extract tar.gz into destDir (created if needed). Validates members first. */
export async function extractTarGz(archivePath, destDir) {
  const members = await listTarGz(archivePath);
  assertSafeTarMembers(members);
  // Verbose listing catches symlink/hardlink type flags (GNU/BSD tar -tvzf).
  const { stdout: verbose } = await run('tar', ['-tvzf', archivePath]);
  for (const line of verbose.split(/\r?\n/).filter(Boolean)) {
    // First field is type+mode; symlink/hardlink start with 'l' or 'h' (UNIX).
    if (/^[lh]/.test(line.trim())) {
      const err = new Error('Archive contains symlink or hardlink entries');
      err.code = 'UNSAFE_ARCHIVE_MEMBER';
      throw err;
    }
  }
  await fs.promises.mkdir(destDir, { recursive: true });
  await run('tar', ['-xzf', archivePath, '-C', destDir]);
  return destDir;
}

/** List top-level entries of a tar.gz without full extract (best-effort). */
export async function listTarGz(archivePath) {
  const { stdout } = await run('tar', ['-tzf', archivePath]);
  return stdout.split(/\r?\n/).filter(Boolean);
}

export async function gzipFile(src, dest) {
  await pipeline(createReadStream(src), createGzip(), createWriteStream(dest));
}

export async function gunzipFile(src, dest) {
  await pipeline(createReadStream(src), createGunzip(), createWriteStream(dest));
}

export async function safeUnlink(p) {
  if (!p) return;
  try {
    await fs.promises.unlink(p);
  } catch (err) {
    if (err?.code !== 'ENOENT') throw err;
  }
}

export async function safeRmRf(dir) {
  if (!dir) return;
  await fs.promises.rm(dir, { recursive: true, force: true });
}
