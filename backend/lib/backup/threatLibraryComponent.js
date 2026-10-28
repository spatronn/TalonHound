// Threat Library source artifacts as a backup component (format version 3).
//
// Bundle layout:
//   files/threat-library/index.json                    file list (key, sha256, bytes, owners)
//   files/threat-library/reports/<id>/<sha256>.<ext>   copies of THREAT_LIBRARY_STORAGE_DIR files
//
// Only files referenced by threat_report_artifacts.storage_key in the backup's
// PostgreSQL snapshot are included, so the database dump and the file set
// describe the same state. Keys are content-addressed, which lets every copy be
// checked against its own name as well as the database sha256.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

export const THREAT_LIBRARY_COMPONENT_DIR = 'files/threat-library';
export const THREAT_LIBRARY_INDEX_FILE = `${THREAT_LIBRARY_COMPONENT_DIR}/index.json`;
export const THREAT_LIBRARY_INDEX_FORMAT = 1;

/**
 * Advisory lock shared by report deletion (shared mode) and the backup's
 * snapshot + file copy phase (exclusive mode): a report's files can never be
 * removed between the snapshot that references them and their copy.
 */
export const THREAT_LIBRARY_ARTIFACT_LOCK = 'talonhound:threat-library-artifact-files';

const KEY_RE = /^reports\/(\d+)\/([A-Za-z0-9._-]+)$/;
const SHA_NAME_RE = /^([0-9a-f]{64})\.[A-Za-z0-9]{1,8}$/;
const MAX_REPORTED = 20;

function componentError(code, message, details = {}) {
  return Object.assign(new Error(message), { code, details });
}

/**
 * Validate a storage key as a confined relative path (`reports/<id>/<file>`).
 * @returns {string|null} normalized key or null when unsafe
 */
export function normalizeArtifactKey(raw) {
  const key = String(raw ?? '').replace(/\\/g, '/');
  const m = KEY_RE.exec(key);
  if (!m) return null;
  if (m[2] === '.' || m[2] === '..' || m[2].startsWith('.')) return null;
  return key;
}

/** sha256 encoded in a content-addressed file name, or null. */
export function shaFromKey(key) {
  const m = SHA_NAME_RE.exec(path.posix.basename(key));
  return m ? m[1] : null;
}

/**
 * Referenced artifact files as seen by `client` (run inside the backup snapshot).
 * One entry per distinct key; rows sharing a key must agree on the sha256.
 */
export async function listReferencedArtifacts(client) {
  const { rows: exists } = await client.query(
    `SELECT to_regclass('public.threat_report_artifacts') IS NOT NULL AS present`
  );
  if (!exists[0]?.present) return [];
  const { rows } = await client.query(
    `SELECT id, report_id, storage_key, sha256
       FROM threat_report_artifacts
      WHERE storage_key IS NOT NULL
      ORDER BY storage_key, id`
  );
  const byKey = new Map();
  for (const row of rows) {
    const key = normalizeArtifactKey(row.storage_key);
    if (!key) {
      throw componentError('TL_ARTIFACT_UNSAFE_KEY', `Unsafe artifact storage key on artifact ${row.id}`, {
        artifact_id: Number(row.id)
      });
    }
    const entry = byKey.get(key) || { key, sha256: null, artifact_ids: [], report_ids: [] };
    const sha = row.sha256 ? String(row.sha256).toLowerCase() : null;
    if (sha && entry.sha256 && sha !== entry.sha256) {
      throw componentError('TL_ARTIFACT_CORRUPT', `Conflicting sha256 for ${key}`, { keys: [key] });
    }
    entry.sha256 = entry.sha256 || sha;
    entry.artifact_ids.push(Number(row.id));
    if (!entry.report_ids.includes(Number(row.report_id))) entry.report_ids.push(Number(row.report_id));
    byKey.set(key, entry);
  }
  return [...byKey.values()];
}

/** Stream-copy src → dest while hashing; dest is created exclusively. */
async function copyWithHash(src, dest, { openRead = fs.createReadStream } = {}) {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  await fs.promises.mkdir(path.dirname(dest), { recursive: true, mode: 0o750 });
  const hashing = new Transform({
    transform(chunk, _enc, cb) {
      hash.update(chunk);
      bytes += chunk.length;
      cb(null, chunk);
    }
  });
  await pipeline(openRead(src), hashing, fs.createWriteStream(dest, { flags: 'wx', mode: 0o640 }));
  return { sha256: hash.digest('hex'), bytes };
}

/**
 * Copy every referenced artifact into `<bundleDir>/files/threat-library/` and
 * write the index. Fails (throws) on any missing, unreadable or corrupt file:
 * a backup that silently lacks a referenced source is not a recovery point.
 *
 * @param {{ entries: object[], storageRoot: string, bundleDir: string, openRead?: Function }} input
 * @returns {Promise<{ fileCount: number, totalBytes: number, relPaths: string[], index: object }>}
 */
export async function copyThreatLibraryArtifacts({ entries, storageRoot, bundleDir, openRead }) {
  const root = path.resolve(storageRoot);
  const outRoot = path.join(bundleDir, THREAT_LIBRARY_COMPONENT_DIR);
  await fs.promises.mkdir(outRoot, { recursive: true, mode: 0o750 });
  const missing = [];
  const corrupt = [];
  const unreadable = [];
  const files = [];
  for (const entry of entries) {
    const src = path.join(root, ...entry.key.split('/'));
    const dest = path.join(outRoot, ...entry.key.split('/'));
    let copied;
    try {
      copied = await copyWithHash(src, dest, { openRead });
    } catch (err) {
      await fs.promises.rm(dest, { force: true }).catch(() => {});
      if (err.code === 'ENOENT') missing.push(entry.key);
      else unreadable.push(`${entry.key} (${err.code || 'read error'})`);
      continue;
    }
    const expected = [shaFromKey(entry.key), entry.sha256].filter(Boolean);
    if (expected.some((sha) => sha !== copied.sha256)) {
      corrupt.push(entry.key);
      continue;
    }
    files.push({
      key: entry.key,
      sha256: copied.sha256,
      bytes: copied.bytes,
      artifact_ids: entry.artifact_ids,
      report_ids: entry.report_ids
    });
  }
  if (missing.length) {
    throw componentError(
      'TL_ARTIFACT_MISSING',
      `${missing.length} referenced Threat Library file(s) missing: ${missing.slice(0, MAX_REPORTED).join(', ')}`,
      { keys: missing }
    );
  }
  if (corrupt.length) {
    throw componentError(
      'TL_ARTIFACT_CORRUPT',
      `${corrupt.length} Threat Library file(s) do not match their checksum: ${corrupt.slice(0, MAX_REPORTED).join(', ')}`,
      { keys: corrupt }
    );
  }
  if (unreadable.length) {
    throw componentError(
      'TL_ARTIFACT_UNREADABLE',
      `${unreadable.length} Threat Library file(s) could not be read: ${unreadable.slice(0, MAX_REPORTED).join(', ')}`,
      { keys: unreadable }
    );
  }
  const totalBytes = files.reduce((n, f) => n + f.bytes, 0);
  const index = {
    format: THREAT_LIBRARY_INDEX_FORMAT,
    layout: 'content-addressed',
    file_count: files.length,
    total_bytes: totalBytes,
    files
  };
  await fs.promises.writeFile(
    path.join(bundleDir, THREAT_LIBRARY_INDEX_FILE),
    `${JSON.stringify(index, null, 1)}\n`,
    { encoding: 'utf8', mode: 0o640 }
  );
  return {
    fileCount: files.length,
    totalBytes,
    relPaths: files.map((f) => `${THREAT_LIBRARY_COMPONENT_DIR}/${f.key}`),
    index
  };
}

/**
 * Snapshot-consistent capture. On a dedicated client: take the artifact lock
 * exclusively, open a REPEATABLE READ snapshot, export it for pg_dump, copy
 * the files referenced in it, then release the lock (deletes may proceed; they
 * cannot affect the exported snapshot or the copies already made).
 *
 * The returned transaction stays open until `release()` so pg_dump can import
 * the snapshot; always call `release()` (it is idempotent).
 */
export async function captureThreatLibrarySnapshot(client, {
  storageRoot,
  bundleDir,
  lockTimeoutMs = 120_000,
  openRead
}) {
  let inTx = false;
  let locked = false;
  const release = async () => {
    if (locked) {
      locked = false;
      await client.query('SELECT pg_advisory_unlock(hashtext($1)::bigint)', [THREAT_LIBRARY_ARTIFACT_LOCK]).catch(() => {});
    }
    if (inTx) {
      inTx = false;
      await client.query('ROLLBACK').catch(() => {});
    }
  };
  try {
    await client.query(`SET lock_timeout = ${Math.max(1000, Math.trunc(lockTimeoutMs))}`);
    await client.query('SELECT pg_advisory_lock(hashtext($1)::bigint)', [THREAT_LIBRARY_ARTIFACT_LOCK]);
    locked = true;
    await client.query('RESET lock_timeout');
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    inTx = true;
    const { rows } = await client.query('SELECT pg_export_snapshot() AS snapshot');
    const snapshot = rows[0].snapshot;
    const entries = await listReferencedArtifacts(client);
    const copied = await copyThreatLibraryArtifacts({ entries, storageRoot, bundleDir, openRead });
    await client.query('SELECT pg_advisory_unlock(hashtext($1)::bigint)', [THREAT_LIBRARY_ARTIFACT_LOCK]);
    locked = false;
    return { snapshot, ...copied, release };
  } catch (err) {
    await release();
    if (err.code === '55P03') {
      throw componentError('TL_ARTIFACT_LOCK_TIMEOUT', 'Timed out waiting for Threat Library deletions to finish');
    }
    throw err;
  }
}

/**
 * Verify the Threat Library component of an unpacked bundle against its
 * manifest entry. Every file must exist once, match its index checksum, its
 * content-addressed name and size, with no undeclared files present.
 *
 * @returns {Promise<{ ok: boolean, errorCode?: string, error?: string, fileCount?: number, totalBytes?: number, index?: object }>}
 */
export async function verifyThreatLibraryComponent(bundleDir, component) {
  const fail = (errorCode, error) => ({ ok: false, errorCode, error });
  const base = path.join(bundleDir, THREAT_LIBRARY_COMPONENT_DIR);
  let index;
  try {
    index = JSON.parse(await fs.promises.readFile(path.join(bundleDir, THREAT_LIBRARY_INDEX_FILE), 'utf8'));
  } catch {
    return fail('TL_INDEX_MISSING', 'Threat Library index.json missing or unreadable');
  }
  if (index?.format !== THREAT_LIBRARY_INDEX_FORMAT || !Array.isArray(index.files)) {
    return fail('TL_INDEX_INVALID', `Unsupported Threat Library index format ${index?.format}`);
  }
  const seen = new Set();
  let totalBytes = 0;
  const missing = [];
  const corrupt = [];
  for (const f of index.files) {
    const key = normalizeArtifactKey(f?.key);
    if (!key || key !== f.key) return fail('TL_INDEX_INVALID', `Unsafe Threat Library path in index: ${String(f?.key)}`);
    if (seen.has(key)) return fail('TL_INDEX_INVALID', `Duplicate Threat Library path in index: ${key}`);
    seen.add(key);
    if (!/^[0-9a-f]{64}$/.test(String(f.sha256))) return fail('TL_INDEX_INVALID', `Invalid sha256 for ${key}`);
    const abs = path.join(base, ...key.split('/'));
    let st;
    try {
      st = await fs.promises.lstat(abs);
    } catch {
      missing.push(key);
      continue;
    }
    if (!st.isFile()) return fail('TL_INDEX_INVALID', `Not a regular file: ${key}`);
    const hash = crypto.createHash('sha256');
    await pipeline(fs.createReadStream(abs), hash);
    const actual = hash.digest('hex');
    const nameSha = shaFromKey(key);
    if (actual !== f.sha256 || st.size !== Number(f.bytes) || (nameSha && nameSha !== actual)) corrupt.push(key);
    totalBytes += st.size;
  }
  if (missing.length) {
    return fail('TL_ARTIFACT_MISSING', `Missing Threat Library files: ${missing.slice(0, MAX_REPORTED).join(', ')}`);
  }
  if (corrupt.length) {
    return fail('TL_ARTIFACT_CORRUPT', `Damaged Threat Library files: ${corrupt.slice(0, MAX_REPORTED).join(', ')}`);
  }
  // Undeclared entries (extra files, links, nested dirs outside the index).
  const extra = [];
  const walk = async (dir, rel) => {
    for (const ent of await fs.promises.readdir(dir, { withFileTypes: true })) {
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) await walk(path.join(dir, ent.name), r);
      else if (r !== 'index.json' && !seen.has(r)) extra.push(r);
    }
  };
  await walk(base, '');
  if (extra.length) {
    return fail('TL_INDEX_INVALID', `Undeclared files in Threat Library component: ${extra.slice(0, MAX_REPORTED).join(', ')}`);
  }
  const declaredCount = Number(component?.file_count ?? index.file_count);
  const declaredBytes = Number(component?.bytes ?? index.total_bytes);
  if (index.files.length !== declaredCount || index.files.length !== Number(index.file_count)) {
    return fail('TL_COUNT_MISMATCH', `Threat Library file count ${index.files.length} != declared ${declaredCount}`);
  }
  if (totalBytes !== declaredBytes) {
    return fail('TL_COUNT_MISMATCH', `Threat Library bytes ${totalBytes} != declared ${declaredBytes}`);
  }
  return { ok: true, fileCount: index.files.length, totalBytes, index };
}

/** Summary of the Threat Library component recorded in a manifest (null for legacy backups). */
export function threatLibraryComponentSummary(manifest) {
  const c = manifest?.components?.threat_library;
  if (!c) return { included: false, file_count: null, bytes: null };
  return { included: true, file_count: Number(c.file_count || 0), bytes: Number(c.bytes || 0) };
}
