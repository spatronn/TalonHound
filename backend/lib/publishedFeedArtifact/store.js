// File-artifact storage for Published Feed snapshots (Phase 1, million-scale).
//
// Layout:   <root>/<feed-id>/<generation-id>.<txt|json>
// Lifecycle: write to "<final>.part" → fsync + close → atomic rename to "<final>" →
//            caller commits the DB pointer → previous artifact retired on retention sweep.
//
// All paths are server-generated (feed id + random generation id); a defence-in-depth
// guard rejects any resolved path that escapes the configured root. Modeled on the proven
// iocSearchExport storage conventions (resolveExportFilePath / temp+rename semantics).

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function getPublishedFeedArtifactConfig() {
  const n = (name, fallback, min, max) => {
    const raw = Number(process.env[name]);
    let v = Number.isFinite(raw) ? Math.trunc(raw) : fallback;
    if (typeof min === 'number') v = Math.max(v, min);
    if (typeof max === 'number') v = Math.min(v, max);
    return v;
  };
  return {
    storageDir: String(process.env.PUBLISHED_FEED_STORAGE_DIR || '/data/published-feeds'),
    // Keep a superseded artifact this long so in-flight downloads / pointer races survive.
    supersededRetentionMinutes: n('PUBLISHED_FEED_ARTIFACT_RETENTION_MINUTES', 60, 1, 24 * 60),
    // A ".part" older than this is considered abandoned (crash/restart) and reclaimable.
    stalePartMinutes: n('PUBLISHED_FEED_STALE_PART_MINUTES', 30, 1, 24 * 60)
  };
}

/** New opaque generation id used for the artifact filename (never client-supplied). */
export function newGenerationId() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(8).toString('hex')}`;
}

/** Absolute feed directory, guarded to stay under the storage root. */
export function resolveFeedDir(storageDir, feedId) {
  const id = Number(feedId);
  if (!Number.isInteger(id) || id <= 0) throw new Error('Invalid feed id for artifact path');
  const base = path.resolve(storageDir);
  const resolved = path.resolve(base, String(id));
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error('Resolved feed dir escapes storage directory');
  }
  return resolved;
}

/**
 * Absolute artifact path for a (feed, generation, format). fileName is composed from a
 * server-generated generation id; a traversal guard is still applied as defence in depth.
 */
export function resolveArtifactPath(storageDir, feedId, generationId, format) {
  const ext = format === 'json' ? 'json' : 'txt';
  const gen = String(generationId);
  if (!/^[a-z0-9-]+$/i.test(gen)) throw new Error('Invalid generation id');
  const dir = resolveFeedDir(storageDir, feedId);
  const resolved = path.resolve(dir, `${gen}.${ext}`);
  if (!resolved.startsWith(dir + path.sep)) throw new Error('Resolved artifact path escapes feed dir');
  return resolved;
}

/** Resolve a stored relative storage_path ("<feed>/<gen>.<ext>") to an absolute path, guarded. */
export function resolveStoredArtifactPath(storageDir, storagePath) {
  const base = path.resolve(storageDir);
  const rel = String(storagePath || '').replace(/^[/\\]+/, '');
  const resolved = path.resolve(base, rel);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error('Stored artifact path escapes storage directory');
  }
  return resolved;
}

/** Relative storage_path persisted in the DB (portable across storageDir moves). */
export function toRelativeStoragePath(feedId, generationId, format) {
  const ext = format === 'json' ? 'json' : 'txt';
  return `${Number(feedId)}/${generationId}.${ext}`;
}

/**
 * Open a temp (.part) write stream for a new generation. Returns the write stream plus the
 * final + temp absolute paths. The caller streams content, then calls commitArtifact.
 */
export async function openArtifactPartStream(cfg, feedId, generationId, format) {
  const finalPath = resolveArtifactPath(cfg.storageDir, feedId, generationId, format);
  const partPath = `${finalPath}.part`;
  await fs.promises.mkdir(path.dirname(finalPath), { recursive: true });
  const stream = fs.createWriteStream(partPath, { flags: 'w', mode: 0o640 });
  return { stream, finalPath, partPath };
}

/** fsync + close a write stream, resolving only once the bytes are durably flushed. */
export function finalizeStream(stream) {
  return new Promise((resolve, reject) => {
    stream.on('error', reject);
    stream.on('finish', () => {
      fs.open(stream.path, 'r', (openErr, fd) => {
        if (openErr) return resolve(); // best-effort fsync; finish already flushed to OS
        fs.fsync(fd, () => fs.close(fd, () => resolve()));
      });
    });
    stream.end();
  });
}

/** Atomically publish the finished .part as the final artifact (rename is atomic on one fs). */
export async function commitArtifact(partPath, finalPath) {
  await fs.promises.rename(partPath, finalPath);
}

/** Best-effort removal of a temp/part or superseded artifact. Never throws on ENOENT. */
export async function removeFileQuiet(filePath) {
  try {
    await fs.promises.unlink(filePath);
  } catch (err) {
    if (err && err.code !== 'ENOENT') {
      // eslint-disable-next-line no-console
      console.warn('[published-feed-artifact] unlink failed:', err.message);
    }
  }
}

export async function statArtifact(filePath) {
  try {
    return await fs.promises.stat(filePath);
  } catch {
    return null;
  }
}

/**
 * Startup/periodic reconciliation: delete abandoned ".part" files older than stalePartMinutes.
 * Never touches published (non-.part) artifacts. Returns the count removed.
 */
export async function reconcileStaleParts(cfg) {
  const root = path.resolve(cfg.storageDir);
  let removed = 0;
  let feedDirs;
  try {
    feedDirs = await fs.promises.readdir(root, { withFileTypes: true });
  } catch (err) {
    if (err && err.code === 'ENOENT') return 0;
    throw err;
  }
  const cutoff = Date.now() - cfg.stalePartMinutes * 60 * 1000;
  for (const d of feedDirs) {
    if (!d.isDirectory()) continue;
    const dir = path.join(root, d.name);
    let files;
    try { files = await fs.promises.readdir(dir); } catch { continue; }
    for (const f of files) {
      if (!f.endsWith('.part')) continue;
      const p = path.join(dir, f);
      const st = await statArtifact(p);
      if (st && st.mtimeMs < cutoff) {
        await removeFileQuiet(p);
        removed += 1;
      }
    }
  }
  return removed;
}

/**
 * Remove superseded artifact files for a feed: any file in the feed dir that is NOT the
 * currently-referenced storage_path and whose mtime is older than the retention window.
 * Keeps the current artifact and recent ones (in-flight download / pointer-race safety).
 */
export async function cleanupSupersededArtifacts(cfg, feedId, currentStoragePath) {
  let dir;
  try { dir = resolveFeedDir(cfg.storageDir, feedId); } catch { return 0; }
  const currentAbs = currentStoragePath
    ? resolveStoredArtifactPath(cfg.storageDir, currentStoragePath)
    : null;
  let files;
  try { files = await fs.promises.readdir(dir); } catch { return 0; }
  const cutoff = Date.now() - cfg.supersededRetentionMinutes * 60 * 1000;
  let removed = 0;
  for (const f of files) {
    const p = path.join(dir, f);
    if (currentAbs && p === currentAbs) continue;
    if (f.endsWith('.part')) continue; // handled by reconcileStaleParts
    const st = await statArtifact(p);
    if (st && st.mtimeMs < cutoff) {
      await removeFileQuiet(p);
      removed += 1;
    }
  }
  return removed;
}

/** Remove all artifacts for a deleted feed. */
export async function removeFeedArtifacts(cfg, feedId) {
  let dir;
  try { dir = resolveFeedDir(cfg.storageDir, feedId); } catch { return; }
  await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
}
