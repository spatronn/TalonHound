// Orphan GC for the Published Feed artifact store — the safety net behind lifecycle cleanup.
//
// Normal failures remove their own files (publishedFeedChunkGeneration / stream generator).
// A killed process cannot, so this sweep reclaims files that no database row references.
// Deletion requires ALL of:
//   - the path matches a known Published Feed layout (anything else is UNKNOWN, never deleted);
//   - the owning feed still exists (removed feeds are handled by removeFeedArtifacts);
//   - the feed's generation advisory lock is held by this sweep, so no generation can be
//     writing files or committing rows for that feed while references are checked and
//     files are unlinked;
//   - no row references the file (chunk rows in any state, generation ids / recency heads,
//     snapshot storage paths);
//   - the file is older than minAgeMinutes and still the same file when re-checked.

import fs from 'node:fs';
import path from 'node:path';
import { getPublishedFeedArtifactConfig } from './store.js';

// Same key as feedPublisherService.publishedFeedGenerationLockKeys (kept local to avoid
// importing the whole service into the store layer).
const GENERATION_LOCK_CLASS = 874290151;

export const ORPHAN_CLASS = Object.freeze({
  REFERENCED: 'referenced',
  PROTECTED: 'protected',
  DELETE_ELIGIBLE: 'delete_eligible',
  UNKNOWN: 'unknown'
});

const FORMAT_EXT = '(txt|json|stix)';
const CHUNK_FILE_RE = new RegExp(
  `^chunks/feed-(\\d+)/(1d|3d|7d|all)/v\\d+/n\\d+/${FORMAT_EXT}/(\\d+)-[a-f0-9]{64}\\.${FORMAT_EXT}$`
);
const CHUNK_PART_RE = new RegExp(
  `^chunks/feed-(\\d+)/(1d|3d|7d|all)/v\\d+/n\\d+/${FORMAT_EXT}/\\.chunk-\\d+-[a-f0-9]+\\.part$`
);
const HEAD_FILE_RE = /^generations\/feed-(\d+)\/([a-z0-9-]+)\.txt-head$/i;
const HEAD_PART_RE = /^generations\/feed-(\d+)\/([a-z0-9-]+)\.txt-head\.part$/i;
const SNAPSHOT_FILE_RE = new RegExp(`^(\\d+)/([a-z0-9-]+)\\.${FORMAT_EXT}$`, 'i');
const SNAPSHOT_TEMP_RE = new RegExp(`^(\\d+)/([a-z0-9-]+)\\.${FORMAT_EXT}\\.(part|body)$`, 'i');

export function resolveOrphanGcMinAgeMinutes(value = process.env.PUBLISHED_FEED_ORPHAN_MIN_AGE_MINUTES) {
  const cfg = getPublishedFeedArtifactConfig();
  const floor = Math.max(cfg.supersededRetentionMinutes, cfg.stalePartMinutes);
  const n = Number(value);
  const requested = Number.isFinite(n) && n > 0 ? Math.trunc(n) : 360;
  return Math.max(requested, floor);
}

/**
 * Classify one path relative to the storage root (posix separators).
 * Returns { feedId, kind, generationId?, group } or null when the layout is not recognized.
 */
export function describeArtifactPath(rel) {
  let m = CHUNK_FILE_RE.exec(rel);
  if (m && m[3] === m[5]) {
    return { feedId: Number(m[1]), kind: 'chunk', group: rel.split('/').slice(0, 6).join('/') };
  }
  m = CHUNK_PART_RE.exec(rel);
  if (m) return { feedId: Number(m[1]), kind: 'chunk_part', group: rel.split('/').slice(0, 6).join('/') };
  m = HEAD_FILE_RE.exec(rel);
  if (m) return { feedId: Number(m[1]), kind: 'recency_head', generationId: m[2], group: `generation:${m[2]}` };
  m = HEAD_PART_RE.exec(rel);
  if (m) return { feedId: Number(m[1]), kind: 'recency_head_part', generationId: m[2], group: `generation:${m[2]}` };
  m = SNAPSHOT_FILE_RE.exec(rel);
  if (m) return { feedId: Number(m[1]), kind: 'snapshot_artifact', generationId: m[2], group: `snapshot:${m[2]}` };
  m = SNAPSHOT_TEMP_RE.exec(rel);
  if (m) {
    return {
      feedId: Number(m[1]),
      kind: m[4].toLowerCase() === 'body' ? 'snapshot_body_temp' : 'snapshot_part',
      generationId: m[2],
      group: `snapshot:${m[2]}`
    };
  }
  return null;
}

const ORPHAN_REASON = {
  chunk: 'chunk_file_without_chunk_row',
  chunk_part: 'abandoned_chunk_part',
  recency_head: 'recency_head_without_generation',
  recency_head_part: 'abandoned_recency_head_part',
  snapshot_artifact: 'snapshot_artifact_without_snapshot_row',
  snapshot_part: 'abandoned_snapshot_part',
  snapshot_body_temp: 'abandoned_snapshot_body_temp'
};

async function walkFiles(root, startRel, visit) {
  const pending = [startRel];
  while (pending.length) {
    const rel = pending.pop();
    const abs = path.join(root, ...rel.split('/'));
    let entries;
    try {
      // eslint-disable-next-line no-await-in-loop
      entries = await fs.promises.readdir(abs, { withFileTypes: true });
    } catch (err) {
      if (err?.code === 'ENOENT') continue;
      throw err;
    }
    for (const entry of entries) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      // Dirent types come from readdir without following links: a symlinked dir is not descended.
      if (entry.isDirectory()) pending.push(childRel);
      // eslint-disable-next-line no-await-in-loop
      else await visit(childRel, entry);
    }
  }
}

async function loadFeedReferences(client, feedId) {
  // Sequential: one client cannot run concurrent queries.
  const chunks = await client.query('SELECT storage_path FROM published_feed_chunks WHERE feed_id = $1', [feedId]);
  const heads = await client.query(
    `SELECT gf.recency_head_path
     FROM published_feed_generation_formats gf
     JOIN published_feed_generations g ON g.id = gf.generation_id
     WHERE g.feed_id = $1 AND gf.recency_head_path IS NOT NULL`,
    [feedId]
  );
  const generations = await client.query('SELECT id FROM published_feed_generations WHERE feed_id = $1', [feedId]);
  const snapshots = await client.query(
    'SELECT storage_path FROM published_feed_snapshots WHERE feed_id = $1 AND storage_path IS NOT NULL',
    [feedId]
  );
  const norm = (p) => String(p || '').replace(/^[/\\]+/, '').split('\\').join('/');
  return {
    paths: new Set([
      ...chunks.rows.map((r) => norm(r.storage_path)),
      ...heads.rows.map((r) => norm(r.recency_head_path)),
      ...snapshots.rows.map((r) => norm(r.storage_path))
    ]),
    generationIds: new Set(generations.rows.map((r) => String(r.id)))
  };
}

function emptyBucket() {
  return { files: 0, bytes: 0 };
}

function addTo(map, key, size) {
  const bucket = map[key] || (map[key] = emptyBucket());
  bucket.files += 1;
  bucket.bytes += size;
}

/**
 * Scan (and optionally clean) the Published Feed artifact store.
 * Dry-run (apply=false) never modifies the filesystem or the database.
 */
export async function runPublishedFeedOrphanGc(pool, {
  apply = false,
  minAgeMinutes = resolveOrphanGcMinAgeMinutes(),
  feedIds = null,
  now = Date.now(),
  storageDir = getPublishedFeedArtifactConfig().storageDir,
  sampleLimit = 25
} = {}) {
  const root = path.resolve(storageDir);
  const cutoffMs = now - minAgeMinutes * 60 * 1000;
  const report = {
    mode: apply ? 'apply' : 'dry_run',
    storage_dir: root,
    min_age_minutes: minAgeMinutes,
    scanned: emptyBucket(),
    referenced: emptyBucket(),
    protected: emptyBucket(),
    orphan_candidates: emptyBucket(),
    delete_eligible: emptyBucket(),
    unknown: emptyBucket(),
    deleted: emptyBucket(),
    delete_failed: 0,
    protected_reasons: {},
    orphan_reasons: {},
    unknown_reasons: {},
    by_feed: {},
    by_group: {},
    oldest_orphan_at: null,
    newest_orphan_at: null,
    unknown_samples: [],
    orphan_samples: []
  };
  let rootStat;
  try {
    rootStat = await fs.promises.lstat(root);
  } catch (err) {
    if (err?.code === 'ENOENT') return report;
    throw err;
  }
  if (!rootStat.isDirectory()) throw new Error('Published Feed storage root is not a directory');

  // Group every file by owning feed first; anything unrecognized is UNKNOWN.
  const byFeed = new Map();
  const recordUnknown = (rel, size, reason) => {
    addTo(report, 'unknown', size);
    report.scanned.files += 1;
    report.scanned.bytes += size;
    report.unknown_reasons[reason] = (report.unknown_reasons[reason] || 0) + 1;
    if (report.unknown_samples.length < sampleLimit) report.unknown_samples.push(rel);
  };
  await walkFiles(root, '', async (rel, entry) => {
    const abs = path.join(root, ...rel.split('/'));
    let st;
    try {
      st = await fs.promises.lstat(abs);
    } catch (err) {
      if (err?.code === 'ENOENT') return;
      throw err;
    }
    if (!entry.isFile() || !st.isFile()) {
      recordUnknown(rel, 0, entry.isSymbolicLink() ? 'symlink' : 'not_regular_file');
      return;
    }
    const desc = describeArtifactPath(rel);
    if (!desc || !(desc.feedId > 0)) {
      recordUnknown(rel, st.size, 'unrecognized_layout');
      return;
    }
    if (feedIds && !feedIds.includes(desc.feedId)) return;
    if (!byFeed.has(desc.feedId)) byFeed.set(desc.feedId, []);
    byFeed.get(desc.feedId).push({ rel, abs, desc, size: st.size, mtimeMs: st.mtimeMs, ino: st.ino });
  });

  const feedIdList = [...byFeed.keys()].sort((a, b) => a - b);
  const { rows: existing } = feedIdList.length
    ? await pool.query('SELECT id FROM published_feeds WHERE id = ANY($1::bigint[])', [feedIdList])
    : { rows: [] };
  const existingFeeds = new Set(existing.map((r) => Number(r.id)));

  for (const feedId of feedIdList) {
    const files = byFeed.get(feedId);
    const feedStats = report.by_feed[feedId] || (report.by_feed[feedId] = {
      scanned: emptyBucket(),
      referenced: emptyBucket(),
      protected: emptyBucket(),
      delete_eligible: emptyBucket(),
      unknown: emptyBucket(),
      deleted: emptyBucket()
    });
    if (!existingFeeds.has(feedId)) {
      for (const f of files) {
        recordUnknown(f.rel, f.size, 'feed_not_found');
        addTo(feedStats, 'scanned', f.size);
        addTo(feedStats, 'unknown', f.size);
      }
      continue;
    }

    // eslint-disable-next-line no-await-in-loop
    const client = await pool.connect();
    let locked = false;
    try {
      // eslint-disable-next-line no-await-in-loop
      const lock = await client.query(
        'SELECT pg_try_advisory_lock($1::int, $2::int) AS ok',
        [GENERATION_LOCK_CLASS, feedId]
      );
      locked = Boolean(lock.rows[0]?.ok);
      // eslint-disable-next-line no-await-in-loop
      const refs = locked ? await loadFeedReferences(client, feedId) : null;
      for (const f of files) {
        report.scanned.files += 1;
        report.scanned.bytes += f.size;
        addTo(feedStats, 'scanned', f.size);
        const protect = (reason) => {
          addTo(report, 'protected', f.size);
          addTo(feedStats, 'protected', f.size);
          report.protected_reasons[reason] = (report.protected_reasons[reason] || 0) + 1;
        };
        if (!locked) {
          protect('generation_in_progress');
          continue;
        }
        const referenced = refs.paths.has(f.rel)
          || ((f.desc.kind === 'recency_head' || f.desc.kind === 'recency_head_part')
            && refs.generationIds.has(f.desc.generationId));
        if (referenced) {
          addTo(report, 'referenced', f.size);
          addTo(feedStats, 'referenced', f.size);
          continue;
        }
        if (f.mtimeMs >= cutoffMs) {
          protect('younger_than_min_age');
          continue;
        }
        const reason = ORPHAN_REASON[f.desc.kind];
        addTo(report, 'orphan_candidates', f.size);
        addTo(report, 'delete_eligible', f.size);
        addTo(feedStats, 'delete_eligible', f.size);
        addTo(report.by_group, `feed-${feedId}:${f.desc.group}`, f.size);
        report.orphan_reasons[reason] = (report.orphan_reasons[reason] || 0) + 1;
        const at = new Date(f.mtimeMs).toISOString();
        if (!report.oldest_orphan_at || at < report.oldest_orphan_at) report.oldest_orphan_at = at;
        if (!report.newest_orphan_at || at > report.newest_orphan_at) report.newest_orphan_at = at;
        if (report.orphan_samples.length < sampleLimit) report.orphan_samples.push(f.rel);
        if (!apply) continue;
        // Re-check identity right before unlinking: same inode, still old, still a file.
        try {
          // eslint-disable-next-line no-await-in-loop
          const again = await fs.promises.lstat(f.abs);
          if (!again.isFile() || again.ino !== f.ino || again.mtimeMs >= cutoffMs) continue;
          // eslint-disable-next-line no-await-in-loop
          await fs.promises.unlink(f.abs);
          addTo(report, 'deleted', f.size);
          addTo(feedStats, 'deleted', f.size);
        } catch (err) {
          if (err?.code !== 'ENOENT') report.delete_failed += 1;
        }
      }
    } finally {
      if (locked) {
        // eslint-disable-next-line no-await-in-loop
        await client.query('SELECT pg_advisory_unlock($1::int, $2::int)', [GENERATION_LOCK_CLASS, feedId])
          .catch(() => {});
      }
      client.release();
    }
  }
  return report;
}

let lastOrphanGcAt = 0;
let orphanGcRunning = false;

export function resolveOrphanGcIntervalMinutes(value = process.env.PUBLISHED_FEED_ORPHAN_GC_INTERVAL_MINUTES) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 5 ? Math.trunc(n) : 60;
}

export function isOrphanGcEnabled(value = process.env.PUBLISHED_FEED_ORPHAN_GC_ENABLED) {
  const v = String(value ?? 'true').trim().toLowerCase();
  return !['0', 'false', 'no', 'off'].includes(v);
}

/** Throttled apply-mode sweep for the scheduler; at most one run per interval per process. */
export async function runPublishedFeedOrphanGcIfDue(pool, { now = Date.now(), log = null } = {}) {
  if (!isOrphanGcEnabled() || orphanGcRunning) return null;
  if (now - lastOrphanGcAt < resolveOrphanGcIntervalMinutes() * 60 * 1000) return null;
  orphanGcRunning = true;
  lastOrphanGcAt = now;
  try {
    const report = await runPublishedFeedOrphanGc(pool, { apply: true });
    if (log && (report.deleted.files || report.unknown.files || report.delete_failed)) {
      log.info('published feed orphan gc', {
        deleted_files: report.deleted.files,
        deleted_bytes: report.deleted.bytes,
        protected_files: report.protected.files,
        unknown_files: report.unknown.files,
        delete_failed: report.delete_failed
      });
    }
    return report;
  } finally {
    orphanGcRunning = false;
  }
}

export function resetOrphanGcThrottleForTests() {
  lastOrphanGcAt = 0;
  orphanGcRunning = false;
}
