// Backup / storage health evaluation for GET /api/backups/status.
// Pure: callers gather facts (DB rows, statfs, temp sweep dry-run) and this
// turns them into stable warning codes the UI can render.

import fs from 'node:fs';
import { listRecoveryPoints } from './retention.js';
import { getBackupConfig } from './config.js';
import { listActiveBackupIds, listCompletedForRetention, getLatestFinished } from './backupStore.js';
import { sweepStaleBackupTemp } from './tempSweep.js';

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Filesystem capacity for the backup directory (same filesystem as the data
 * volumes on a default single-disk install).
 * @returns {Promise<{ total_bytes: number, free_bytes: number, free_percent: number, inodes_total: number, inodes_free: number, inodes_free_percent: number|null } | null>}
 */
export async function readFilesystemCapacity(dir) {
  try {
    const st = await fs.promises.statfs(dir);
    const total = Number(st.blocks) * Number(st.bsize);
    const free = Number(st.bavail) * Number(st.bsize);
    const files = Number(st.files);
    const ffree = Number(st.ffree);
    return {
      total_bytes: total,
      free_bytes: free,
      free_percent: total > 0 ? Math.round((free / total) * 1000) / 10 : 0,
      inodes_total: files,
      inodes_free: ffree,
      inodes_free_percent: files > 0 ? Math.round((ffree / files) * 1000) / 10 : null
    };
  } catch {
    return null;
  }
}

function warning(code, severity, message) {
  return { code, severity, message };
}

/**
 * @param {{
 *   cfg: { enabled: boolean, minRetained: number, maxAgeHours: number, retentionDays: number, diskWarnFreePercent: number, inodeWarnFreePercent: number },
 *   completed: object[],          // status = 'completed' rows
 *   latestFinished?: object|null, // newest completed/failed/interrupted row
 *   capacity?: object|null,       // readFilesystemCapacity()
 *   staleTemp?: { stale: number, stale_bytes: number } | null,
 *   now?: Date
 * }} facts
 */
export function evaluateBackupHealth({
  cfg,
  completed = [],
  latestFinished = null,
  capacity = null,
  staleTemp = null,
  threatLibraryArtifactCount = 0,
  now = new Date()
}) {
  const warnings = [];
  const points = listRecoveryPoints(completed);
  const newest = points[0] || null;

  if (points.length === 0) {
    warnings.push(warning('no_recovery_point', 'critical', 'No verified backup is available for recovery.'));
  } else if (points.length < cfg.minRetained) {
    warnings.push(
      warning(
        'insufficient_recovery_points',
        'warning',
        `${points.length} verified backup${points.length === 1 ? '' : 's'} stored; ${cfg.minRetained} required.`
      )
    );
  }

  if (newest && threatLibraryArtifactCount > 0 && !newest.manifest?.components?.threat_library) {
    warnings.push(
      warning(
        'latest_backup_without_threat_library',
        'warning',
        'The newest verified backup does not include Threat Library source files.'
      )
    );
  }

  if (latestFinished && ['failed', 'interrupted'].includes(latestFinished.status)) {
    warnings.push(warning('last_backup_failed', 'warning', 'The most recent backup did not complete.'));
  }

  if (cfg.enabled && cfg.maxAgeHours > 0 && newest) {
    const ageMs = now.getTime() - new Date(newest.completed_at || newest.created_at).getTime();
    if (ageMs > cfg.maxAgeHours * 60 * 60 * 1000) {
      warnings.push(
        warning('backup_overdue', 'warning', `Newest verified backup is older than ${cfg.maxAgeHours} hours.`)
      );
    }
  }

  // Retention runs hourly; a recovery point past the window by more than a day
  // (and not held by minRetained) means the sweep is failing.
  const overdueCutoff = now.getTime() - (cfg.retentionDays + 1) * DAY_MS;
  const overdue = points
    .slice(cfg.minRetained)
    .filter((r) => new Date(r.created_at || r.completed_at).getTime() < overdueCutoff);
  if (overdue.length > 0) {
    warnings.push(warning('retention_overdue', 'warning', 'Expired backups were not removed by retention.'));
  }

  if (staleTemp && staleTemp.stale > 0) {
    warnings.push(
      warning('stale_temp_artifacts', 'warning', 'Abandoned backup staging files are present.')
    );
  }

  if (capacity) {
    const lastArchive = Number(newest?.archive_size_bytes || 0);
    const lowPercent = capacity.free_percent < cfg.diskWarnFreePercent;
    // Next backup stages a dump and an archive before the old one can rotate out.
    const lowForNext = lastArchive > 0 && capacity.free_bytes < lastArchive * 2;
    if (lowPercent || lowForNext) {
      warnings.push(
        warning(
          'low_disk_space',
          lowForNext ? 'critical' : 'warning',
          lowForNext
            ? 'Free space is below twice the last backup size; the next backup may fail.'
            : `Backup filesystem has less than ${cfg.diskWarnFreePercent}% free space.`
        )
      );
    }
    if (capacity.inodes_free_percent != null && capacity.inodes_free_percent < cfg.inodeWarnFreePercent) {
      warnings.push(
        warning('low_inodes', 'warning', `Backup filesystem has less than ${cfg.inodeWarnFreePercent}% free inodes.`)
      );
    }
  }

  return { recovery_points: points.length, warnings };
}

async function countThreatLibraryArtifactFiles(db) {
  try {
    const { rows } = await db.query(
      `SELECT CASE WHEN to_regclass('public.threat_report_artifacts') IS NULL THEN 0
              ELSE (SELECT COUNT(*) FROM threat_report_artifacts WHERE storage_key IS NOT NULL) END::int AS n`
    );
    return Number(rows[0]?.n || 0);
  } catch {
    return 0;
  }
}

/**
 * Gather facts and evaluate. Read-only: the temp sweep runs as a dry run here;
 * only the backup worker deletes stale staging.
 */
export async function loadBackupHealth(db, cfg = getBackupConfig()) {
  const [completed, latestFinished, activeIds, capacity, threatLibraryArtifactCount] = await Promise.all([
    listCompletedForRetention(db),
    getLatestFinished(db),
    listActiveBackupIds(db),
    readFilesystemCapacity(cfg.backupDir),
    countThreatLibraryArtifactFiles(db)
  ]);
  const staleTemp = await sweepStaleBackupTemp(cfg.backupDir, {
    activeBackupIds: activeIds,
    apply: false
  }).catch(() => null);
  return {
    capacity,
    staleTemp,
    ...evaluateBackupHealth({ cfg, completed, latestFinished, capacity, staleTemp, threatLibraryArtifactCount })
  };
}

const STORAGE_CODES = new Set(['low_disk_space', 'low_inodes', 'stale_temp_artifacts']);

/** System → Health rows (Core Services) derived from loadBackupHealth(). */
export function systemHealthEntries(health) {
  const storageWarnings = health.warnings.filter((w) => STORAGE_CODES.has(w.code));
  const backupWarnings = health.warnings.filter((w) => !STORAGE_CODES.has(w.code));
  const cap = health.capacity;
  const gib = (n) => `${(n / 1024 ** 3).toFixed(1)} GiB`;
  return [
    {
      key: 'storage',
      name: 'Storage',
      status: !cap
        ? 'unknown'
        : storageWarnings.some((w) => w.severity === 'critical')
          ? 'unhealthy'
          : storageWarnings.length
            ? 'degraded'
            : 'healthy',
      reason: storageWarnings[0]?.code || (cap ? null : 'capacity_unavailable'),
      evidence: cap
        ? [
            storageWarnings[0]?.message,
            `${gib(cap.free_bytes)} free of ${gib(cap.total_bytes)} (${cap.free_percent}%)` +
              (cap.inodes_free_percent != null ? `, inodes ${cap.inodes_free_percent}% free` : '')
          ].filter(Boolean).join(' ')
        : null,
      required: false,
      include_in_overall: Boolean(cap)
    },
    {
      key: 'backups',
      name: 'Backups',
      status: backupWarnings.length ? 'degraded' : 'healthy',
      reason: backupWarnings[0]?.code || null,
      evidence:
        backupWarnings[0]?.message ||
        `${health.recovery_points} verified recovery point${health.recovery_points === 1 ? '' : 's'}`,
      required: false,
      include_in_overall: false
    }
  ];
}
