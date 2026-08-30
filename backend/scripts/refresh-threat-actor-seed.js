#!/usr/bin/env node
import {
  buildBundledSnapshotDocument,
  DEFAULT_BUNDLED_SNAPSHOT_PATH,
  detectPotentialCanonicalIdentityChanges,
  diffBundledSnapshots,
  fetchMalpediaActors,
  loadBundledSnapshot,
  parseMalpediaActorsResponse,
  printPotentialIdentityChanges,
  printSnapshotDiffSummary,
  recordsToSnapshotActors,
  writeBundledSnapshot
} from '../lib/threatActors/index.js';

/**
 * Maintainer workflow: refresh the version-controlled bundled Threat Actor snapshot
 * from the public Malpedia API.
 *
 * This command is NOT used during installation, startup, or upgrade.
 *
 * Usage:
 *   docker compose exec backend npm run threat-actors:refresh -- --dry-run
 *   docker compose exec backend npm run threat-actors:refresh -- --write
 */

function parseMode(argv = process.argv.slice(2)) {
  const dryRun = argv.includes('--dry-run');
  const write = argv.includes('--write');
  if (dryRun === write) {
    throw new Error('Specify exactly one of --dry-run or --write');
  }
  return { dryRun, write };
}

async function loadPreviousSnapshotActors(snapshotPath) {
  try {
    const bundled = await loadBundledSnapshot(snapshotPath);
    return bundled.document.actors;
  } catch (err) {
    if (err?.code === 'ENOENT' || /Failed to read bundled snapshot/.test(String(err?.message || ''))) {
      return [];
    }
    throw err;
  }
}

async function main() {
  const { dryRun, write } = parseMode();
  const snapshotPath = process.env.THREAT_ACTOR_SNAPSHOT_PATH || DEFAULT_BUNDLED_SNAPSHOT_PATH;

  console.log(`[refresh-threat-actor-seed] mode=${dryRun ? 'dry-run' : 'write'}`);

  const raw = await fetchMalpediaActors();
  const parsed = parseMalpediaActorsResponse(raw);
  if (!parsed.ok) {
    throw new Error(`Malpedia response rejected: ${parsed.error}${parsed.count != null ? ` (count=${parsed.count})` : ''}`);
  }

  buildBundledSnapshotDocument(parsed.records, {
    sourceActorCount: Object.keys(raw).length
  });

  const previousActors = await loadPreviousSnapshotActors(snapshotPath);
  const nextActors = recordsToSnapshotActors(parsed.records);
  const diff = diffBundledSnapshots(previousActors, nextActors);
  const potentialIdentityChanges = detectPotentialCanonicalIdentityChanges(previousActors, nextActors);

  printSnapshotDiffSummary(diff, {
    sourceActorCount: Object.keys(raw).length,
    identityConflicts: 0
  });
  printPotentialIdentityChanges(potentialIdentityChanges);

  if (dryRun) {
    console.log('\nSnapshot file changes: NONE (--dry-run)');
    return;
  }

  await writeBundledSnapshot(snapshotPath, parsed.records, {
    sourceActorCount: Object.keys(raw).length
  });
  console.log(`\nSnapshot updated successfully: ${snapshotPath}`);
}

main().catch((err) => {
  console.error('[refresh-threat-actor-seed] failed:', err?.message || err);
  if (err?.conflicts?.length) {
    for (const conflict of err.conflicts.slice(0, 20)) {
      console.error(`  - ${conflict.type}: ${conflict.name || conflict.slug}`);
    }
  }
  process.exit(1);
});
