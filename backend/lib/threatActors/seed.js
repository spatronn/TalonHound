import {
  applyThreatActorImportPlan,
  buildThreatActorImportPlan,
  IMPORT_OPERATOR_BUNDLED,
  printImportSummary
} from './reconciliation.js';
import { isUnknownSentinelActor } from './normalization.js';
import { DEFAULT_BUNDLED_SNAPSHOT_PATH, loadBundledSnapshot } from './snapshot.js';

export const SYSTEM_SEED_OPERATOR = 'system-seed';
export const UNKNOWN_DESCRIPTION = 'Default when threat actor is unset or unrecognized';

export async function loadExistingThreatActors(client) {
  const { rows } = await client.query('SELECT * FROM threat_actors ORDER BY name ASC');
  return rows;
}

export async function ensureUnknownThreatActor(client, { operator = SYSTEM_SEED_OPERATOR } = {}) {
  const { rows } = await client.query(
    `SELECT * FROM threat_actors
     WHERE lower(name) = 'unknown' OR slug = 'unknown'
     ORDER BY CASE WHEN slug = 'unknown' THEN 0 ELSE 1 END
     LIMIT 1`
  );
  if (rows[0]) return rows[0];

  const { rows: inserted } = await client.query(
    `INSERT INTO threat_actors (name, slug, aliases, description, active, catalog_sources, created_by, updated_by)
     VALUES ('Unknown', 'unknown', NULL, $2, TRUE, ARRAY['system']::text[], $1, $1)
     RETURNING *`,
    [operator, UNKNOWN_DESCRIPTION]
  );
  return inserted[0];
}

/**
 * Reconcile bundled snapshot records against the database.
 * Idempotent: safe for fresh install, upgrade, and repeated migrate runs.
 */
export async function reconcileBundledThreatActors(client, {
  snapshotPath = DEFAULT_BUNDLED_SNAPSHOT_PATH,
  dryRun = false,
  operator = IMPORT_OPERATOR_BUNDLED,
  ensureUnknown = true
} = {}) {
  if (ensureUnknown && !dryRun) {
    await ensureUnknownThreatActor(client);
  }

  const bundled = await loadBundledSnapshot(snapshotPath);
  const existing = await loadExistingThreatActors(client);
  const plan = buildThreatActorImportPlan(bundled.records, existing);

  if (ensureUnknown) {
    const unknown = existing.find(isUnknownSentinelActor);
    if (unknown) {
      plan.skippedUnknownSentinel = Math.max(plan.skippedUnknownSentinel, 1);
      plan.preserved.unknown = { id: unknown.id, name: unknown.name, action: 'preserved' };
    }
  }

  const result = {
    snapshotPath: bundled.path,
    snapshotActorCount: bundled.records.length,
    plan,
    applied: null
  };

  if (!dryRun) {
    result.applied = await applyThreatActorImportPlan(client, plan, { operator });
  }

  return result;
}

export function printBundledReconcileSummary(result, { dryRun = false } = {}) {
  printImportSummary(result.plan, { dryRun, sourceLabel: 'Bundled snapshot' });
  console.log(`Snapshot path:               ${result.snapshotPath}`);
  console.log(`Snapshot actors:             ${result.snapshotActorCount}`);
  if (result.applied) {
    console.log(
      `\nApplied: inserted=${result.applied.inserted}, updated=${result.applied.updated}, catalog_sources=${result.applied.catalogSourcesUpdated || 0}`
    );
  }
}
