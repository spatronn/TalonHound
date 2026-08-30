import { UNKNOWN_THREAT_CLASSIFICATION } from '../threatClassification.js';
import {
  loadMitreReference,
  resolveBundledMitreMappings
} from './mitreReference.js';
import {
  buildThreatClassificationReconcilePlan,
  descriptionIsEmpty,
  loadBundledSnapshot
} from './reconciliation.js';

export const SYSTEM_SEED_OPERATOR = 'system-seed';
export const UNKNOWN_DESCRIPTION = 'Default when classification is unset or unrecognized.';

export async function loadExistingThreatClassifications(client) {
  const { rows } = await client.query(
    `SELECT id, name, slug, description, active, sort_order, system_default
     FROM threat_classifications
     ORDER BY sort_order ASC, name ASC`
  );
  return rows;
}

export async function loadMitreMappingsByClassificationId(client) {
  const { rows } = await client.query(
    `SELECT classification_id, attack_id, attack_name, attack_type, attack_url, sort_order
     FROM threat_classification_mitre_mappings
     ORDER BY classification_id ASC, sort_order ASC, attack_id ASC`
  );
  const map = new Map();
  for (const row of rows) {
    const key = String(row.classification_id);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push({
      attack_id: row.attack_id,
      attack_name: row.attack_name,
      attack_type: row.attack_type,
      attack_url: row.attack_url,
      sort_order: Number(row.sort_order) || 0
    });
  }
  return map;
}

export async function ensureUnknownThreatClassification(client, { operator = SYSTEM_SEED_OPERATOR } = {}) {
  const { rows } = await client.query(
    `SELECT * FROM threat_classifications WHERE slug = $1 LIMIT 1`,
    [UNKNOWN_THREAT_CLASSIFICATION]
  );
  if (rows[0]) return rows[0];

  const { rows: inserted } = await client.query(
    `INSERT INTO threat_classifications
       (id, name, slug, description, active, sort_order, system_default, created_by, updated_by)
     VALUES ('4ee39c50-9e95-4c2e-bfba-c177a4c771e7', 'Unknown', $1, $2, TRUE, 0, TRUE, $3, $3)
     RETURNING *`,
    [UNKNOWN_THREAT_CLASSIFICATION, UNKNOWN_DESCRIPTION, operator]
  );
  return inserted[0];
}

async function syncMitreMappings(client, classificationId, mappings, { dryRun = false } = {}) {
  const { rows: existingRows } = await client.query(
    `SELECT attack_id, attack_name, attack_type, attack_url, sort_order
     FROM threat_classification_mitre_mappings
     WHERE classification_id = $1::uuid
     ORDER BY sort_order ASC, attack_id ASC`,
    [classificationId]
  );

  const desired = mappings || [];
  const desiredIds = new Set(desired.map((m) => m.attack_id));
  const existingIds = new Set(existingRows.map((m) => m.attack_id));

  let inserted = 0;
  let deleted = 0;
  let unchanged = 0;

  for (const existing of existingRows) {
    if (!desiredIds.has(existing.attack_id)) {
      if (!dryRun) {
        await client.query(
          `DELETE FROM threat_classification_mitre_mappings
           WHERE classification_id = $1::uuid AND attack_id = $2`,
          [classificationId, existing.attack_id]
        );
      }
      deleted += 1;
    }
  }

  for (const mapping of desired) {
    if (existingIds.has(mapping.attack_id)) {
      unchanged += 1;
      continue;
    }
    if (!dryRun) {
      await client.query(
        `INSERT INTO threat_classification_mitre_mappings
           (classification_id, attack_id, attack_name, attack_type, attack_url, sort_order)
         VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
        [
          classificationId,
          mapping.attack_id,
          mapping.attack_name,
          mapping.attack_type,
          mapping.attack_url,
          mapping.sort_order
        ]
      );
    }
    inserted += 1;
  }

  return { inserted, deleted, unchanged };
}

async function applyThreatClassificationReconcilePlan(client, plan, { operator = SYSTEM_SEED_OPERATOR, dryRun = false } = {}) {
  const applied = {
    inserted: 0,
    descriptionsUpdated: 0,
    mitreInserted: 0,
    mitreDeleted: 0
  };

  for (const record of plan.inserts) {
    if (!dryRun) {
      await client.query(
        `INSERT INTO threat_classifications
           (id, name, slug, description, active, sort_order, system_default, created_by, updated_by)
         VALUES ($1::uuid, $2, $3, $4, $5, $6, TRUE, $7, $7)
         ON CONFLICT (slug) DO NOTHING`,
        [
          record.id,
          record.name,
          record.slug,
          record.description,
          record.active !== false,
          record.sort_order,
          operator
        ]
      );
    }
    applied.inserted += 1;

    const classificationId = record.id;
    const mitreResult = await syncMitreMappings(client, classificationId, record.resolved_mitre, { dryRun });
    applied.mitreInserted += mitreResult.inserted;
    applied.mitreDeleted += mitreResult.deleted;
  }

  for (const update of plan.descriptionUpdates) {
    if (!dryRun) {
      await client.query(
        `UPDATE threat_classifications
         SET description = $2, updated_by = $3, updated_at = NOW()
         WHERE id = $1::uuid AND (description IS NULL OR btrim(description) = '')`,
        [update.id, update.description, operator]
      );
    }
    applied.descriptionsUpdated += 1;
  }

  for (const sync of plan.mitreSyncs) {
    const mitreResult = await syncMitreMappings(client, sync.classification_id, sync.mappings, { dryRun });
    applied.mitreInserted += mitreResult.inserted;
    applied.mitreDeleted += mitreResult.deleted;
  }

  return applied;
}

/**
 * Reconcile bundled built-in taxonomy and MITRE mappings.
 * Idempotent: safe for fresh install, upgrade, and repeated migrate runs.
 */
export async function reconcileBundledThreatClassifications(client, {
  snapshotPath,
  dryRun = false,
  operator = SYSTEM_SEED_OPERATOR,
  ensureUnknown = true
} = {}) {
  if (ensureUnknown && !dryRun) {
    await ensureUnknownThreatClassification(client, { operator });
  }

  const bundled = await loadBundledSnapshot(snapshotPath);
  const reference = await loadMitreReference();
  const existing = await loadExistingThreatClassifications(client);

  const records = bundled.records.map((record) => ({
    ...record,
    resolved_mitre: resolveBundledMitreMappings(record.mitre_attack || [], reference)
  }));

  const plan = buildThreatClassificationReconcilePlan(records, existing);
  const applied = dryRun
    ? null
    : await applyThreatClassificationReconcilePlan(client, plan, { operator, dryRun: false });

  return {
    snapshotPath: bundled.path,
    snapshotCount: records.length,
    plan,
    applied
  };
}

export function printBundledThreatClassificationSummary(result, { dryRun = false } = {}) {
  const { plan } = result;
  console.log('\nThreat Classification Validation');
  console.log(`Snapshot path:               ${result.snapshotPath}`);
  console.log(`Bundled built-ins:           ${result.snapshotCount}`);
  console.log(`Plan inserts:                ${plan.inserts.length}`);
  console.log(`Plan description updates:    ${plan.descriptionUpdates.length}`);
  console.log(`Plan MITRE syncs:            ${plan.mitreSyncs.length}`);
  console.log(`Preserved custom rows:       ${plan.preservedCustom}`);
  if (plan.conflicts.length) {
    console.log(`Conflicts:                   ${plan.conflicts.length}`);
  }
  if (result.applied) {
    console.log(
      `Applied: inserted=${result.applied.inserted}, descriptions=${result.applied.descriptionsUpdated}, mitre_inserted=${result.applied.mitreInserted}, mitre_deleted=${result.applied.mitreDeleted}`
    );
  }
  if (dryRun) console.log('(dry run — no database writes)');
}

export { descriptionIsEmpty };
