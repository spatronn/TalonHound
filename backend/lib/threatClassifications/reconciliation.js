import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_BUNDLED_SNAPSHOT_PATH = path.resolve(__dirname, '../../seeds/threat-classifications.json');

/** @typedef {{ id: string, attack_id: string, attack_name: string, attack_type: string, attack_url: string, sort_order: number }} ResolvedMitreMapping */

/**
 * @typedef {{
 *   id: string,
 *   name: string,
 *   slug: string,
 *   description: string,
 *   sort_order: number,
 *   active: boolean,
 *   mitre_attack: Array<{ id: string }>,
 *   resolved_mitre: ResolvedMitreMapping[]
 * }} BundledClassificationRecord
 */

export async function loadBundledSnapshot(snapshotPath = DEFAULT_BUNDLED_SNAPSHOT_PATH) {
  const raw = JSON.parse(await readFile(snapshotPath, 'utf8'));
  const records = Array.isArray(raw?.records) ? raw.records : [];
  return {
    path: snapshotPath,
    version: raw?.version ?? null,
    records
  };
}

export function isUnknownBundledRecord(record) {
  return String(record?.slug || '').trim() === 'unknown';
}

export function descriptionIsEmpty(value) {
  return value == null || String(value).trim() === '';
}

/**
 * @param {Array<object>} existingRows
 */
export function buildExistingClassificationIndex(existingRows = []) {
  const byId = new Map();
  const bySlug = new Map();
  for (const row of existingRows) {
    if (row?.id) byId.set(String(row.id), row);
    if (row?.slug) bySlug.set(String(row.slug), row);
  }
  return { byId, bySlug, rows: existingRows };
}

/**
 * @param {object} bundledRecord
 * @param {{ byId: Map<string, object>, bySlug: Map<string, object> }} index
 */
export function findExistingClassificationMatch(bundledRecord, index) {
  if (bundledRecord?.id && index.byId.has(String(bundledRecord.id))) {
    return index.byId.get(String(bundledRecord.id));
  }
  if (bundledRecord?.slug && index.bySlug.has(String(bundledRecord.slug))) {
    return index.bySlug.get(String(bundledRecord.slug));
  }
  return null;
}

/**
 * @param {Array<BundledClassificationRecord>} bundledRecords
 * @param {Array<object>} existingRows
 */
export function buildThreatClassificationReconcilePlan(bundledRecords, existingRows = []) {
  const index = buildExistingClassificationIndex(existingRows);
  const matchedIds = new Set();

  const plan = {
    inserts: [],
    descriptionUpdates: [],
    mitreSyncs: [],
    skippedUnknown: false,
    preservedCustom: existingRows.filter((row) => !row.system_default).length,
    conflicts: []
  };

  for (const record of bundledRecords) {
    const existing = findExistingClassificationMatch(record, index);
    if (!existing) {
      plan.inserts.push(record);
      continue;
    }

    if (matchedIds.has(String(existing.id))) {
      plan.conflicts.push({
        slug: record.slug,
        existingId: existing.id,
        reason: 'duplicate_match'
      });
      continue;
    }
    matchedIds.add(String(existing.id));

    if (isUnknownBundledRecord(existing)) {
      plan.skippedUnknown = true;
    }

    if (descriptionIsEmpty(existing.description) && !descriptionIsEmpty(record.description)) {
      plan.descriptionUpdates.push({
        id: existing.id,
        slug: existing.slug,
        description: record.description
      });
    }

    if (existing.system_default) {
      plan.mitreSyncs.push({
        classification_id: existing.id,
        slug: existing.slug,
        mappings: record.resolved_mitre || []
      });
    }
  }

  return plan;
}
