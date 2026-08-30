#!/usr/bin/env node
import {
  DEFAULT_MITRE_REFERENCE_PATH,
  invalidateMitreReferenceCache,
  isValidMitreAttackId,
  loadMitreReference,
  resolveBundledMitreMappings
} from '../lib/threatClassifications/mitreReference.js';
import { DEFAULT_BUNDLED_SNAPSHOT_PATH, loadBundledSnapshot } from '../lib/threatClassifications/reconciliation.js';
const args = new Set(process.argv.slice(2));
const dryRun = args.has('--dry-run');

async function main() {
  invalidateMitreReferenceCache();
  const reference = await loadMitreReference();
  const bundled = await loadBundledSnapshot(DEFAULT_BUNDLED_SNAPSHOT_PATH);
  const errors = [];

  for (const record of reference.values()) {
    if (!isValidMitreAttackId(record.id)) {
      errors.push(`Reference record has invalid id format: ${record.id}`);
    }
    if (!record.url.startsWith('https://attack.mitre.org/')) {
      errors.push(`Reference record ${record.id} has non-official URL: ${record.url}`);
    }
  }

  const slugSet = new Set();
  for (const record of bundled.records) {
    if (!record.slug || !record.name) {
      errors.push(`Bundled record missing name/slug: ${JSON.stringify(record)}`);
      continue;
    }
    if (slugSet.has(record.slug)) {
      errors.push(`Duplicate bundled slug: ${record.slug}`);
    }
    slugSet.add(record.slug);

    try {
      resolveBundledMitreMappings(record.mitre_attack || [], reference);
    } catch (err) {
      errors.push(`${record.slug}: ${err.message}`);
    }
  }

  if (errors.length) {
    console.error('[threat-classifications:validate-mitre] FAILED');
    for (const err of errors) console.error(`  - ${err}`);
    process.exit(1);
  }

  console.log('[threat-classifications:validate-mitre] OK');
  console.log(`Reference path: ${DEFAULT_MITRE_REFERENCE_PATH}`);
  console.log(`Bundled taxonomy path: ${DEFAULT_BUNDLED_SNAPSHOT_PATH}`);
  console.log(`Reference records: ${reference.size}`);
  console.log(`Bundled classifications: ${bundled.records.length}`);
  if (dryRun) console.log('(dry run)');
}

main().catch((err) => {
  console.error('[threat-classifications:validate-mitre] FAILED:', err?.message || err);
  process.exit(1);
});
