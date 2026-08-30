#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

node <<'NODE'
import pg from 'pg';
import {
  inferCatalogSourcesForRow,
  summarizeThreatActorProvenance
} from './lib/threatActors/catalogBackfill.js';
import { resolveCatalogSources } from './lib/threatActors/catalogSources.js';
import { loadBundledSnapshot } from './lib/threatActors/snapshot.js';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const KNOWN = ['APT28', 'APT29', 'Lazarus', 'Turla', 'APT41', 'Sandworm', 'MuddyWater', 'Unknown'];

function pad(value, width) {
  return String(value).padStart(width, ' ');
}

try {
  const client = await pool.connect();
  const { rows } = await client.query('SELECT * FROM threat_actors ORDER BY name ASC');
  const bundled = await loadBundledSnapshot();
  const bundledSlugSet = new Set(bundled.records.map((record) => record.slug));
  const summary = summarizeThreatActorProvenance(rows);

  const slugDup = await client.query(`
    SELECT slug, COUNT(*)::int AS count
    FROM threat_actors
    GROUP BY slug
    HAVING COUNT(*) > 1
  `);
  const nameDup = await client.query(`
    SELECT lower(name) AS name_key, COUNT(*)::int AS count
    FROM threat_actors
    GROUP BY lower(name)
    HAVING COUNT(*) > 1
  `);

  console.log('Threat Actor provenance validation\n');
  console.log(`Total actors:                  ${pad(summary.total, 4)}`);
  console.log(`Bundled only:                  ${pad(summary.bundledOnly, 4)}`);
  console.log(`Manual only:                   ${pad(summary.manualOnly, 4)}`);
  console.log(`Manual + bundled:              ${pad(summary.manualAndBundled, 4)}`);
  console.log(`Legacy seed + bundled:         ${pad(summary.legacySeedBundled, 4)}`);
  console.log(`Pending collisions:            ${pad(summary.pendingCollisions, 4)}`);
  console.log(`Unknown:                       ${pad(summary.unknown, 4)}`);
  console.log(`Unclassified:                  ${pad(summary.unclassified, 4)}`);
  console.log(`Invalid source states:         ${pad(summary.invalidSources, 4)}`);
  console.log('');
  console.log('Known actor validation:');
  for (const name of KNOWN) {
    const row = rows.find((item) => item.name === name || item.slug === name.toLowerCase());
    if (!row) {
      console.log(`${pad(name, 10)} missing`);
      continue;
    }
    const sources = resolveCatalogSources(row).join(', ') || 'unclassified';
    const pending = row.bundled_catalog_collision_pending ? ' (pending collision)' : '';
    console.log(`${pad(name, 10)} ${sources}${pending} | id=${row.id} active=${row.active}`);
  }

  console.log('');
  console.log(`Canonical duplicates:          ${pad(nameDup.rows.length, 4)}`);
  console.log(`Slug duplicates:               ${pad(slugDup.rows.length, 4)}`);

  if (summary.pendingCollisions > 0) {
    console.log('\nPending collisions:');
    for (const row of rows.filter((item) => item.bundled_catalog_collision_pending)) {
      console.log(`  - ${row.name} (${row.slug}) id=${row.id}`);
    }
  }

  const misclassifiedBundled = rows.filter((row) => {
    if (row.slug === 'unknown') return false;
    if (!bundledSlugSet.has(String(row.slug || ''))) return false;
    const sources = resolveCatalogSources(row);
    return !sources.includes('bundled') && !sources.includes('legacy-seed');
  });
  if (misclassifiedBundled.length) {
    console.log('\nBundled snapshot slugs missing bundled provenance:');
    for (const row of misclassifiedBundled.slice(0, 20)) {
      console.log(`  - ${row.name} (${row.slug}) sources=${JSON.stringify(row.catalog_sources)} created_by=${row.created_by}`);
    }
    if (misclassifiedBundled.length > 20) {
      console.log(`  ... and ${misclassifiedBundled.length - 20} more`);
    }
  }

  client.release();
} finally {
  await pool.end();
}
NODE
