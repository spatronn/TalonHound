#!/usr/bin/env node
import '../lib/ensure-db-password.js';
import pg from 'pg';
import {
  applyThreatActorImportPlan,
  buildThreatActorImportPlan,
  fetchMalpediaActors,
  loadBundledSnapshot,
  parseMalpediaActorsResponse,
  printImportSummary
} from '../lib/threatActors/index.js';

/**
 * Manual Malpedia threat actor bootstrap import.
 *
 * Source: Malpedia (https://malpedia.caad.fkie.fraunhofer.de/) — Threat Actors view
 * is based on the MISP Galaxy threat-actor dataset.
 *
 * Usage:
 *   docker compose exec backend npm run import:malpedia-actors -- --dry-run
 *   docker compose exec backend npm run import:malpedia-actors -- --apply
 *   docker compose exec backend npm run import:malpedia-actors -- --from-file --dry-run
 */

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

function parseArgs(argv = process.argv.slice(2)) {
  const dryRun = argv.includes('--dry-run');
  const apply = argv.includes('--apply');
  if (dryRun === apply) {
    throw new Error('Specify exactly one of --dry-run or --apply');
  }

  const fromFile = argv.includes('--from-file');
  const fromApi = argv.includes('--from-api') || !fromFile;
  const fileIdx = argv.indexOf('--file');
  const filePath = fileIdx >= 0 ? argv[fileIdx + 1] : undefined;

  return { dryRun, fromApi, fromFile, filePath };
}

async function loadSourceRecords({ fromApi, filePath }) {
  if (fromApi) {
    const raw = await fetchMalpediaActors();
    const parsed = parseMalpediaActorsResponse(raw);
    if (!parsed.ok) {
      throw new Error(`Malpedia response rejected: ${parsed.error}${parsed.count != null ? ` (count=${parsed.count})` : ''}`);
    }
    return { records: parsed.records, skippedInvalid: parsed.skippedInvalid || 0, sourceLabel: 'Malpedia' };
  }

  const bundled = await loadBundledSnapshot(filePath);
  return { records: bundled.records, skippedInvalid: 0, sourceLabel: 'Bundled snapshot file' };
}

async function main() {
  const { dryRun, fromApi, filePath } = parseArgs();
  const sourceMode = fromApi ? 'malpedia-api' : 'bundled-file';

  console.log(`[import-malpedia-threat-actors] mode=${dryRun ? 'dry-run' : 'apply'} source=${sourceMode}`);

  const { records, skippedInvalid, sourceLabel } = await loadSourceRecords({ fromApi, filePath });

  const client = await pool.connect();
  try {
    const { rows: existing } = await client.query('SELECT * FROM threat_actors ORDER BY name ASC');
    const plan = buildThreatActorImportPlan(records, existing);
    plan.skippedInvalid += skippedInvalid;

    printImportSummary(plan, { dryRun, sourceLabel });

    if (!dryRun) {
      const result = await applyThreatActorImportPlan(client, plan);
      console.log(`\nApplied: inserted=${result.inserted}, updated=${result.updated}`);
    }
  } finally {
    client.release();
  }
}

main()
  .then(() => pool.end())
  .catch(async (err) => {
    console.error('[import-malpedia-threat-actors] failed:', err?.message || err);
    await pool.end().catch(() => {});
    process.exit(1);
  });
