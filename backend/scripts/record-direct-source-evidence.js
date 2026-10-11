/**
 * Record direct source evidence: report rows that explicitly tie an IOC to a
 * catalog Malware Family / Threat Actor (e.g. a publisher's IOC appendix).
 *
 * Usage (inside the backend container):
 *   npm run attribution:record-direct-evidence -- --manifest /tmp/report.json            # dry run (default)
 *   npm run attribution:record-direct-evidence -- --manifest /tmp/report.json --apply    # write
 *   Options: --json, --recorded-by <name> (stored in resolved_by / audit actor)
 *
 * Manifest: { "source": { "publisher", "title", "url", "published_at", "section" },
 *             "items": [{ "entity_kind", "entity_name", "source_label"?, "row_label",
 *                         "observable_type", "value", "association_kind"?, "evidence_role"? }] }
 * Items that fail validation, identity or entity checks are skipped and
 * reported; nothing is guessed. See lib/directSourceEvidence.js.
 */
import '../lib/ensure-db-password.js';
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { createAuditLogService } from '../lib/auditLogService.js';
import {
  applyDirectEvidence,
  directEvidenceAuditEvents,
  formatDirectEvidencePlan,
  planDirectEvidence
} from '../lib/directSourceEvidence.js';

const args = process.argv.slice(2);
const single = (flag) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};
const apply = args.includes('--apply');
const json = args.includes('--json');
const manifestPath = single('--manifest');
const recordedBy = String(single('--recorded-by') || 'direct-source-evidence').slice(0, 128);

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  max: 2
});

async function main() {
  if (!manifestPath) throw new Error('--manifest <file.json> is required');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const client = await pool.connect();
  let result;
  try {
    await client.query("SET statement_timeout = '60s'");
    await client.query("SET lock_timeout = '5s'");
    result = apply
      ? await applyDirectEvidence(client, manifest, { recordedBy })
      : await planDirectEvidence(client, manifest);
  } finally {
    client.release();
  }

  if (apply && result.created?.length) {
    const audit = createAuditLogService(pool);
    for (const event of directEvidenceAuditEvents(result, { actorUsername: recordedBy })) {
      await audit.auditSuccess(event);
    }
  }

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    for (const line of formatDirectEvidencePlan(result)) console.log(line);
    if (apply) console.log(`[direct-evidence] written: ${result.created?.length || 0}`);
    else console.log('[direct-evidence] dry run only — rerun with --apply to write');
  }
  if (!result.ok) process.exitCode = 2;
}

main()
  .catch((err) => {
    console.error('[direct-evidence] failed:', err?.message || err);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
