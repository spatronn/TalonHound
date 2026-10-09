#!/usr/bin/env node
/**
 * Repair the confidence provenance of IOCs created by Threat Library.
 *
 * Before a44bc84, Threat Library "Create IOCs" passed the report's assertion
 * strength (candidate confidence >= 0.85 → high, else medium) to
 * createManualIoc, which recorded it as confidence_source = 'manual_entry'
 * ("Source: Manual entry"). New rows record 'source_entry' with
 * confidence_source_name = the Threat Library source ("Threat_Library entry
 * confidence"). This script relabels the old rows — provenance only: the
 * confidence value, analyst overrides, status, expiry and every other column
 * stay as they are.
 *
 * A row is relabelled only when its Threat Library origin is provable:
 *   - ioc_source_id is the Threat Library IOC source and source_name matches it
 *   - created_origin = 'manual_add' and confidence_source = 'manual_entry'
 *   - confidence is high or medium (the only values Threat Library writes)
 *   - note is exactly the Threat Library writer's
 *     "Threat Library report <uuid>: <role> (<malicious|suspicious>)"
 *     and <uuid> is an existing Threat Library report
 * Anything else is listed and left unchanged. The UPDATE repeats every
 * predicate (exact-match guard), so a row edited after planning is skipped.
 *
 * Note: ioc_items has a BEFORE UPDATE trigger that sets updated_at = NOW();
 * relabelled rows are therefore re-evaluated once by incremental Published
 * Feeds. confidence_source is not part of any feed output, so feed content
 * does not change.
 *
 * Dry-run by default; pass --apply to write. Idempotent.
 *
 *   node scripts/repair-threat-library-confidence-provenance.js [--apply]
 */

import '../lib/ensure-db-password.js';
import pg from 'pg';
import { IOC_SOURCE_NAME } from '../lib/threatLibrary/constants.js';

export const THREAT_LIBRARY_NOTE_RE =
  /^Threat Library report ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}): [a-z_]+ \((malicious|suspicious)\)$/;

/**
 * Classify one ioc_items row. Pure so it can be unit tested.
 * @param {{ ioc_source_id: number|string|null, source_name: string|null, created_origin: string|null,
 *   confidence_source: string|null, confidence: string|null, note: string|null, report_exists: boolean }} row
 * @param {number} threatLibrarySourceId
 * @returns {{ decision: string, change: boolean }}
 */
export function planConfidenceProvenanceRepair(row, threatLibrarySourceId) {
  if (String(row?.confidence_source || '') === 'source_entry') return { decision: 'already_source_entry', change: false };
  if (Number(row?.ioc_source_id) !== Number(threatLibrarySourceId) || row?.source_name !== IOC_SOURCE_NAME) {
    return { decision: 'not_threat_library_source', change: false };
  }
  if (row.created_origin !== 'manual_add') return { decision: 'unexpected_origin', change: false };
  if (row.confidence_source !== 'manual_entry') return { decision: 'unexpected_provenance', change: false };
  if (!['high', 'medium'].includes(String(row.confidence || ''))) return { decision: 'unexpected_confidence', change: false };
  if (!THREAT_LIBRARY_NOTE_RE.test(String(row.note || ''))) return { decision: 'note_not_threat_library', change: false };
  if (row.report_exists !== true) return { decision: 'report_missing', change: false };
  return { decision: 'relabel', change: true };
}

function connectionConfig() {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound'
  };
}

async function main() {
  const apply = process.argv.slice(2).includes('--apply');
  const pool = new pg.Pool(connectionConfig());
  try {
    const src = await pool.query(`SELECT id FROM ioc_sources WHERE name = $1 AND archived_at IS NULL LIMIT 1`, [IOC_SOURCE_NAME]);
    const sourceId = src.rows[0]?.id ? Number(src.rows[0].id) : null;
    if (!sourceId) throw new Error(`IOC source ${IOC_SOURCE_NAME} not found`);
    const { rows } = await pool.query(
      `SELECT i.id, i.observable_type, i.observable, i.ioc_source_id, i.source_name, i.created_origin,
              i.confidence_source, i.confidence, i.note,
              EXISTS (
                SELECT 1 FROM threat_reports r
                WHERE r.public_id::text = substring(i.note FROM '^Threat Library report ([0-9a-f-]{36}):')
              ) AS report_exists
       FROM ioc_items i
       WHERE i.ioc_source_id = $1
       ORDER BY i.id`,
      [sourceId]
    );
    const summary = { mode: apply ? 'apply' : 'dry-run', total: rows.length, relabel: 0, updated: 0, skipped_changed_since_plan: 0, decisions: {} };
    const examples = [];
    for (const row of rows) {
      const plan = planConfidenceProvenanceRepair(row, sourceId);
      summary.decisions[plan.decision] = (summary.decisions[plan.decision] || 0) + 1;
      if (!plan.change) {
        if (plan.decision !== 'already_source_entry' && examples.length < 20) {
          examples.push(`${row.id} ${row.observable_type} ${row.observable} [${plan.decision}]`);
        }
        continue;
      }
      summary.relabel += 1;
      if (!apply) continue;
      const res = await pool.query(
        `UPDATE ioc_items
            SET confidence_source = 'source_entry',
                confidence_source_name = $3
          WHERE id = $1 AND observable_type = $2
            AND ioc_source_id = $4 AND source_name = $3
            AND created_origin = 'manual_add'
            AND confidence_source = 'manual_entry'
            AND confidence = $5
            AND note = $6`,
        [row.id, row.observable_type, IOC_SOURCE_NAME, sourceId, row.confidence, row.note]
      );
      if (res.rowCount === 1) summary.updated += 1;
      else summary.skipped_changed_since_plan += 1;
    }
    for (const line of examples) console.log(`left unchanged: ${line}`);
    console.log(JSON.stringify(summary));
  } finally {
    await pool.end();
  }
}

const invokedDirectly = process.argv[1] && /repair-threat-library-confidence-provenance\.js$/.test(process.argv[1]);
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
