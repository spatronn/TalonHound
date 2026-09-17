#!/usr/bin/env node
/**
 * Repair Threat Library report TLP values that were invented by the AI stage.
 *
 * Before tlpPolicy.js, the pipeline persisted whatever `tlp` the model
 * returned, so public reports without any TLP marking ended up TLP:AMBER.
 * This script re-derives the effective TLP deterministically and only changes
 * a report when the correction is provable:
 *
 *   manual       -> never touched
 *   explicit     -> document carries a TLP marking: tlp = marking, source = explicit
 *   default      -> no marking and the current value is either already the
 *                   default OR provably came from the model (the cached chunk /
 *                   synthesis result of the report's analysis run returned it)
 *   ambiguous    -> no marking, value differs from the default and no cached
 *                   model output explains it (e.g. supplied at import time):
 *                   left unchanged and listed for manual review
 *
 * Dry-run by default; pass --apply to write. Idempotent.
 *
 *   node scripts/repair-threat-library-tlp.js [--apply] [--report <public_id>]
 */

import '../lib/ensure-db-password.js';
import pg from 'pg';
import { normalizeTlp } from '../lib/threatLibrary/constants.js';
import { defaultTlpForSource, detectExplicitTlp } from '../lib/threatLibrary/tlpPolicy.js';

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const onlyIdx = args.indexOf('--report');
const onlyPublicId = onlyIdx >= 0 ? args[onlyIdx + 1] : null;

function connectionConfig() {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound'
  };
}

/**
 * Classify one report row. Pure so it can be unit tested.
 * @param {{ tlp: string, tlp_source: string, source_type: string, canonical_document: object|null }} report
 * @param {string[]} modelTlps  normalized `tlp` values the model returned for the current analysis run
 */
export function planTlpRepair(report, modelTlps = []) {
  const current = normalizeTlp(report.tlp || 'clear');
  const source = String(report.tlp_source || 'default');
  if (source === 'manual') {
    return { decision: 'skip_manual', tlp: current, tlp_source: 'manual', change: false };
  }
  const detection = detectExplicitTlp(report.canonical_document);
  if (detection) {
    return {
      decision: 'explicit',
      tlp: detection.tlp,
      tlp_source: 'explicit',
      change: detection.tlp !== current || source !== 'explicit',
      evidence: detection.matches.slice(0, 3).map((m) => m.marking)
    };
  }
  const fallback = defaultTlpForSource(report.source_type);
  if (current === fallback) {
    return { decision: 'default', tlp: fallback, tlp_source: 'default', change: source !== 'default' };
  }
  const modelSaidIt = modelTlps.map((v) => normalizeTlp(v)).includes(current);
  if (modelSaidIt) {
    return {
      decision: 'model_invented',
      tlp: fallback,
      tlp_source: 'default',
      change: true,
      evidence: [`model returned ${current}`]
    };
  }
  return { decision: 'ambiguous', tlp: current, tlp_source: source, change: false };
}

async function main() {
  const pool = new pg.Pool(connectionConfig());
  try {
    const { rows } = await pool.query(
      `SELECT r.id, r.public_id, r.title, r.source_type, r.tlp, r.tlp_source, r.canonical_document,
              COALESCE((
                SELECT array_agg(c.result->>'tlp')
                FROM threat_library_analysis_chunks c
                WHERE c.report_id = r.id
                  AND c.analysis_run_id = r.analysis_run_id
                  AND c.result->>'tlp' IS NOT NULL
              ), ARRAY[]::text[]) AS model_tlps
       FROM threat_reports r
       WHERE r.deleted_at IS NULL
         ${onlyPublicId ? 'AND r.public_id = $1' : ''}
       ORDER BY r.id`,
      onlyPublicId ? [onlyPublicId] : []
    );
    const summary = { total: rows.length, changed: 0, skipped_manual: 0, explicit: 0, default: 0, model_invented: 0, ambiguous: 0 };
    for (const r of rows) {
      const plan = planTlpRepair(r, r.model_tlps || []);
      summary[plan.decision === 'skip_manual' ? 'skipped_manual' : plan.decision] += 1;
      const line = [
        r.public_id,
        `${r.source_type}`,
        `${r.tlp}/${r.tlp_source}`,
        '->',
        `${plan.tlp}/${plan.tlp_source}`,
        `[${plan.decision}${plan.change ? (apply ? ' APPLIED' : ' would change') : ''}]`,
        plan.evidence ? `(${plan.evidence.join('; ')})` : '',
        `"${String(r.title || '').slice(0, 60)}"`
      ].join(' ');
      console.log(line);
      if (plan.change) {
        summary.changed += 1;
        if (apply) {
          await pool.query(
            `UPDATE threat_reports SET tlp = $2, tlp_source = $3, updated_at = NOW() WHERE id = $1`,
            [r.id, plan.tlp, plan.tlp_source]
          );
        }
      }
    }
    console.log(JSON.stringify({ mode: apply ? 'apply' : 'dry-run', ...summary }));
  } finally {
    await pool.end();
  }
}

const invokedDirectly = process.argv[1] && /repair-threat-library-tlp\.js$/.test(process.argv[1]);
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
