#!/usr/bin/env node
/**
 * Dry-run audit of Threat Library IP candidates whose only source evidence is
 * a numeric prefix of a larger DNS hostname (e.g. 10.20.30.40.foo.example.com).
 *
 * Does NOT modify production data. `--apply` is rejected: cleanup is a
 * re-extract / Retry after tl-candidates-v8, not a DELETE from this script.
 *
 *   node scripts/audit-embedded-hostname-ip-candidates.js [--report <public_id|id>]
 */

import '../lib/ensure-db-password.js';
import pg from 'pg';
import { isOnlyEmbeddedInDnsHostname } from '../lib/threatLibrary/sourceOccurrence.js';

const args = process.argv.slice(2);
if (args.includes('--apply') || args.includes('--delete') || args.includes('--fix')) {
  console.error('Refusing destructive flags. Re-run report analysis (Retry) after tl-candidates-v8.');
  process.exit(2);
}

const onlyIdx = args.indexOf('--report');
const only = onlyIdx >= 0 ? args[onlyIdx + 1] : null;

function connectionConfig() {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound'
  };
}

function evidenceHaystack(row) {
  const parts = [row.evidence_text || ''];
  const ev = row.evidence && typeof row.evidence === 'object' ? row.evidence : {};
  for (const o of ev.occurrences || []) {
    if (o?.surrounding_text) parts.push(String(o.surrounding_text));
  }
  if (Array.isArray(row.document_blocks)) {
    for (const b of row.document_blocks) {
      if (b?.text) parts.push(String(b.text));
    }
  }
  return parts.join('\n');
}

async function main() {
  const pool = new pg.Pool(connectionConfig());
  try {
    const params = [];
    let where = `c.candidate_type = 'ip'`;
    if (only) {
      params.push(only);
      where += ` AND (r.public_id::text = $1 OR r.id::text = $1)`;
    }
    const { rows } = await pool.query(
      `SELECT c.id, c.public_id, c.report_id, r.public_id AS report_public_id,
              r.title, r.source_url, r.analysis_status, r.import_status,
              c.candidate_type, c.original_value, c.normalized_value,
              c.assessment, c.review_status, c.match_state, c.matched_ioc_id,
              c.evidence_text, c.evidence,
              r.canonical_document
         FROM threat_report_candidates c
         JOIN threat_reports r ON r.id = c.report_id
        WHERE ${where}
        ORDER BY c.id`,
      params
    );

    const flagged = [];
    for (const row of rows) {
      const blocks = row.canonical_document?.blocks || [];
      const hay = evidenceHaystack({ ...row, document_blocks: blocks });
      if (!hay.trim()) continue;
      if (isOnlyEmbeddedInDnsHostname(hay, 'ip', row.normalized_value)) {
        flagged.push({
          candidate_id: row.id,
          candidate_public_id: row.public_id,
          report_id: row.report_id,
          report_public_id: row.report_public_id,
          title: row.title,
          source_url: row.source_url,
          analysis_status: row.analysis_status,
          import_status: row.import_status,
          value: row.normalized_value,
          original_value: row.original_value,
          assessment: row.assessment,
          review_status: row.review_status,
          match_state: row.match_state,
          matched_ioc_id: row.matched_ioc_id,
          evidence_text: (row.evidence_text || '').slice(0, 240)
        });
      }
    }

    console.log(
      JSON.stringify(
        {
          dry_run: true,
          ip_candidates_scanned: rows.length,
          embedded_only_flagged: flagged.length,
          safest_cleanup:
            'Do not DELETE rows. Retry/re-analyze each affected report so tl-candidates-v8 rebuilds the candidate set. If review_status is created_ioc, review the linked IOC separately — it may be a false positive.',
          flagged
        },
        null,
        2
      )
    );
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
