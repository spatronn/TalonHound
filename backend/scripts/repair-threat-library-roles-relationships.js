#!/usr/bin/env node
/**
 * Repair Threat Library data persisted before the deterministic role and
 * relationship policies (evidencePolicy.enforceRoleTypeCompatibility,
 * relationshipPolicy.validateRelationship) existed.
 *
 * Candidates: a file hash (md5/sha1/sha256) carrying a role that is invalid for
 *   a file (command_and_control, payload_hosting, …) gets the canonical role the
 *   policy assigns (malware_sample, or reference for a non-malicious row).
 *   Nothing else on the row changes.
 *
 * Relationships: a row is deleted only when the deterministic type policy
 *   rejects it (unknown type, incompatible endpoint kinds, or an indicator the
 *   candidate policy classified context only) — no text can make such a
 *   relationship valid, and co-mention is not evidence of it. Type-valid rows
 *   the report does not support (relationshipPolicy.checkRelationshipEvidence)
 *   are only listed: a re-analysis would not recreate them.
 *
 * Dry-run by default; pass --apply to write. Idempotent.
 *
 *   node scripts/repair-threat-library-roles-relationships.js [--apply] [--report <public_id>]
 */

import '../lib/ensure-db-password.js';
import pg from 'pg';
import { enforceRoleTypeCompatibility } from '../lib/threatLibrary/evidencePolicy.js';
import {
  buildEvidenceIndex,
  checkRelationshipEvidence,
  publisherTokens,
  validateRelationship
} from '../lib/threatLibrary/relationshipPolicy.js';

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
 * @param {{ candidate_type: string, role: string|null, assessment: string|null }} row
 */
export function planCandidateRoleRepair(row) {
  const current = row.role || 'unknown';
  const next = enforceRoleTypeCompatibility({ ...row, role: current }).role;
  return { change: next !== current, from: current, to: next };
}

/**
 * @param {object} row relationship joined with endpoint metadata
 *   { relationship_type, evidence_text, block_id, subject_kind, subject_entity_type,
 *     subject_names, subject_candidate_type, subject_candidate_values, object_* (same) }
 * @param {{ evidenceIndex: ReturnType<typeof buildEvidenceIndex>, publisherTokens: string[] }} ctx
 * @returns {{ decision: 'keep'|'delete'|'keep_type_valid_without_evidence', reason: string|null }}
 */
export function planRelationshipRepair(row, ctx) {
  const endpoint = (side) =>
    row[`${side}_kind`] === 'entity'
      ? { kind: 'entity', entity_type: row[`${side}_entity_type`], names: row[`${side}_names`] || [] }
      : {
          kind: 'candidate',
          candidate_type: row[`${side}_candidate_type`],
          assessment: row[`${side}_candidate_assessment`],
          names: row[`${side}_candidate_values`] || []
        };
  const subject = endpoint('subject');
  const object = endpoint('object');
  const rel = {
    relationship_type: row.relationship_type,
    evidence_text: row.evidence_text,
    evidence_block_ids: row.block_id ? [row.block_id] : []
  };
  const typeVerdict = validateRelationship(rel, subject, object);
  if (!typeVerdict.ok) return { decision: 'delete', reason: typeVerdict.reason };
  const evidence = checkRelationshipEvidence(rel, subject, object, ctx);
  return evidence.ok
    ? { decision: 'keep', reason: null }
    : { decision: 'keep_type_valid_without_evidence', reason: evidence.reason };
}

const REPORT_FILTER = onlyPublicId ? 'AND r.public_id = $1' : '';
const REPORT_PARAMS = onlyPublicId ? [onlyPublicId] : [];

async function repairCandidateRoles(pool) {
  const { rows } = await pool.query(
    `SELECT c.id, c.candidate_type, c.normalized_value, c.role, c.assessment, r.public_id AS report_public_id
     FROM threat_report_candidates c
     JOIN threat_reports r ON r.id = c.report_id
     WHERE r.deleted_at IS NULL
       AND c.candidate_type IN ('md5', 'sha1', 'sha256')
       ${REPORT_FILTER}
     ORDER BY c.id`,
    REPORT_PARAMS
  );
  let changed = 0;
  for (const row of rows) {
    const plan = planCandidateRoleRepair(row);
    if (!plan.change) continue;
    changed += 1;
    console.log(
      `candidate ${row.id} report=${row.report_public_id} ${row.candidate_type}:${row.normalized_value} role ${plan.from} -> ${plan.to} [${apply ? 'APPLIED' : 'would change'}]`
    );
    if (apply) {
      // Guard on the old role: a concurrent re-analysis or re-run never gets overwritten.
      await pool.query(
        `UPDATE threat_report_candidates SET role = $2, updated_at = NOW() WHERE id = $1 AND role = $3`,
        [row.id, plan.to, plan.from]
      );
    }
  }
  return { scanned: rows.length, changed };
}

async function repairRelationships(pool) {
  const { rows } = await pool.query(
    `SELECT t.id, t.relationship_type, t.evidence_text, t.block_id,
            t.subject_kind, t.object_kind,
            se.entity_type AS subject_entity_type,
            CASE WHEN se.id IS NULL THEN NULL
                 ELSE ARRAY[se.name] || COALESCE((SELECT array_agg(a.alias) FROM threat_entity_aliases a WHERE a.entity_id = se.id), ARRAY[]::text[])
            END AS subject_names,
            sc.candidate_type AS subject_candidate_type, sc.assessment AS subject_candidate_assessment,
            CASE WHEN sc.id IS NULL THEN NULL ELSE ARRAY[sc.normalized_value, sc.original_value] END AS subject_candidate_values,
            oe.entity_type AS object_entity_type,
            CASE WHEN oe.id IS NULL THEN NULL
                 ELSE ARRAY[oe.name] || COALESCE((SELECT array_agg(a.alias) FROM threat_entity_aliases a WHERE a.entity_id = oe.id), ARRAY[]::text[])
            END AS object_names,
            oc.candidate_type AS object_candidate_type, oc.assessment AS object_candidate_assessment,
            CASE WHEN oc.id IS NULL THEN NULL ELSE ARRAY[oc.normalized_value, oc.original_value] END AS object_candidate_values,
            r.id AS report_id, r.public_id AS report_public_id, r.source_url, r.source_name
     FROM threat_relationships t
     JOIN threat_reports r ON r.id = t.report_id
     LEFT JOIN threat_entities se ON se.id = t.subject_entity_id
     LEFT JOIN threat_entities oe ON oe.id = t.object_entity_id
     LEFT JOIN threat_report_candidates sc ON sc.id = t.subject_candidate_id
     LEFT JOIN threat_report_candidates oc ON oc.id = t.object_candidate_id
     WHERE r.deleted_at IS NULL
       ${REPORT_FILTER}
     ORDER BY r.id, t.id`,
    REPORT_PARAMS
  );

  const ctxByReport = new Map();
  const summary = { scanned: rows.length, keep: 0, delete: 0, keep_type_valid_without_evidence: 0 };
  for (const row of rows) {
    if (!ctxByReport.has(row.report_id)) {
      // Canonical documents are large: load one report at a time.
      const { rows: docRows } = await pool.query(`SELECT canonical_document FROM threat_reports WHERE id = $1`, [row.report_id]);
      const document = docRows[0]?.canonical_document || null;
      ctxByReport.clear();
      ctxByReport.set(row.report_id, {
        evidenceIndex: buildEvidenceIndex(document, { sourceUrl: row.source_url }),
        publisherTokens: publisherTokens(row, document)
      });
    }
    const plan = planRelationshipRepair(row, ctxByReport.get(row.report_id));
    summary[plan.decision] += 1;
    if (plan.decision === 'keep') continue;
    const subject = row.subject_names?.[0] || row.subject_candidate_values?.[0] || '?';
    const object = row.object_names?.[0] || row.object_candidate_values?.[0] || '?';
    const label = plan.decision === 'delete' ? (apply ? 'DELETED' : 'would delete') : plan.decision;
    console.log(
      `relationship ${row.id} report=${row.report_public_id} ${row.subject_entity_type || row.subject_candidate_type}:${subject} --${row.relationship_type}--> ${row.object_entity_type || row.object_candidate_type}:${object} [${label}] (${plan.reason})`
    );
    if (apply && plan.decision === 'delete') {
      await pool.query(`DELETE FROM threat_relationships WHERE id = $1`, [row.id]);
    }
  }
  return summary;
}

async function main() {
  const pool = new pg.Pool(connectionConfig());
  try {
    const roles = await repairCandidateRoles(pool);
    const relationships = await repairRelationships(pool);
    console.log(JSON.stringify({ mode: apply ? 'apply' : 'dry-run', report: onlyPublicId, roles, relationships }));
  } finally {
    await pool.end();
  }
}

const invokedDirectly = process.argv[1] && /repair-threat-library-roles-relationships\.js$/.test(process.argv[1]);
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
