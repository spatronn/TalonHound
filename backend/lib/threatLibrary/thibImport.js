/**
 * Persist a validated THIB import after analyst confirmation (no AI).
 */

import crypto from 'node:crypto';
import { previewThibImport } from './thib/codec.js';
import { normalizeTlp } from './constants.js';
import {
  createThreatReport,
  replaceCandidates,
  upsertEntity,
  linkReportEntity,
  replaceRelationships,
  updateReportStatus,
  insertArtifact,
  getReportById
} from './store.js';

/**
 * @param {import('pg').Pool} pool
 * @param {object} bundle
 * @param {{ createdBy?: string, createIocs?: boolean, conflictMode?: 'keep_both'|'keep_local'|'accept_imported' }} opts
 */
export async function importThibBundle(pool, bundle, opts = {}) {
  const preview = await previewThibImport(pool, bundle);
  if (!preview.ok) return preview;
  if (preview.already_imported) {
    return {
      ok: true,
      already_imported: true,
      report: preview.report,
      message: 'Already imported'
    };
  }

  const b = preview.bundle;
  const conflictMode = opts.conflictMode || 'keep_both';

  const report = await createThreatReport(pool, {
    title: b.report.title,
    source_type: 'thib',
    source_name: b.report.source_name || b.generator?.name || 'THIB',
    source_url: b.report.source_url,
    source_file_name: b.report.source_file_name,
    source_sha256: b.report.source_sha256,
    published_at: b.report.published_at,
    language: b.report.language,
    tlp: normalizeTlp(b.report.tlp),
    confidence: b.report.confidence,
    report_type: b.report.report_type,
    summary: b.report.summary,
    import_status: 'processing',
    analysis_status: 'skipped',
    portable_id: b.report.id,
    bundle_id: b.bundle_id,
    created_by: opts.createdBy || null
  });

  await insertArtifact(pool, report.id, {
    artifact_type: 'thib_upload',
    file_name: `${b.bundle_id}.thib.json`,
    mime_type: 'application/json',
    source_metadata: {
      bundle_id: b.bundle_id,
      spec_version: b.spec_version,
      integrity: b.integrity,
      conflict_mode: conflictMode
    }
  });

  // Entities first
  const entityByPortable = new Map();
  for (const e of b.entities || []) {
    const row = await upsertEntity(pool, {
      portable_id: e.id,
      entity_type: e.entity_type,
      name: e.name,
      aliases: e.aliases,
      description: e.description
    });
    entityByPortable.set(e.id, row);
    await linkReportEntity(pool, report.id, row.id, {});
  }

  const candidates = (preview.candidates || []).map((c) => {
    // keep_both: never overwrite local assessment via IOC mutation; store imported claim on candidate
    if (conflictMode === 'keep_local' && c.matched_ioc_id) {
      return { ...c, review_status: 'approved', assessment: c.assessment };
    }
    if (conflictMode === 'accept_imported' && c.matched_ioc_id) {
      return { ...c, review_status: 'approved' };
    }
    return {
      ...c,
      review_status: c.matched_ioc_id ? 'approved' : c.assessment === 'context_only' ? 'context_only' : 'pending'
    };
  });

  const saved = await replaceCandidates(pool, report.id, candidates);
  const candByPortable = new Map(saved.map((c) => [c.portable_id, c]));

  const rels = [];
  for (const r of b.relationships || []) {
    const subjectEntity = entityByPortable.get(r.subject_ref);
    const objectEntity = entityByPortable.get(r.object_ref);
    const subjectCand = candByPortable.get(r.subject_ref);
    const objectCand = candByPortable.get(r.object_ref);
    if (!subjectEntity && !subjectCand) continue;
    if (!objectEntity && !objectCand) continue;
    rels.push({
      portable_id: r.id || `relationship--${crypto.randomUUID()}`,
      subject_kind: subjectEntity ? 'entity' : 'candidate',
      subject_entity_id: subjectEntity?.id || null,
      subject_candidate_id: subjectCand?.id || null,
      subject_ioc_id: subjectCand?.matched_ioc_id || null,
      subject_portable_ref: r.subject_ref,
      relationship_type: r.relationship_type,
      object_kind: objectEntity ? 'entity' : 'candidate',
      object_entity_id: objectEntity?.id || null,
      object_candidate_id: objectCand?.id || null,
      object_ioc_id: objectCand?.matched_ioc_id || null,
      object_portable_ref: r.object_ref,
      role: r.role,
      confidence: r.confidence,
      evidence_text: r.evidence_text,
      section: r.section,
      page_number: r.page_number,
      block_id: r.block_id
    });
  }
  await replaceRelationships(pool, report.id, rels);

  const summary = preview.summary;
  await updateReportStatus(pool, report.id, {
    import_status: 'review_required',
    analysis_status: 'skipped',
    candidate_summary: {
      total: summary.indicators,
      existing: summary.already_in_talonhound,
      new: summary.new,
      invalid: summary.invalid,
      context_only: summary.context_only || 0,
      needs_review: summary.needs_review || 0,
      conflicts: summary.conflicts
    },
    thib_spec_version: b.spec_version
  });

  // Fix thib_spec_version column via direct update (updateReportStatus may not include it)
  await pool.query(`UPDATE threat_reports SET thib_spec_version = $2, updated_at = NOW() WHERE id = $1`, [
    report.id,
    b.spec_version
  ]);

  return {
    ok: true,
    already_imported: false,
    report: await getReportById(pool, report.id),
    summary
  };
}
