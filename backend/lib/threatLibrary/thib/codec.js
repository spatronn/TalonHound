/**
 * TalonHound Intelligence Bundle (THIB) 1.0 export / import codec.
 * Portable UUIDs only — never local DB IDs.
 */

import crypto from 'node:crypto';
import { z } from 'zod';
import { readCanonicalVersion } from '../../productVersion.js';
import {
  THIB_FORMAT,
  THIB_SPEC_VERSION,
  TLP_VALUES,
  normalizeTlp
} from '../constants.js';
import { attachThibIntegrity, verifyThibIntegrity } from './integrity.js';
import { normalizeCandidateValue } from '../candidateExtraction.js';
import { bulkMatchCandidates } from '../iocMatch.js';

const portableId = z.string().min(8).max(128);

const thibIndicatorSchema = z.object({
  id: portableId,
  type: z.string().min(1).max(32),
  value: z.string().min(1).max(4000),
  assessment: z
    .enum(['malicious', 'suspicious', 'context_only', 'unknown', 'invalid'])
    .optional()
    .default('unknown'),
  role: z.string().max(64).optional().nullable(),
  confidence: z.number().min(0).max(1).nullable().optional(),
  evidence_text: z.string().max(2000).optional().nullable(),
  section: z.string().max(300).optional().nullable(),
  page_number: z.number().int().nullable().optional(),
  block_id: z.string().max(64).optional().nullable()
});

const thibEntitySchema = z.object({
  id: portableId,
  entity_type: z.enum([
    'threat_actor',
    'malware',
    'campaign',
    'tool',
    'vulnerability',
    'infrastructure',
    'organization',
    'attack_pattern'
  ]),
  name: z.string().min(1).max(300),
  aliases: z.array(z.string().max(200)).max(30).optional().default([]),
  description: z.string().max(4000).optional().nullable()
});

const thibRelationshipSchema = z.object({
  id: portableId,
  subject_ref: portableId,
  relationship_type: z.string().min(1).max(64),
  object_ref: portableId,
  role: z.string().max(64).optional().nullable(),
  confidence: z.number().min(0).max(1).nullable().optional(),
  evidence_text: z.string().max(2000).optional().nullable(),
  section: z.string().max(300).optional().nullable(),
  page_number: z.number().int().nullable().optional(),
  block_id: z.string().max(64).optional().nullable()
});

const thibReportSchema = z.object({
  id: portableId,
  title: z.string().min(1).max(500),
  source_type: z.enum(['url', 'pdf', 'thib', 'other']).optional().nullable(),
  source_name: z.string().max(300).optional().nullable(),
  source_url: z.string().max(2000).optional().nullable(),
  source_file_name: z.string().max(300).optional().nullable(),
  source_sha256: z.string().max(128).optional().nullable(),
  published_at: z.string().max(64).optional().nullable(),
  language: z.string().max(16).optional().nullable(),
  tlp: z.string().max(32).optional().default('clear'),
  confidence: z.number().min(0).max(1).nullable().optional(),
  report_type: z.string().max(64).optional().nullable(),
  summary: z.string().max(20000).optional().nullable()
});

export const thibBundleSchema = z.object({
  format: z.literal(THIB_FORMAT),
  spec_version: z.string().min(1).max(16),
  bundle_id: portableId,
  created_at: z.string().min(1).max(64),
  generator: z
    .object({
      name: z.string().max(100),
      version: z.string().max(64).optional().nullable()
    })
    .optional(),
  report: thibReportSchema,
  entities: z.array(thibEntitySchema).max(500).optional().default([]),
  indicators: z.array(thibIndicatorSchema).max(5000).optional().default([]),
  relationships: z.array(thibRelationshipSchema).max(5000).optional().default([]),
  references: z
    .array(
      z.object({
        title: z.string().max(500).optional().nullable(),
        url: z.string().max(2000).optional().nullable()
      })
    )
    .max(50)
    .optional()
    .default([]),
  integrity: z
    .object({
      alg: z.string().optional(),
      content_sha256: z.string().optional(),
      hash: z.string().optional()
    })
    .optional()
});

function newPortable(prefix) {
  return `${prefix}--${crypto.randomUUID()}`;
}

/**
 * Build THIB from a finalized report snapshot (no local DB ids).
 * @param {{
 *   report: object,
 *   entities: object[],
 *   candidates: object[],
 *   relationships: object[]
 * }} snapshot
 */
export function exportThibBundle(snapshot) {
  const report = snapshot.report;
  if (normalizeTlp(report.tlp) === 'red') {
    const err = new Error('TLP:RED reports cannot be exported without explicit elevated export permission');
    err.code = 'tlp_red_export_blocked';
    throw err;
  }

  const entityIdMap = new Map();
  const entities = (snapshot.entities || []).map((e) => {
    const id = e.portable_id || newPortable('entity');
    entityIdMap.set(e.id, id);
    entityIdMap.set(`entity:${e.entity_type}:${e.normalized_name}`, id);
    return {
      id,
      entity_type: e.entity_type,
      name: e.name,
      aliases: e.aliases || [],
      description: e.description || null
    };
  });

  const indicatorIdMap = new Map();
  const indicators = (snapshot.candidates || [])
    .filter((c) => ['approved', 'created_ioc', 'context_only'].includes(c.review_status) || c.match_state === 'existing')
    .filter((c) => c.review_status !== 'ignored' && c.review_status !== 'rejected')
    .map((c) => {
      const id = c.portable_id || newPortable('indicator');
      indicatorIdMap.set(c.id, id);
      indicatorIdMap.set(`${c.candidate_type}:${c.normalized_value}`, id);
      return {
        id,
        type: c.candidate_type,
        value: c.normalized_value,
        assessment: c.assessment,
        role: c.role,
        confidence: c.confidence == null ? null : Number(c.confidence),
        evidence_text: c.evidence_text ? String(c.evidence_text).slice(0, 500) : null,
        section: c.section || null,
        page_number: c.page_number ?? null,
        block_id: c.block_id || null
      };
    });

  const relationships = (snapshot.relationships || []).map((r) => {
    const subjectRef =
      r.subject_portable_ref ||
      (r.subject_entity_id && entityIdMap.get(r.subject_entity_id)) ||
      (r.subject_candidate_id && indicatorIdMap.get(r.subject_candidate_id)) ||
      newPortable('ref');
    const objectRef =
      r.object_portable_ref ||
      (r.object_entity_id && entityIdMap.get(r.object_entity_id)) ||
      (r.object_candidate_id && indicatorIdMap.get(r.object_candidate_id)) ||
      newPortable('ref');
    return {
      id: r.portable_id || newPortable('relationship'),
      subject_ref: subjectRef,
      relationship_type: r.relationship_type,
      object_ref: objectRef,
      role: r.role || null,
      confidence: r.confidence == null ? null : Number(r.confidence),
      evidence_text: r.evidence_text ? String(r.evidence_text).slice(0, 500) : null,
      section: r.section || null,
      page_number: r.page_number ?? null,
      block_id: r.block_id || null
    };
  });

  let version = 'unknown';
  try {
    version = readCanonicalVersion();
  } catch {
    version = process.env.TALONHOUND_VERSION || 'unknown';
  }

  const bundle = {
    format: THIB_FORMAT,
    spec_version: THIB_SPEC_VERSION,
    bundle_id: report.bundle_id || newPortable('thib'),
    created_at: new Date().toISOString(),
    generator: { name: 'TalonHound', version },
    report: {
      id: report.portable_id || newPortable('report'),
      title: report.title,
      source_type: report.source_type,
      source_name: report.source_name || null,
      source_url: report.source_url || null,
      source_file_name: report.source_file_name || null,
      source_sha256: report.source_sha256 || null,
      published_at: report.published_at || null,
      language: report.language || null,
      tlp: normalizeTlp(report.tlp),
      confidence: report.confidence == null ? null : Number(report.confidence),
      report_type: report.report_type || null,
      summary: report.summary || null
    },
    entities,
    indicators,
    relationships,
    references: report.source_url
      ? [{ title: report.title, url: report.source_url }]
      : []
  };

  const sealed = attachThibIntegrity(bundle);

  // Safety: ensure no local numeric ioc_id fields leaked
  const serialized = JSON.stringify(sealed);
  if (/"ioc_id"\s*:/.test(serialized) || /"matched_ioc_id"\s*:/.test(serialized)) {
    const err = new Error('THIB export unexpectedly contained local IOC ids');
    err.code = 'thib_export_leak';
    throw err;
  }

  return sealed;
}

/**
 * Validate THIB JSON structurally + integrity (no AI).
 * @param {unknown} raw
 */
export function validateThibBundle(raw) {
  const parsed = thibBundleSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      error: 'THIB schema validation failed',
      details: parsed.error.issues.slice(0, 30).map((i) => ({
        path: i.path.join('.'),
        message: i.message
      }))
    };
  }
  const bundle = parsed.data;
  if (bundle.format !== THIB_FORMAT) {
    return { ok: false, error: 'Invalid format identifier' };
  }
  const major = String(bundle.spec_version).split('.')[0];
  if (major !== '1') {
    return { ok: false, error: `Unsupported THIB spec_version: ${bundle.spec_version}` };
  }
  const integrity = verifyThibIntegrity(bundle);
  if (!integrity.ok) return integrity;

  // Normalize TLP
  bundle.report.tlp = normalizeTlp(bundle.report.tlp);
  if (!TLP_VALUES.includes(bundle.report.tlp)) {
    bundle.report.tlp = 'clear';
  }

  return { ok: true, bundle };
}

/**
 * Preview THIB import: normalize indicators + bulk match local IOC DB (no AI, no write).
 * @param {import('pg').Pool} pool
 * @param {object} bundle
 */
export async function previewThibImport(pool, bundle) {
  const validation = validateThibBundle(bundle);
  if (!validation.ok) return validation;

  const b = validation.bundle;
  const { rows: existing } = await pool.query(
    `SELECT id, public_id, title, import_status FROM threat_reports
     WHERE bundle_id = $1 AND deleted_at IS NULL LIMIT 1`,
    [b.bundle_id]
  );
  if (existing[0]) {
    return {
      ok: true,
      already_imported: true,
      report: existing[0],
      bundle: b,
      summary: {
        indicators: b.indicators.length,
        already_in_talonhound: 0,
        new: 0,
        invalid: 0,
        conflicts: 0
      }
    };
  }

  const candidates = [];
  let invalid = 0;
  for (const ind of b.indicators) {
    const n = normalizeCandidateValue(ind.value, ind.type);
    if (!n.ok || !n.isIoc) {
      invalid += 1;
      candidates.push({
        portable_id: ind.id,
        candidate_type: ind.type,
        original_value: ind.value,
        normalized_value: ind.value,
        assessment: 'invalid',
        role: ind.role || 'unknown',
        confidence: ind.confidence ?? null,
        evidence_text: ind.evidence_text || null,
        section: ind.section || null,
        page_number: ind.page_number ?? null,
        block_id: ind.block_id || null,
        is_ioc: false
      });
      continue;
    }
    candidates.push({
      portable_id: ind.id,
      candidate_type: n.candidateType,
      original_value: ind.value,
      normalized_value: n.normalizedValue,
      assessment: ind.assessment || 'unknown',
      role: ind.role || 'unknown',
      confidence: ind.confidence ?? null,
      evidence_text: ind.evidence_text || null,
      section: ind.section || null,
      page_number: ind.page_number ?? null,
      block_id: ind.block_id || null,
      is_ioc: true
    });
  }

  const matched = await bulkMatchCandidates(pool, candidates);
  const conflicts = matched.candidates.filter((c) => {
    if (!c.matched_ioc_id) return false;
    // Conflict if imported assessment differs from a simple local existence claim — preserve both later
    return c.assessment === 'malicious' || c.assessment === 'suspicious';
  }).length;

  return {
    ok: true,
    already_imported: false,
    bundle: b,
    candidates: matched.candidates,
    entities: b.entities,
    relationships: b.relationships,
    summary: {
      indicators: b.indicators.length,
      already_in_talonhound: matched.summary.existing,
      new: matched.summary.new,
      invalid: invalid + matched.summary.invalid,
      conflicts,
      context_only: matched.summary.context_only,
      needs_review: matched.summary.needs_review
    }
  };
}
