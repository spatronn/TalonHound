/**
 * Strict Zod schema + phased validation for AI semantic analysis output.
 * AI must never invent local IOC database IDs.
 */

import { z } from 'zod';
import { normalizeAiAnalysisInput } from './normalize.js';
import { extractJsonObject, capRawOutputSample } from './extract.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './contract.js';

const conf = z.number().min(0).max(1).nullable().optional();

export const assessmentEnum = z.enum(['malicious', 'suspicious', 'context_only', 'unknown', 'invalid']);
export const roleEnum = z.enum([
  'command_and_control',
  'redirector',
  'payload_hosting',
  'malware_download',
  'phishing',
  'tracking',
  'malicious_infrastructure',
  'delivery',
  'legitimate_service',
  'hosting_platform',
  'victim',
  'reference',
  'security_tool',
  'unknown'
]);
export const entityTypeEnum = z.enum([
  'threat_actor',
  'malware',
  'campaign',
  'tool',
  'vulnerability',
  'infrastructure',
  'organization',
  'attack_pattern'
]);

export const aiEntitySchema = z.object({
  entity_type: entityTypeEnum,
  name: z.string().min(1).max(300),
  aliases: z.array(z.string().max(200)).max(20).optional().default([]),
  description: z.string().max(2000).optional().nullable(),
  confidence: conf,
  evidence_block_ids: z.array(z.string().max(64)).max(20).optional().default([]),
  evidence_text: z.string().max(1000).optional().nullable()
});

export const aiCandidateUpdateSchema = z.object({
  candidate_id: z.string().min(1).max(64).optional().nullable(),
  candidate_type: z.string().min(1).max(32),
  normalized_value: z.string().min(1).max(2000),
  assessment: assessmentEnum,
  role: roleEnum.or(z.string().max(64)),
  confidence: conf,
  evidence_block_ids: z.array(z.string().max(64)).max(10).optional().default([]),
  evidence_text: z.string().max(1000).optional().nullable(),
  section: z.string().max(300).optional().nullable()
});

export const aiRelationshipSchema = z.object({
  subject_kind: z.enum(['entity', 'candidate']),
  subject_ref: z.string().min(1).max(400),
  relationship_type: z.string().min(1).max(64),
  object_kind: z.enum(['entity', 'candidate']),
  object_ref: z.string().min(1).max(400),
  role: z.string().max(64).optional().nullable(),
  confidence: conf,
  evidence_block_ids: z.array(z.string().max(64)).max(10).optional().default([]),
  evidence_text: z.string().max(1000).optional().nullable()
});

export const aiAnalysisSchema = z.object({
  summary: z.string().max(8000),
  report_type: z.string().max(64).optional().nullable(),
  language: z.string().max(16).optional().nullable(),
  tlp: z.string().max(32).optional().nullable(),
  confidence: conf,
  entities: z.array(aiEntitySchema).max(100).optional().default([]),
  candidate_updates: z.array(aiCandidateUpdateSchema).max(500).optional().default([]),
  relationships: z.array(aiRelationshipSchema).max(300).optional().default([])
});

function zodIssues(error) {
  return error.issues.slice(0, 30).map((i) => ({
    path: i.path.join('.') || '(root)',
    message: i.message,
    expected: i.expected != null ? String(i.expected) : undefined,
    received: i.received != null ? String(i.received) : undefined,
    code: i.code
  }));
}

/**
 * Structural Zod validation only.
 * @param {unknown} raw
 */
export function validateAiStructure(raw) {
  const parsed = aiAnalysisSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'ai_output_schema_error',
      error: 'AI response failed schema validation',
      details: zodIssues(parsed.error)
    };
  }
  return { ok: true, value: parsed.data };
}

/**
 * Semantic / reference validation after structure passes.
 * Policy: drop invalid optional relationships; reject unknown candidate_updates;
 * strip unknown block ids; never accept local DB ids.
 *
 * @param {object} data
 * @param {{
 *   knownBlockIds?: Set<string>,
 *   knownCandidateKeys?: Set<string>,
 *   candidateIdMap?: Map<string, { candidate_type: string, normalized_value: string }>
 * }} [ctx]
 */
export function validateAiReferences(data, ctx = {}) {
  const rejected = [];
  const knownBlocks = ctx.knownBlockIds || null;
  const knownCandidates = ctx.knownCandidateKeys || null;
  const idMap = ctx.candidateIdMap || new Map();

  const filterBlocks = (ids, path) => {
    if (!knownBlocks) return ids || [];
    const kept = [];
    for (const id of ids || []) {
      if (knownBlocks.has(id)) kept.push(id);
      else rejected.push({ path, code: 'unknown_block_id', message: `Unknown block id ${id}` });
    }
    return kept;
  };

  const entities = (data.entities || []).map((e, idx) => ({
    ...e,
    evidence_block_ids: filterBlocks(e.evidence_block_ids, `entities[${idx}].evidence_block_ids`)
  }));

  const candidate_updates = [];
  for (let idx = 0; idx < (data.candidate_updates || []).length; idx += 1) {
    const u = data.candidate_updates[idx];
    let candidate_type = u.candidate_type;
    let normalized_value = u.normalized_value;
    if (u.candidate_id && idMap.has(String(u.candidate_id))) {
      const ref = idMap.get(String(u.candidate_id));
      candidate_type = ref.candidate_type;
      normalized_value = ref.normalized_value;
    }
    const key = `${candidate_type}\0${normalized_value}`;
    if (knownCandidates && !knownCandidates.has(key)) {
      rejected.push({
        path: `candidate_updates[${idx}]`,
        code: 'unknown_candidate',
        message: `Unknown candidate ${candidate_type}:${normalized_value}`
      });
      continue;
    }
    candidate_updates.push({
      ...u,
      candidate_type,
      normalized_value,
      evidence_block_ids: filterBlocks(u.evidence_block_ids, `candidate_updates[${idx}].evidence_block_ids`),
      ioc_id: undefined,
      matched_ioc_id: undefined
    });
  }

  const entityNames = new Set(
    entities.map((e) => String(e.name || '').trim().toLowerCase()).filter(Boolean)
  );
  const relationships = [];
  for (let idx = 0; idx < (data.relationships || []).length; idx += 1) {
    const r = data.relationships[idx];
    const path = `relationships[${idx}]`;
    let ok = true;
    if (r.subject_kind === 'entity') {
      if (!entityNames.has(String(r.subject_ref || '').trim().toLowerCase())) {
        rejected.push({ path: `${path}.subject_ref`, code: 'unknown_entity_ref', message: 'Subject entity not in entities[]' });
        ok = false;
      }
    } else if (r.subject_kind === 'candidate' && knownCandidates) {
      const ref = String(r.subject_ref || '');
      const hit =
        knownCandidates.has(ref) ||
        [...knownCandidates].some((k) => k.endsWith(`\0${ref}`) || k === ref.replace(':', '\0'));
      if (!hit && !idMap.has(ref)) {
        rejected.push({ path: `${path}.subject_ref`, code: 'unknown_candidate_ref', message: 'Subject candidate not in input set' });
        ok = false;
      }
    }
    if (r.object_kind === 'entity') {
      if (!entityNames.has(String(r.object_ref || '').trim().toLowerCase())) {
        rejected.push({ path: `${path}.object_ref`, code: 'unknown_entity_ref', message: 'Object entity not in entities[]' });
        ok = false;
      }
    } else if (r.object_kind === 'candidate' && knownCandidates) {
      const ref = String(r.object_ref || '');
      const hit =
        knownCandidates.has(ref) ||
        [...knownCandidates].some((k) => k.endsWith(`\0${ref}`) || k === ref.replace(':', '\0'));
      if (!hit && !idMap.has(ref)) {
        rejected.push({ path: `${path}.object_ref`, code: 'unknown_candidate_ref', message: 'Object candidate not in input set' });
        ok = false;
      }
    }
    if (!ok) continue;
    relationships.push({
      ...r,
      evidence_block_ids: filterBlocks(r.evidence_block_ids, `${path}.evidence_block_ids`)
    });
  }

  const value = {
    ...data,
    entities,
    candidate_updates,
    relationships
  };

  const blob = JSON.stringify(value);
  if (/"ioc_id"\s*:|"matched_ioc_id"\s*:|"database_id"\s*:/.test(blob)) {
    return {
      ok: false,
      code: 'ai_output_reference_error',
      error: 'AI response contained forbidden local database id fields',
      details: [{ path: '(payload)', message: 'Forbidden local id field' }],
      rejected
    };
  }

  return {
    ok: true,
    value,
    rejected,
    code: rejected.length ? 'ai_output_partial' : null
  };
}

/**
 * Full legacy entry used by older tests — normalize + structure + references.
 * @param {unknown} raw
 * @param {{ knownBlockIds?: Set<string>, knownCandidateKeys?: Set<string>, candidateIdMap?: Map<string, any> }} [ctx]
 */
export function validateAiAnalysis(raw, ctx = {}) {
  const normalized = normalizeAiAnalysisInput(raw, ctx);
  if (!normalized.ok) {
    return {
      ok: false,
      code: 'ai_output_schema_error',
      error: normalized.error,
      details: [{ path: '(root)', message: normalized.error }]
    };
  }
  const structural = validateAiStructure(normalized.value);
  if (!structural.ok) return structural;
  const semantic = validateAiReferences(structural.value, ctx);
  if (!semantic.ok) return semantic;
  return {
    ok: true,
    value: semantic.value,
    rejected: semantic.rejected || [],
    normalization_notes: normalized.notes,
    schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
  };
}

/**
 * Parse provider text through extract → normalize → validate.
 * @param {string} text
 * @param {object} [ctx]
 */
export function processAiResponseText(text, ctx = {}) {
  const extracted = extractJsonObject(text);
  if (!extracted.ok) {
    return {
      ok: false,
      code: extracted.code,
      error: extracted.error,
      details: [{ path: '(raw)', message: extracted.error }],
      raw_sample: capRawOutputSample(text),
      schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
    };
  }
  const result = validateAiAnalysis(extracted.value, ctx);
  return {
    ...result,
    extract_method: extracted.method,
    raw_sample: result.ok ? undefined : capRawOutputSample(text),
    schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
  };
}
