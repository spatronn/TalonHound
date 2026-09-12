/**
 * Strict Zod schema for AI semantic analysis output.
 * AI must never invent local IOC database IDs.
 */

import { z } from 'zod';

const conf = z.number().min(0).max(1).nullable().optional();

const assessmentEnum = z.enum(['malicious', 'suspicious', 'context_only', 'unknown', 'invalid']);
const roleEnum = z.enum([
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
const entityTypeEnum = z.enum([
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
  /** Must reference a deterministic candidate normalized value+type, not a DB id */
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

/**
 * @param {unknown} raw
 * @param {{ knownBlockIds?: Set<string>, knownCandidateKeys?: Set<string> }} [ctx]
 */
export function validateAiAnalysis(raw, ctx = {}) {
  const parsed = aiAnalysisSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      error: 'AI response failed schema validation',
      details: parsed.error.issues.slice(0, 20).map((i) => ({
        path: i.path.join('.'),
        message: i.message
      }))
    };
  }

  const data = parsed.data;
  const knownBlocks = ctx.knownBlockIds || null;
  const knownCandidates = ctx.knownCandidateKeys || null;

  const filterBlocks = (ids) => {
    if (!knownBlocks) return ids || [];
    return (ids || []).filter((id) => knownBlocks.has(id));
  };

  data.entities = (data.entities || []).map((e) => ({
    ...e,
    evidence_block_ids: filterBlocks(e.evidence_block_ids)
  }));

  data.candidate_updates = (data.candidate_updates || [])
    .filter((u) => {
      if (!knownCandidates) return true;
      return knownCandidates.has(`${u.candidate_type}\0${u.normalized_value}`);
    })
    .map((u) => ({
      ...u,
      evidence_block_ids: filterBlocks(u.evidence_block_ids),
      // Strip any accidental ioc_id fields AI might invent
      ioc_id: undefined,
      matched_ioc_id: undefined
    }));

  data.relationships = (data.relationships || []).map((r) => ({
    ...r,
    evidence_block_ids: filterBlocks(r.evidence_block_ids)
  }));

  // Never allow local DB ids in AI payload
  const forbidden = JSON.stringify(data).match(/"ioc_id"\s*:|"matched_ioc_id"\s*:/);
  if (forbidden) {
    return { ok: false, error: 'AI response contained forbidden local IOC id fields' };
  }

  return { ok: true, value: data };
}
