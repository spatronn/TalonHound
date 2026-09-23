/**
 * Deterministic validation for Threat Library relationships.
 *
 * The model (or a bundle) proposes `subject --type--> object`; this policy
 * decides whether it is persisted. A relationship is kept only when:
 *  - its type is a known relationship type and the subject/object kinds are a
 *    compatible combination for it (e.g. `malware uses organization` is not);
 *  - (AI analysis) the source report STATES it (the model's block citations are
 *    only a hint — in production most cite the wrong block): a body-prose
 *    sentence names both endpoints (name or alias) with a predicate cue for the
 *    relationship type between them in the right direction, or a short section
 *    headed by the subject states the predicate on the object. Co-occurrence,
 *    table rows and document chrome (headers, footers, source lines) are never
 *    evidence;
 *  - (AI analysis) when an endpoint is the report's publisher, only a verbatim
 *    quote counts — the publisher is named throughout its own report (coverage,
 *    detections, disclaimers), so co-mention in a block is not evidence.
 *
 * Invalid relationships are rejected, never persisted with a lowered confidence:
 * persisted rows reach MCP, THIB/STIX export and Threat Context unfiltered.
 */

import { NEGATIVE_ZONES, annotateDocumentZones } from './documentZones.js';

/** Endpoint kinds: entity types plus indicator kinds for candidate endpoints. */
const ACTOR = 'threat_actor';
const MALWARE = 'malware';
const CAMPAIGN = 'campaign';
const TOOL = 'tool';
const VULNERABILITY = 'vulnerability';
const INFRASTRUCTURE = 'infrastructure';
const ORGANIZATION = 'organization';
const ATTACK_PATTERN = 'attack_pattern';
const NETWORK_INDICATOR = 'network_indicator';
const FILE_INDICATOR = 'file_indicator';

const NETWORK_CANDIDATE_TYPES = new Set(['ip', 'ipv6', 'cidr', 'domain', 'url']);
const FILE_CANDIDATE_TYPES = new Set(['md5', 'sha1', 'sha256']);

const ACTORS = [ACTOR, CAMPAIGN];
const CAPABILITIES = [MALWARE, TOOL];
const INDICATORS = [NETWORK_INDICATOR, FILE_INDICATOR];

/**
 * Allowed endpoint kinds per relationship type (STIX 2.1 SROs plus the
 * TalonHound types already produced in production: delivered_by, operates,
 * overlaps_with, is_detected_as). A type not listed here is rejected.
 */
const RELATIONSHIP_RULES = Object.freeze({
  uses: {
    subjects: [...ACTORS, MALWARE],
    objects: [MALWARE, TOOL, ATTACK_PATTERN, INFRASTRUCTURE, ...INDICATORS]
  },
  targets: {
    subjects: [...ACTORS, ...CAPABILITIES, ATTACK_PATTERN],
    objects: [ORGANIZATION, VULNERABILITY, INFRASTRUCTURE, NETWORK_INDICATOR]
  },
  exploits: {
    subjects: [...ACTORS, ...CAPABILITIES],
    objects: [VULNERABILITY]
  },
  communicates_with: {
    subjects: [...CAPABILITIES, FILE_INDICATOR],
    objects: [INFRASTRUCTURE, NETWORK_INDICATOR]
  },
  delivered_by: {
    subjects: [...CAPABILITIES, FILE_INDICATOR],
    objects: [...CAPABILITIES, INFRASTRUCTURE, ...INDICATORS]
  },
  delivers: {
    subjects: [...CAPABILITIES, INFRASTRUCTURE, ...INDICATORS],
    objects: [...CAPABILITIES, FILE_INDICATOR]
  },
  downloads: {
    subjects: [...CAPABILITIES, FILE_INDICATOR],
    objects: [...CAPABILITIES, FILE_INDICATOR]
  },
  drops: {
    subjects: [...CAPABILITIES, FILE_INDICATOR],
    objects: [...CAPABILITIES, FILE_INDICATOR]
  },
  hosts: {
    subjects: [INFRASTRUCTURE, NETWORK_INDICATOR],
    objects: [...CAPABILITIES, FILE_INDICATOR]
  },
  variant_of: {
    subjects: [...CAPABILITIES, FILE_INDICATOR],
    objects: [...CAPABILITIES]
  },
  is_detected_as: {
    subjects: [...CAPABILITIES, FILE_INDICATOR],
    objects: [...CAPABILITIES]
  },
  attributed_to: {
    subjects: [...ACTORS, ...CAPABILITIES, INFRASTRUCTURE, ...INDICATORS],
    objects: [ACTOR, CAMPAIGN]
  },
  operates: {
    subjects: [ACTOR],
    objects: [CAMPAIGN, INFRASTRUCTURE, NETWORK_INDICATOR]
  },
  impersonates: {
    subjects: [...ACTORS, ...CAPABILITIES, INFRASTRUCTURE, NETWORK_INDICATOR],
    objects: [ORGANIZATION]
  },
  overlaps_with: {
    subjects: [...ACTORS, ...CAPABILITIES, INFRASTRUCTURE],
    objects: [...ACTORS, ...CAPABILITIES, INFRASTRUCTURE]
  }
});

export const RELATIONSHIP_TYPES = Object.freeze(Object.keys(RELATIONSHIP_RULES));

export const RELATIONSHIP_REJECTIONS = Object.freeze({
  UNKNOWN_TYPE: 'unknown_relationship_type',
  INCOMPATIBLE_TYPES: 'incompatible_endpoint_types',
  NON_MALICIOUS_INDICATOR: 'non_malicious_indicator_endpoint',
  NO_EVIDENCE: 'no_evidence',
  PUBLISHER_WITHOUT_QUOTE: 'publisher_without_explicit_quote'
});

/**
 * `communicates-with`, `Communicates With` → `communicates_with`.
 * @param {string} type
 */
export function normalizeRelationshipType(type) {
  return String(type || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

/**
 * @param {{ kind: 'entity'|'candidate', entity_type?: string, candidate_type?: string }} endpoint
 * @returns {string|null}
 */
export function endpointKind(endpoint) {
  if (!endpoint) return null;
  if (endpoint.kind === 'entity') return endpoint.entity_type ? String(endpoint.entity_type) : null;
  const t = String(endpoint.candidate_type || '').toLowerCase();
  if (NETWORK_CANDIDATE_TYPES.has(t)) return NETWORK_INDICATOR;
  if (FILE_CANDIDATE_TYPES.has(t)) return FILE_INDICATOR;
  if (t === 'cve') return VULNERABILITY;
  if (t === 'attack_technique') return ATTACK_PATTERN;
  return null;
}

/**
 * @param {string} subjectKind
 * @param {string} relationshipType normalized
 * @param {string} objectKind
 */
export function isRelationshipTypeCompatible(subjectKind, relationshipType, objectKind) {
  const rule = RELATIONSHIP_RULES[relationshipType];
  if (!rule) return false;
  return rule.subjects.includes(subjectKind) && rule.objects.includes(objectKind);
}

/** Lowercase, refang, collapse whitespace — the haystack/needle form for mention checks. */
function normalizeMentionText(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\bhxxp/g, 'http')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Whole-term mentions: an ASCII-alphanumeric name edge must not run into a
 * letter/digit ("Vidar" ≠ "Vidarr"). Modifier letters are not word characters
 * (PDFs use U+02EE "ˮ" as a closing quote).
 */
const WORD_CHAR = /[\p{Lu}\p{Ll}\p{Lt}\p{Lo}\p{N}]/u;

/**
 * Publisher name tokens from the report source: host labels minus generic
 * prefixes / suffixes ("www.zscaler.com" → ["zscaler"],
 * "unit42.paloaltonetworks.com" → ["unit42", "paloaltonetworks"]).
 * @param {{ source_url?: string|null, source_name?: string|null }} report
 * @param {{ meta?: { source_host?: string|null } }|null} [document]
 */
export function publisherTokens(report, document = null) {
  const hosts = [];
  if (document?.meta?.source_host) hosts.push(document.meta.source_host);
  try {
    if (report?.source_url) hosts.push(new URL(report.source_url).hostname);
  } catch {
    /* not a URL */
  }
  const sourceName = String(report?.source_name || '').trim();
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(sourceName) && !/\.(?:pdf|html?|txt|json)$/i.test(sourceName)) {
    hosts.push(sourceName);
  }
  const generic = new Set(['www', 'blog', 'blogs', 'research', 'labs', 'com', 'co', 'gov', 'org', 'net', 'ac', 'edu', 'io']);
  const tokens = new Set();
  for (const host of hosts) {
    const labels = String(host).toLowerCase().split('.').filter(Boolean);
    labels.slice(0, -1).forEach((l) => {
      if (!generic.has(l) && l.length >= 3) tokens.add(l);
    });
  }
  return [...tokens];
}

/**
 * An organization entity is the publisher when its compact name (or alias)
 * matches a publisher host token ("Zscaler", "Zscaler ThreatLabz" ↔ "zscaler").
 * @param {{ kind: string, entity_type?: string, names?: string[] }} endpoint
 * @param {string[]} tokens
 */
export function isPublisherEndpoint(endpoint, tokens) {
  if (!endpoint || endpoint.kind !== 'entity' || endpoint.entity_type !== ORGANIZATION) return false;
  if (!tokens?.length) return false;
  return (endpoint.names || []).some((n) => {
    const lower = String(n || '').toLowerCase();
    const compact = lower.replace(/[^\p{L}\p{N}]/gu, '');
    // "UK National Cyber Security Centre (NCSC)" ↔ "ncsc": a whole word of the name.
    const words = lower.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
    return (
      compact.length >= 3 &&
      tokens.some((t) => compact === t || (t.length >= 4 && compact.startsWith(t)) || words.includes(t))
    );
  });
}

/**
 * Predicate cues per relationship type. Co-occurrence never proves a predicate:
 * a sentence must name both endpoints with a cue for THIS relationship between
 * them, in the right direction — `forward` for "subject … cue … object"
 * ("InvisibleFerret uses …"), `reverse` for "object … cue … subject" ("… used by
 * the Lazarus group"). `symmetric` types need the cue between them in either order.
 * English cues only: a relationship stated only in another language is rejected.
 */
const PREDICATE_CUES = Object.freeze({
  uses: {
    forward: /\b(?:us(?:e|es|ed|ing)|leverag(?:e|es|ed|ing)|employ(?:s|ed|ing)?|deploy(?:s|ed|ing)?|rel(?:y|ies|ied|ying) on|includ(?:e|es|ed|ing)|incorporat(?:e|es|ed|ing)|ha(?:s|ve) an?|equipped with)\b/,
    reverse: /\b(?:used|leveraged|employed|deployed) by\b/
  },
  targets: {
    forward: /\b(?:target(?:s|ed|ing)?|attack(?:s|ed|ing)?|compromis(?:e|es|ed|ing))\b/,
    reverse: /\b(?:targeted|attacked|compromised) by\b/
  },
  exploits: { forward: /\bexploit(?:s|ed|ing)?\b/, reverse: /\bexploited by\b/ },
  communicates_with: {
    forward: /\b(?:communicat\w*|beacon\w*|connect\w*|contact\w*|calls? (?:back|home)|reach(?:es)? out)\b/,
    reverse: null
  },
  delivered_by: {
    forward: /\b(?:deliver(?:ed|y)|distributed|dropped|served|hosted|downloaded|spread)\b/,
    reverse: /\b(?:deliver(?:s|ing)?|distribut(?:es|ing)|drop(?:s|ping)?|serv(?:es|ing)|host(?:s|ing)|download(?:s|ing)?)\b/
  },
  delivers: {
    forward: /\b(?:deliver\w*|download\w*|drop\w*|distribut\w*|serv(?:e|es|ing)|fetch\w*|retriev\w*)\b/,
    reverse: /\b(?:delivered|downloaded|dropped|distributed|served|fetched|retrieved) by\b/
  },
  downloads: {
    forward: /\b(?:download\w*|fetch\w*|retriev\w*|pull(?:s|ed)?)\b/,
    reverse: /\b(?:downloaded|fetched|retrieved) by\b/
  },
  drops: { forward: /\b(?:drop\w*|writ(?:e|es|ing)|extract\w*|install\w*)\b/, reverse: /\b(?:dropped|written|installed) by\b/ },
  hosts: { forward: /\b(?:host\w*|serv(?:e|es|ing)|stag\w*)\b/, reverse: /\b(?:hosted|served|staged) (?:on|by|at)\b/ },
  variant_of: {
    forward: /\b(?:variant|version|fork|derivative|successor|evolution|based on|derived from|rebrand\w*)\b/,
    reverse: null
  },
  // "products detect WinPot … as Backdoor.Win32.ATMPot.gen": "as" between, a detection verb before.
  is_detected_as: { forward: /\bas\b/, reverse: null, lead: /\b(?:detect\w*|identif\w*|flag\w*|classif\w*)\b/ },
  attributed_to: {
    forward: /\b(?:attribut\w*|linked to|tied to|associated with|operated by|run by)\b/,
    reverse: /\b(?:behind|responsible for|operat(?:es|ed))\b/
  },
  operates: {
    forward: /\b(?:operat\w*|run(?:s|ning)?|control\w*|conduct\w*|manag\w*|administer\w*)\b/,
    reverse: /\b(?:operated|run|controlled|conducted|managed) by\b/
  },
  impersonates: {
    forward: /\b(?:impersonat\w*|masquerad\w*|pos(?:e|es|ing) as|spoof\w*|mimic\w*)\b/,
    reverse: /\bimpersonated by\b/
  },
  overlaps_with: { symmetric: /\b(?:overlap\w*|intersect\w*|link\w*|connect\w*|associat\w*|shar(?:e|es|ed|ing)|tied)\b/ }
});

/** Sections are topic context only while short. */
const SECTION_CONTEXT_MAX_UNITS = 8;

/** Character spans of every whole-term mention of any name. */
function mentionSpans(haystack, names) {
  const spans = [];
  for (const raw of names || []) {
    const term = normalizeMentionText(raw);
    if (!term || term.length < 2) continue;
    const checkStart = /^[a-z0-9]/.test(term);
    const checkEnd = /[a-z0-9]$/.test(term);
    let from = 0;
    for (;;) {
      const idx = haystack.indexOf(term, from);
      if (idx < 0) break;
      const before = idx > 0 ? haystack[idx - 1] : '';
      const after = haystack[idx + term.length] || '';
      if ((!checkStart || !before || !WORD_CHAR.test(before)) && (!checkEnd || !after || !WORD_CHAR.test(after))) {
        spans.push({ start: idx, end: idx + term.length });
      }
      from = idx + 1;
    }
  }
  return spans;
}

/** Sentences (a period must be followed by whitespace, so "Backdoor.Win32.ATMPot.gen" stays whole). */
function splitSentences(text) {
  return String(text || '')
    .split(/(?<=[.!?。！？;])\s+|\s+[●•▪]\s+/)
    .map((x) => normalizeMentionText(x))
    .filter(Boolean);
}

/** "overlap between X and Y": a symmetric cue ahead of both endpoints joined by "and". */
const SYMMETRIC_PAIR_LEAD = /(?:between|among)\s*$/;
const SYMMETRIC_PAIR_JOIN = /^\s*(?:and|&)\s*$/;

/** One sentence states `subject --type--> object`: both named, cue between them, right direction. */
function sentenceStates(sentence, subject, object, relationshipType) {
  const cues = PREDICATE_CUES[relationshipType];
  if (!cues) return false;
  const subj = mentionSpans(sentence, subject.names);
  const obj = mentionSpans(sentence, object.names);
  if (!subj.length || !obj.length) return false;
  for (const s of subj) {
    for (const o of obj) {
      const between = s.end <= o.start ? sentence.slice(s.end, o.start) : o.end <= s.start ? sentence.slice(o.end, s.start) : '';
      if (cues.symmetric) {
        if (cues.symmetric.test(between)) return true;
        const lead = sentence.slice(0, Math.min(s.start, o.start));
        if (SYMMETRIC_PAIR_JOIN.test(between) && SYMMETRIC_PAIR_LEAD.test(lead) && cues.symmetric.test(lead)) return true;
        continue;
      }
      const leadOk = !cues.lead || cues.lead.test(sentence.slice(0, Math.min(s.start, o.start)));
      if (s.end <= o.start && leadOk && cues.forward?.test(between)) return true;
      if (o.end <= s.start && cues.reverse?.test(between)) return true;
    }
  }
  return false;
}

/**
 * Section topic: the heading names the subject, a sentence of the section names
 * the object with the cue before it ("InvisibleFerret" heading, "The keylogger
 * uses … pyWinhook"). Symmetric types need the cue anywhere in that sentence.
 */
function sentenceStatesUnderTopic(sentence, object, relationshipType) {
  const cues = PREDICATE_CUES[relationshipType];
  if (!cues) return false;
  const obj = mentionSpans(sentence, object.names);
  if (!obj.length) return false;
  if (cues.symmetric) return cues.symmetric.test(sentence);
  return obj.some((o) => cues.forward?.test(sentence.slice(0, o.start)));
}

/**
 * Evidence-context index over a canonical document. Only body prose is
 * evidence: blocks the existing zone annotation (documentZones.js) puts in a
 * negative zone — header_footer, source_metadata, navigation, vendor_about,
 * reference_section — are dropped, and tables are dropped (a table row
 * enumerates, it does not state a predicate). A section runs from a heading to
 * the next heading.
 * @param {{ blocks?: { id: string, type?: string, text?: string }[], meta?: object }|null} document
 * @param {{ sourceUrl?: string|null }} [opts]
 */
export function buildEvidenceIndex(document, opts = {}) {
  let blocks = document?.blocks || [];
  try {
    let sourceHost = document?.meta?.source_host || null;
    if (!sourceHost && opts.sourceUrl) sourceHost = new URL(opts.sourceUrl).hostname;
    blocks = annotateDocumentZones({ ...document, blocks }, { sourceUrl: opts.sourceUrl || null, sourceHost }).blocks;
  } catch {
    /* unannotated: every block counts as body */
  }
  const units = [];
  const sections = [];
  let section = { heading: null, units: [] };
  sections.push(section);
  for (const b of blocks) {
    if (NEGATIVE_ZONES.has(String(b.zone || '')) || b.layout === 'page_edge') continue;
    const text = normalizeMentionText(b.text);
    if (!text) continue;
    if (b.type === 'heading') {
      section = { heading: text, units: [] };
      sections.push(section);
      continue;
    }
    if (b.type === 'table') continue;
    const unit = { blockId: b.id ? String(b.id) : null, text, sentences: splitSentences(b.text) };
    units.push(unit);
    section.units.push(unit);
  }
  return {
    units,
    fullText: units.map((u) => u.text).join(' \n '),
    sections: sections.filter((sec) => sec.heading && sec.units.length > 0 && sec.units.length <= SECTION_CONTEXT_MAX_UNITS)
  };
}

/**
 * @typedef {{ kind: 'entity'|'candidate', entity_type?: string, candidate_type?: string, assessment?: string|null, names: string[] }} RelationshipEndpoint
 */

/**
 * Does the report STATE the relationship? In order: a verbatim quote of body
 * prose that states it; a body sentence naming both endpoints with the
 * predicate cue between them; a short section headed by the subject whose
 * sentence states the predicate on the object. A publisher endpoint needs the
 * quote.
 *
 * @param {{ relationship_type?: string, evidence_text?: string|null, evidence_block_ids?: string[] }} rel
 * @param {RelationshipEndpoint} subject
 * @param {RelationshipEndpoint} object
 * @param {{ evidenceIndex?: ReturnType<typeof buildEvidenceIndex>, publisherTokens?: string[] }} [opts]
 * @returns {{ ok: true, block_id: string|null, basis: 'quote'|'sentence'|'section' } | { ok: false, reason: string }}
 */
export function checkRelationshipEvidence(rel, subject, object, opts = {}) {
  const index = opts.evidenceIndex || { units: [], fullText: '', sections: [] };
  const type = normalizeRelationshipType(rel?.relationship_type);
  const cited = new Set((rel?.evidence_block_ids || []).map(String));
  const prefer = (list) => list.find((u) => cited.has(u.blockId)) || list[0];

  const quote = normalizeMentionText(rel?.evidence_text);
  const quoteOk =
    quote.length >= 8 &&
    index.fullText.includes(quote) &&
    splitSentences(quote).some((sentence) => sentenceStates(sentence, subject, object, type));
  const quoteUnit = quoteOk ? prefer(index.units.filter((u) => u.text.includes(quote))) : null;

  const publisherInvolved =
    isPublisherEndpoint(subject, opts.publisherTokens) || isPublisherEndpoint(object, opts.publisherTokens);
  if (publisherInvolved) {
    return quoteOk
      ? { ok: true, block_id: quoteUnit?.blockId || null, basis: 'quote' }
      : { ok: false, reason: RELATIONSHIP_REJECTIONS.PUBLISHER_WITHOUT_QUOTE };
  }
  if (quoteOk) return { ok: true, block_id: quoteUnit?.blockId || null, basis: 'quote' };

  // Anchor on the model's citation when it states the relationship, else on the
  // shortest (most specific) stating sentence.
  let best = null;
  for (const u of index.units) {
    for (const sentence of u.sentences) {
      if (!sentenceStates(sentence, subject, object, type)) continue;
      const rank = [cited.has(u.blockId) ? 0 : 1, sentence.length];
      if (!best || rank[0] < best.rank[0] || (rank[0] === best.rank[0] && rank[1] < best.rank[1])) best = { u, rank };
    }
  }
  if (best) return { ok: true, block_id: best.u.blockId, basis: 'sentence' };

  for (const sec of index.sections) {
    if (!mentionSpans(sec.heading, subject.names).length) continue;
    const unit = sec.units.find((u) => u.sentences.some((sentence) => sentenceStatesUnderTopic(sentence, object, type)));
    if (unit) return { ok: true, block_id: unit.blockId, basis: 'section' };
  }
  return { ok: false, reason: RELATIONSHIP_REJECTIONS.NO_EVIDENCE };
}

/**
 * Validate one proposed relationship: type policy, then (AI analysis) evidence.
 *
 * @param {{ relationship_type: string, evidence_text?: string|null, evidence_block_ids?: string[] }} rel
 * @param {RelationshipEndpoint} subject
 * @param {RelationshipEndpoint} object
 * @param {{ requireEvidence?: boolean, evidenceIndex?: ReturnType<typeof buildEvidenceIndex>, publisherTokens?: string[] }} [opts]
 * @returns {{ ok: true, relationship_type: string, block_id: string|null } | { ok: false, reason: string, relationship_type: string }}
 */
export function validateRelationship(rel, subject, object, opts = {}) {
  const relationshipType = normalizeRelationshipType(rel?.relationship_type);
  if (!RELATIONSHIP_RULES[relationshipType]) {
    return { ok: false, reason: RELATIONSHIP_REJECTIONS.UNKNOWN_TYPE, relationship_type: relationshipType };
  }
  if (!isRelationshipTypeCompatible(endpointKind(subject), relationshipType, endpointKind(object))) {
    return { ok: false, reason: RELATIONSHIP_REJECTIONS.INCOMPATIBLE_TYPES, relationship_type: relationshipType };
  }
  // The candidate evidence policy already decided an indicator is context only
  // (a forum, a vendor site, a reference): a relationship cannot turn it into
  // adversary infrastructure. `targets` is exempt — a target need not be malicious.
  if (relationshipType !== 'targets' && [subject, object].some(isNonMaliciousIndicator)) {
    return { ok: false, reason: RELATIONSHIP_REJECTIONS.NON_MALICIOUS_INDICATOR, relationship_type: relationshipType };
  }
  if (opts.requireEvidence !== true) {
    return { ok: true, relationship_type: relationshipType, block_id: null };
  }
  const evidence = checkRelationshipEvidence(rel, subject, object, opts);
  return evidence.ok
    ? { ok: true, relationship_type: relationshipType, block_id: evidence.block_id, basis: evidence.basis }
    : { ok: false, reason: evidence.reason, relationship_type: relationshipType };
}

function isNonMaliciousIndicator(endpoint) {
  return endpoint?.kind === 'candidate' && ['context_only', 'invalid'].includes(String(endpoint.assessment || ''));
}
