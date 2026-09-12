/**
 * Deterministic normalization of AI semantic output before strict Zod validation.
 * Only clear aliases — never invent ambiguous semantics.
 */

const ENTITY_TYPE_ALIASES = Object.freeze({
  threat_actor: 'threat_actor',
  'threat-actor': 'threat_actor',
  'threat actor': 'threat_actor',
  threatactor: 'threat_actor',
  actor: 'threat_actor',
  malware: 'malware',
  campaign: 'campaign',
  tool: 'tool',
  vulnerability: 'vulnerability',
  vuln: 'vulnerability',
  cve: 'vulnerability',
  infrastructure: 'infrastructure',
  infra: 'infrastructure',
  organization: 'organization',
  organisation: 'organization',
  org: 'organization',
  attack_pattern: 'attack_pattern',
  'attack-pattern': 'attack_pattern',
  'attack pattern': 'attack_pattern',
  technique: 'attack_pattern'
});

const ASSESSMENT_ALIASES = Object.freeze({
  malicious: 'malicious',
  malware: 'malicious',
  bad: 'malicious',
  suspicious: 'suspicious',
  suspect: 'suspicious',
  context_only: 'context_only',
  'context-only': 'context_only',
  'context only': 'context_only',
  contextual: 'context_only',
  unknown: 'unknown',
  unclear: 'unknown',
  invalid: 'invalid',
  false_positive: 'invalid',
  'false-positive': 'invalid',
  'false positive': 'invalid'
});

const ROLE_ALIASES = Object.freeze({
  command_and_control: 'command_and_control',
  'command-and-control': 'command_and_control',
  'command and control': 'command_and_control',
  c2: 'command_and_control',
  c_and_c: 'command_and_control',
  redirector: 'redirector',
  redirect: 'redirector',
  payload_hosting: 'payload_hosting',
  'payload-hosting': 'payload_hosting',
  'payload hosting': 'payload_hosting',
  malware_download: 'malware_download',
  'malware-download': 'malware_download',
  'malware download': 'malware_download',
  phishing: 'phishing',
  tracking: 'tracking',
  tracker: 'tracking',
  malicious_infrastructure: 'malicious_infrastructure',
  'malicious-infrastructure': 'malicious_infrastructure',
  'malicious infrastructure': 'malicious_infrastructure',
  delivery: 'delivery',
  legitimate_service: 'legitimate_service',
  'legitimate-service': 'legitimate_service',
  'legitimate service': 'legitimate_service',
  hosting_platform: 'hosting_platform',
  'hosting-platform': 'hosting_platform',
  'hosting platform': 'hosting_platform',
  victim: 'victim',
  reference: 'reference',
  security_tool: 'security_tool',
  'security-tool': 'security_tool',
  'security tool': 'security_tool',
  unknown: 'unknown'
});

/** Documented categorical confidence → numeric mapping (0–1). */
export const CATEGORICAL_CONFIDENCE = Object.freeze({
  high: 0.85,
  strong: 0.85,
  medium: 0.55,
  moderate: 0.55,
  med: 0.55,
  low: 0.25,
  weak: 0.25,
  none: 0,
  unknown: null
});

function keyify(v) {
  return String(v || '')
    .trim()
    .toLowerCase()
    .replace(/[_]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/ /g, '_');
}

function aliasLookup(map, raw) {
  if (raw == null || raw === '') return null;
  const s = String(raw).trim();
  const direct = map[s.toLowerCase()];
  if (direct) return direct;
  const spaced = s.toLowerCase().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (map[spaced]) return map[spaced];
  const underscored = spaced.replace(/ /g, '_');
  if (map[underscored]) return map[underscored];
  const compact = spaced.replace(/ /g, '');
  if (map[compact]) return map[compact];
  return null;
}

/**
 * Normalize confidence to number in [0,1] or null.
 * Supports: 0.93, 93, "93%", "high" (documented categorical map).
 * @param {unknown} raw
 * @returns {{ value: number|null, ok: boolean, reason?: string }}
 */
export function normalizeConfidence(raw) {
  if (raw == null || raw === '') return { value: null, ok: true };
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    if (raw >= 0 && raw <= 1) return { value: raw, ok: true };
    if (raw > 1 && raw <= 100) return { value: raw / 100, ok: true };
    return { value: null, ok: false, reason: 'confidence_out_of_range' };
  }
  const s = String(raw).trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(CATEGORICAL_CONFIDENCE, s)) {
    return { value: CATEGORICAL_CONFIDENCE[s], ok: true };
  }
  const pct = s.match(/^(\d+(?:\.\d+)?)\s*%$/);
  if (pct) {
    const n = Number(pct[1]);
    if (n >= 0 && n <= 100) return { value: n / 100, ok: true };
  }
  const num = Number(s);
  if (Number.isFinite(num)) return normalizeConfidence(num);
  return { value: null, ok: false, reason: 'unrecognized_confidence' };
}

function normalizeLanguage(raw) {
  if (raw == null || raw === '') return null;
  const s = String(raw).trim().toLowerCase();
  if (s.startsWith('en')) return 'en';
  return s.slice(0, 16);
}

function normalizeTlpHint(raw) {
  if (raw == null || raw === '') return null;
  const s = String(raw).trim().toUpperCase().replace(/^TLP[:\s-]*/i, '');
  if (['RED', 'AMBER+STRICT', 'AMBER', 'GREEN', 'CLEAR', 'WHITE'].includes(s)) {
    return s === 'WHITE' ? 'CLEAR' : s;
  }
  if (s === 'GREEN' || s === 'AMBER' || s === 'RED' || s === 'CLEAR') return s;
  const lower = String(raw).trim().toLowerCase();
  if (lower === 'green') return 'GREEN';
  if (lower === 'amber') return 'AMBER';
  if (lower === 'red') return 'RED';
  if (lower === 'clear' || lower === 'white') return 'CLEAR';
  return String(raw).trim().slice(0, 32);
}

/**
 * @param {object} raw
 * @param {{ candidateIdMap?: Map<string, { candidate_type: string, normalized_value: string }> }} [ctx]
 */
export function normalizeAiAnalysisInput(raw, ctx = {}) {
  const notes = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, error: 'AI payload is not an object', notes };
  }

  const out = { ...raw };
  if (out.entities == null) {
    out.entities = [];
    notes.push('defaulted_missing_entities');
  }
  if (out.candidate_updates == null) {
    out.candidate_updates = [];
    notes.push('defaulted_missing_candidate_updates');
  }
  if (out.relationships == null) {
    out.relationships = [];
    notes.push('defaulted_missing_relationships');
  }

  const conf = normalizeConfidence(out.confidence);
  if (!conf.ok) notes.push(`confidence:${conf.reason}`);
  else if (typeof raw.confidence === 'string') notes.push('normalized_confidence_categorical_or_string');
  out.confidence = conf.value;

  out.language = normalizeLanguage(out.language);
  out.tlp = normalizeTlpHint(out.tlp);
  if (out.summary == null) out.summary = '';
  out.summary = String(out.summary);

  out.entities = (Array.isArray(out.entities) ? out.entities : []).map((e) => {
    if (!e || typeof e !== 'object') return e;
    const entity_type =
      aliasLookup(ENTITY_TYPE_ALIASES, e.entity_type) ||
      aliasLookup(ENTITY_TYPE_ALIASES, e.type) ||
      e.entity_type;
    if (entity_type !== e.entity_type) notes.push(`entity_type_alias:${e.entity_type}->${entity_type}`);
    const c = normalizeConfidence(e.confidence);
    return {
      ...e,
      entity_type,
      confidence: c.ok ? c.value : e.confidence,
      aliases: Array.isArray(e.aliases) ? e.aliases : [],
      evidence_block_ids: Array.isArray(e.evidence_block_ids)
        ? e.evidence_block_ids
        : e.evidence_block
          ? [e.evidence_block]
          : []
    };
  });

  const idMap = ctx.candidateIdMap || new Map();
  out.candidate_updates = (Array.isArray(out.candidate_updates) ? out.candidate_updates : []).map((u) => {
    if (!u || typeof u !== 'object') return u;
    let candidate_type = u.candidate_type;
    let normalized_value = u.normalized_value;
    const cid = u.candidate_id != null ? String(u.candidate_id) : null;
    if (cid && idMap.has(cid)) {
      const ref = idMap.get(cid);
      candidate_type = ref.candidate_type;
      normalized_value = ref.normalized_value;
      notes.push(`resolved_candidate_id:${cid}`);
    }
    const assessment = aliasLookup(ASSESSMENT_ALIASES, u.assessment) || u.assessment;
    const role = aliasLookup(ROLE_ALIASES, u.role) || u.role || 'unknown';
    if (assessment !== u.assessment) notes.push(`assessment_alias:${u.assessment}->${assessment}`);
    if (u.role && role !== u.role) notes.push(`role_alias:${u.role}->${role}`);
    const c = normalizeConfidence(u.confidence);
    return {
      ...u,
      candidate_id: cid,
      candidate_type,
      normalized_value,
      assessment,
      role,
      confidence: c.ok ? c.value : u.confidence,
      evidence_block_ids: Array.isArray(u.evidence_block_ids)
        ? u.evidence_block_ids
        : u.evidence_block
          ? [u.evidence_block]
          : []
    };
  });

  out.relationships = (Array.isArray(out.relationships) ? out.relationships : []).map((r) => {
    if (!r || typeof r !== 'object') return r;
    const c = normalizeConfidence(r.confidence);
    const role = r.role != null ? aliasLookup(ROLE_ALIASES, r.role) || r.role : r.role;
    return {
      ...r,
      role,
      confidence: c.ok ? c.value : r.confidence,
      evidence_block_ids: Array.isArray(r.evidence_block_ids)
        ? r.evidence_block_ids
        : r.evidence_block
          ? [r.evidence_block]
          : []
    };
  });

  // Strip forbidden authoritative local IDs if present on objects
  const stripIds = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    delete obj.ioc_id;
    delete obj.matched_ioc_id;
    delete obj.database_id;
    delete obj.user_id;
    delete obj.report_id;
  };
  stripIds(out);
  for (const e of out.entities) stripIds(e);
  for (const u of out.candidate_updates) stripIds(u);
  for (const r of out.relationships) stripIds(r);

  return { ok: true, value: out, notes };
}

export { ENTITY_TYPE_ALIASES, ASSESSMENT_ALIASES, ROLE_ALIASES, aliasLookup, keyify };
