/**
 * STIX 2.0 / 2.1 JSON bundle parsing for linked IOC Sources.
 * Only Indicator objects produce authoritative Indicators by default.
 * Observed-data / standalone SCOs are Context Only unless tied by an
 * Indicator relationship with clear assertion semantics.
 */

import { normalizeObservable } from '../../../observable-normalization.js';
import { createStixEvidence, EVIDENCE_MEMBERSHIP, summarizeEvidence } from './evidence.js';
import { parseStixPattern } from './pattern.js';

const SCO_TYPES = new Set([
  'ipv4-addr',
  'ipv6-addr',
  'domain-name',
  'url',
  'file',
  'email-addr',
  'network-traffic'
]);

const META_TYPES = new Set([
  'identity',
  'marking-definition',
  'relationship',
  'sighting',
  'malware',
  'tool',
  'infrastructure',
  'campaign',
  'attack-pattern',
  'course-of-action',
  'intrusion-set',
  'threat-actor',
  'vulnerability',
  'location',
  'report',
  'note',
  'opinion',
  'grouping',
  'bundle'
]);

/**
 * @param {string} text
 * @returns {{ ok: boolean, code?: string, message?: string, bundle?: object, spec_version?: string|null }}
 */
export function parseStixJsonDocument(text) {
  let data;
  try {
    data = JSON.parse(String(text || ''));
  } catch {
    return { ok: false, code: 'invalid_json', message: 'Content is not valid JSON' };
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { ok: false, code: 'invalid_stix_json', message: 'STIX JSON root must be an object' };
  }

  // Bundle or bare object list / single SDO.
  if (data.type === 'bundle' || Array.isArray(data.objects)) {
    const objects = Array.isArray(data.objects) ? data.objects : [];
    const spec = data.spec_version || inferSpecVersion(objects);
    if (spec && !String(spec).startsWith('2.')) {
      return {
        ok: false,
        code: 'unsupported_stix_version',
        message: `Unsupported STIX spec_version ${spec}`
      };
    }
    return { ok: true, bundle: { type: 'bundle', id: data.id || null, spec_version: spec, objects }, spec_version: spec };
  }

  if (typeof data.type === 'string' && data.type !== 'bundle') {
    // Single SDO/SCO — treat as one-object bundle.
    const spec = data.spec_version || '2.1';
    if (!String(spec).startsWith('2.')) {
      return { ok: false, code: 'unsupported_stix_version', message: `Unsupported STIX spec_version ${spec}` };
    }
    return {
      ok: true,
      bundle: { type: 'bundle', id: null, spec_version: spec, objects: [data] },
      spec_version: spec
    };
  }

  return { ok: false, code: 'not_stix_json', message: 'JSON is not a STIX 2.x bundle or object' };
}

function inferSpecVersion(objects) {
  for (const o of objects || []) {
    if (o?.spec_version) return o.spec_version;
  }
  return objects?.length ? '2.1' : null;
}

function scoValue(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const t = String(obj.type || '').toLowerCase();
  if (t === 'ipv4-addr' || t === 'ipv6-addr' || t === 'domain-name' || t === 'url' || t === 'email-addr') {
    const v = obj.value;
    if (v == null || v === '') return null;
    const type =
      t === 'ipv4-addr' ? 'ip' :
        t === 'ipv6-addr' ? 'ipv6' :
          t === 'domain-name' ? 'domain' :
            t === 'url' ? 'url' : 'email';
    return { type, value: String(v) };
  }
  if (t === 'file' && obj.hashes && typeof obj.hashes === 'object') {
    const hashes = obj.hashes;
    const out = [];
    for (const [k, v] of Object.entries(hashes)) {
      const key = String(k).toLowerCase().replace(/'/g, '');
      const type = key === 'md5' ? 'md5' : key === 'sha-1' || key === 'sha1' ? 'sha1' : key === 'sha-256' || key === 'sha256' ? 'sha256' : null;
      if (type && v) out.push({ type, value: String(v) });
    }
    return out.length ? out : null;
  }
  return null;
}

function isExpired(validUntil, now = new Date()) {
  if (!validUntil) return false;
  const t = Date.parse(String(validUntil));
  return Number.isFinite(t) && t < now.getTime();
}

/**
 * @param {object} bundle
 * @param {{ now?: Date }} [opts]
 */
export function extractStixJsonEvidence(bundle, opts = {}) {
  const now = opts.now || new Date();
  const objects = Array.isArray(bundle?.objects) ? bundle.objects : [];
  const byId = new Map();
  for (const o of objects) {
    if (o?.id) byId.set(o.id, o);
  }

  /** @type {import('./evidence.js').StixEvidence[]} */
  const evidence = [];
  const pushNorm = (partial) => {
    const type = partial.observable_type;
    let raw = partial.original_value;
    if (type === 'url' && raw && !/^[a-z][a-z0-9+.-]*:\/\//i.test(String(raw))) {
      raw = `http://${String(raw).trim()}`;
    }
    if (type === 'email') {
      const normalized = String(raw || '').trim().toLowerCase();
      if (!normalized) return;
      evidence.push(
        createStixEvidence({
          ...partial,
          original_value: String(partial.original_value).trim(),
          normalized_value: normalized,
          source_format: 'stix_json'
        })
      );
      return;
    }
    const norm = normalizeObservable(type === 'ipv6' ? 'ip' : type, raw) || String(raw || '').trim();
    if (!norm) return;
    evidence.push(
      createStixEvidence({
        ...partial,
        original_value: String(partial.original_value).trim(),
        normalized_value:
          type === 'domain' || type === 'url'
            ? norm
            : type === 'md5' || type === 'sha1' || type === 'sha256'
              ? norm.toLowerCase()
              : norm,
        source_format: 'stix_json'
      })
    );
  };

  // Relationships: indicator → malware/infrastructure (metadata only for now).
  const indicatesTargets = new Map();
  for (const o of objects) {
    if (o?.type !== 'relationship') continue;
    if (String(o.relationship_type || '').toLowerCase() === 'indicates' && o.source_ref && o.target_ref) {
      const list = indicatesTargets.get(o.source_ref) || [];
      list.push(o.target_ref);
      indicatesTargets.set(o.source_ref, list);
    }
  }

  for (const o of objects) {
    if (!o || typeof o !== 'object') continue;
    const type = String(o.type || '').toLowerCase();

    if (type === 'indicator') {
      const id = o.id || null;
      const revoked = o.revoked === true;
      const expired = isExpired(o.valid_until, now);
      const patternType = String(o.pattern_type || 'stix').toLowerCase();
      if (patternType !== 'stix') {
        pushNorm({
          original_value: String(o.pattern || o.name || id || 'indicator'),
          normalized_value: String(o.pattern || o.name || id || 'indicator'),
          observable_type: 'unknown',
          stix_object_id: id,
          evidence_locator: id,
          object_semantics: 'indicator',
          evidence_role: 'unsupported_pattern',
          membership: EVIDENCE_MEMBERSHIP.UNSUPPORTED,
          diagnostics: ['unsupported_pattern'],
          meta: { pattern_type: patternType, revoked, expired }
        });
        continue;
      }

      const parsed = parseStixPattern(o.pattern);
      if (!parsed.ok) {
        pushNorm({
          original_value: String(o.pattern || ''),
          normalized_value: String(o.pattern || ''),
          observable_type: 'unknown',
          stix_object_id: id,
          evidence_locator: id,
          object_semantics: 'indicator',
          evidence_role: 'unsupported_pattern',
          membership: EVIDENCE_MEMBERSHIP.UNSUPPORTED,
          diagnostics: [parsed.code || 'unsupported_pattern'],
          meta: { message: parsed.message, revoked, expired, valid_until: o.valid_until || null }
        });
        continue;
      }

      let membership = EVIDENCE_MEMBERSHIP.INDICATOR;
      const diagnostics = [];
      if (revoked) {
        membership = EVIDENCE_MEMBERSHIP.EXCLUDED;
        diagnostics.push('revoked_indicator');
      } else if (expired) {
        membership = EVIDENCE_MEMBERSHIP.CONTEXT_ONLY;
        diagnostics.push('expired_validity');
      }

      for (const obs of parsed.observables) {
        let rowMembership = membership;
        const rowDiagnostics = [...diagnostics];
        let role = rowMembership === EVIDENCE_MEMBERSHIP.INDICATOR ? 'malicious_infrastructure' : 'stix_indicator_inactive';
        // email-addr is a publisher Indicator assertion but not a TalonHound
        // network IOC type — never promote the mailbox domain as a domain IOC.
        if (obs.type === 'email') {
          rowMembership = EVIDENCE_MEMBERSHIP.CONTEXT_ONLY;
          rowDiagnostics.push('email_not_network_ioc_type', 'email_address_not_domain');
          role = 'malicious_email';
        }
        pushNorm({
          original_value: obs.value,
          normalized_value: obs.value,
          observable_type: obs.type,
          stix_object_id: id,
          evidence_locator: id,
          object_semantics: 'indicator',
          evidence_role: role,
          membership: rowMembership,
          diagnostics: rowDiagnostics,
          meta: {
            pattern_compound: parsed.compound,
            confidence: o.confidence ?? null,
            labels: o.labels || null,
            created: o.created || null,
            modified: o.modified || null,
            valid_from: o.valid_from || null,
            valid_until: o.valid_until || null,
            revoked,
            indicates: indicatesTargets.get(id) || [],
            external_references: o.external_references || null
          }
        });
      }
      continue;
    }

    if (type === 'observed-data') {
      // Never authoritative by presence alone.
      const id = o.id || null;
      const embedded = o.objects && typeof o.objects === 'object' && !Array.isArray(o.objects) ? o.objects : null;
      if (embedded) {
        for (const [k, sco] of Object.entries(embedded)) {
          const vals = scoValue(sco);
          const list = Array.isArray(vals) ? vals : vals ? [vals] : [];
          for (const v of list) {
            pushNorm({
              original_value: v.value,
              normalized_value: v.value,
              observable_type: v.type,
              stix_object_id: id,
              evidence_locator: `${id}#${k}`,
              object_semantics: 'observed_data',
              evidence_role: 'observed_context',
              membership: EVIDENCE_MEMBERSHIP.CONTEXT_ONLY,
              diagnostics: ['observed_data_not_indicator'],
              meta: { sco_type: sco?.type || null }
            });
          }
        }
      }
      for (const ref of o.object_refs || []) {
        const sco = byId.get(ref);
        const vals = scoValue(sco);
        const list = Array.isArray(vals) ? vals : vals ? [vals] : [];
        for (const v of list) {
          pushNorm({
            original_value: v.value,
            normalized_value: v.value,
            observable_type: v.type,
            stix_object_id: id,
            evidence_locator: `${id}->${ref}`,
            object_semantics: 'observed_data',
            evidence_role: 'observed_context',
            membership: EVIDENCE_MEMBERSHIP.CONTEXT_ONLY,
            diagnostics: ['observed_data_not_indicator'],
            meta: { object_ref: ref }
          });
        }
      }
      continue;
    }

    if (SCO_TYPES.has(type)) {
      // Standalone SCOs in a bundle are inventory, not Indicators.
      const vals = scoValue(o);
      const list = Array.isArray(vals) ? vals : vals ? [vals] : [];
      for (const v of list) {
        pushNorm({
          original_value: v.value,
          normalized_value: v.value,
          observable_type: v.type,
          stix_object_id: o.id || null,
          evidence_locator: o.id || null,
          object_semantics: 'sco',
          evidence_role: 'standalone_sco',
          membership: EVIDENCE_MEMBERSHIP.CONTEXT_ONLY,
          diagnostics: ['standalone_sco_not_indicator'],
          meta: { sco_type: type }
        });
      }
      continue;
    }

    if (META_TYPES.has(type) || type === 'relationship' || type === 'sighting') {
      // Intentionally ignored for IOC membership.
      continue;
    }
  }

  return {
    evidence,
    summary: summarizeEvidence(evidence),
    object_counts: countTypes(objects)
  };
}

function countTypes(objects) {
  const c = {};
  for (const o of objects || []) {
    const t = String(o?.type || 'unknown');
    c[t] = (c[t] || 0) + 1;
  }
  return c;
}

/**
 * Detect whether JSON text looks like STIX 2.x (before full parse).
 * @param {string} text
 */
export function looksLikeStixJson(text) {
  const s = String(text || '').trim().slice(0, 4000);
  if (!s.startsWith('{') && !s.startsWith('[')) return false;
  if (/"type"\s*:\s*"bundle"/i.test(s)) return true;
  if (/"type"\s*:\s*"indicator"/i.test(s) && /"pattern"\s*:/i.test(s)) return true;
  if (/"spec_version"\s*:\s*"2\./i.test(s)) return true;
  return false;
}

/**
 * Full parse entry: text → evidence + ok/error.
 * @param {string} text
 * @param {{ now?: Date }} [opts]
 */
export function parseStixJsonSource(text, opts = {}) {
  const doc = parseStixJsonDocument(text);
  if (!doc.ok) return { ...doc, evidence: [], candidates: [], summary: summarizeEvidence([]) };
  const extracted = extractStixJsonEvidence(doc.bundle, opts);
  return {
    ok: true,
    format: 'stix_json',
    spec_version: doc.spec_version,
    evidence: extracted.evidence,
    summary: extracted.summary,
    object_counts: extracted.object_counts,
    bundle_id: doc.bundle?.id || null
  };
}
