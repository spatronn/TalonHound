/**
 * Source-span verification for experimental Qwen IOC proposals.
 * Rejects proposals that cannot be grounded in the supplied document blocks.
 */

import { normalizeCandidateValue } from '../../candidateValue.js';
import { refangTextForExtraction } from '../../defang.js';

const TYPE_ALIASES = {
  ipv4: 'ip',
  ipv6: 'ip',
  ip: 'ip',
  domain: 'domain',
  url: 'url',
  md5: 'md5',
  sha1: 'sha1',
  sha256: 'sha256'
};

function defangAll(s) {
  return refangTextForExtraction(String(s || ''))
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{\.\}/g, '.')
    .replace(/hxxps?/gi, (m) => (m.toLowerCase().startsWith('hxxps') ? 'https' : 'http'));
}

/**
 * @param {{ type: string, value: string, block_id?: string, evidence_excerpt?: string }} proposal
 * @param {object[]} blocks
 */
export function groundProposal(proposal, blocks) {
  const rawType = String(proposal?.type || '').toLowerCase();
  const type = TYPE_ALIASES[rawType] || rawType;
  const value = String(proposal?.value || '').trim();
  if (!type || !value) {
    return { ok: false, reason: 'missing_type_or_value' };
  }
  if (!TYPE_ALIASES[rawType] && !['ip', 'domain', 'url', 'md5', 'sha1', 'sha256'].includes(type)) {
    return { ok: false, reason: 'unsupported_type', type };
  }

  const norm = normalizeCandidateValue(value, type);
  if (!norm.ok) {
    return { ok: false, reason: 'normalize_failed', detail: norm.reason || null };
  }
  if (norm.candidateType && norm.candidateType !== type && !(type === 'ip' && norm.candidateType === 'ip')) {
    // Allow ipv4→ip alias only.
    if (!(rawType === 'ipv4' || rawType === 'ipv6')) {
      return { ok: false, reason: 'type_mismatch', expected: type, got: norm.candidateType };
    }
  }

  const byId = new Map((blocks || []).map((b) => [b.id, b]));
  const needle = defangAll(norm.normalizedValue).toLowerCase();
  const excerpt = defangAll(proposal.evidence_excerpt || '').toLowerCase();
  const block = proposal.block_id ? byId.get(proposal.block_id) : null;
  const blockText = defangAll(block?.text || '').toLowerCase();

  let groundedIn = null;
  if (block && blockText.includes(needle)) groundedIn = 'block';
  else if (excerpt && excerpt.includes(needle) && block) {
    // Excerpt claims the value but block text does not — reject.
    return { ok: false, reason: 'excerpt_not_in_block', block_id: proposal.block_id };
  } else {
    // Fall back: search all blocks for the exact normalized value.
    const hit = (blocks || []).find((b) => defangAll(b.text || '').toLowerCase().includes(needle));
    if (!hit) return { ok: false, reason: 'value_not_in_document' };
    groundedIn = 'document_search';
    proposal = { ...proposal, block_id: hit.id };
  }

  if (proposal.evidence_excerpt && excerpt && !excerpt.includes(needle) && groundedIn === 'block') {
    // Soft: excerpt missing value but block has it — keep with note.
    return {
      ok: true,
      warning: 'evidence_excerpt_missing_value',
      type: norm.candidateType || type,
      value: norm.normalizedValue,
      block_id: proposal.block_id,
      grounded_in: groundedIn
    };
  }

  return {
    ok: true,
    type: norm.candidateType || type,
    value: norm.normalizedValue,
    block_id: proposal.block_id,
    grounded_in: groundedIn
  };
}

/**
 * @param {object[]} proposals
 * @param {object[]} blocks
 */
export function groundProposals(proposals, blocks) {
  const accepted = [];
  const rejected = [];
  for (const p of proposals || []) {
    const g = groundProposal(p, blocks);
    if (g.ok) {
      accepted.push({
        ...p,
        type: g.type,
        value: g.value,
        block_id: g.block_id || p.block_id,
        grounded_in: g.grounded_in,
        grounding_warning: g.warning || null
      });
    } else {
      rejected.push({ proposal: p, reason: g.reason, detail: g });
    }
  }
  return { accepted, rejected };
}
