/**
 * Standalone independent Qwen IOC discovery (shadow / offline only).
 * Never writes to the DB. Concurrency must remain 1 at the caller.
 */

import { groundProposals } from './grounding.js';

export const SHADOW_QWEN_DISCOVERY_VERSION = 'tl-shadow-qwen-discovery-v1';

const SYSTEM_PROMPT = `You are an independent threat-intelligence IOC extraction engine.
Extract publisher-asserted Indicators of Compromise from the provided document blocks.

Return ONLY valid JSON:
{
  "proposals": [
    {
      "type": "ipv4|ipv6|domain|url|md5|sha1|sha256",
      "value": "exact observable after removing common defanging",
      "block_id": "source block id",
      "evidence_excerpt": "verbatim excerpt from that block",
      "section_heading": "nearest heading if known else empty",
      "assertion_category": "formal_ioc_appendix|network_infrastructure_list|hash_inventory|c2_list|narrative_assertion|contextual_reference|technical_example|uncertain",
      "assessment": "malicious|benign|contextual|uncertain",
      "confidence": 0.0,
      "confidence_explanation": "short reason"
    }
  ],
  "ambiguous": [],
  "notes": ""
}

Rules:
- Only propose values that appear in the provided blocks (after normal defanging).
- Do not invent values.
- Prefer formal IOC lists / hash inventories / C2 lists over contextual mentions.
- Incomplete placeholders go in ambiguous, not proposals.
- Filenames, registry keys, CVEs are out of scope for proposals.
- Do not use any prior candidate list; discover from the blocks only.`;

function flattenBlocksForPrompt(blocks) {
  return (blocks || []).map((b) => ({
    id: b.id,
    type: b.type,
    text: String(b.text || '').slice(0, 1200),
    ...(b.table
      ? {
          table: {
            headers: b.table.headers || b.table.header || null,
            rows: (b.table.rows || []).slice(0, 40).map((r) => (Array.isArray(r) ? r.map((c) => String(c).slice(0, 200)) : r))
          }
        }
      : {})
  }));
}

/**
 * Split blocks into prompt-sized chunks while preserving order.
 * @param {object[]} blocks
 * @param {number} maxChars
 */
export function chunkBlocks(blocks, maxChars = 14000) {
  const chunks = [];
  let cur = [];
  let size = 0;
  for (const b of blocks || []) {
    const add = JSON.stringify({ id: b.id, type: b.type, text: b.text }).length + 8;
    if (cur.length && size + add > maxChars) {
      chunks.push(cur);
      cur = [];
      size = 0;
    }
    cur.push(b);
    size += add;
  }
  if (cur.length) chunks.push(cur);
  return chunks;
}

async function ollamaPs(baseUrl) {
  const res = await fetch(`${baseUrl.replace(/\/$/, '')}/api/ps`, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`ollama_ps_http_${res.status}`);
  return res.json();
}

async function ollamaChat(baseUrl, payload, timeoutMs) {
  const res = await fetch(`${baseUrl.replace(/\/$/, '')}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`ollama_chat_http_${res.status}:${body.slice(0, 200)}`);
  }
  return res.json();
}

function parseMessageContent(content) {
  const raw = String(content || '').trim();
  if (!raw) return { proposals: [], ambiguous: [], notes: 'empty' };
  try {
    return JSON.parse(raw);
  } catch {
    const start = raw.indexOf('{');
    const end = raw.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(raw.slice(start, end + 1));
      } catch {
        /* fall through */
      }
    }
    return { proposals: [], ambiguous: [], notes: 'parse_error', raw: raw.slice(0, 500) };
  }
}

/**
 * @param {object} opts
 * @param {object[]} opts.blocks
 * @param {string} [opts.baseUrl]
 * @param {string} [opts.model]
 * @param {boolean} [opts.abortIfBusy]
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.maxChunks]
 * @param {boolean} [opts.fullDocument]
 */
export async function runIndependentQwenDiscovery(opts = {}) {
  const baseUrl = opts.baseUrl || process.env.SHADOW_OLLAMA_BASE_URL || 'http://192.168.1.8:11434';
  const model = opts.model || process.env.SHADOW_OLLAMA_MODEL || 'qwen3.5:9b';
  const timeoutMs = opts.timeoutMs || 900000;
  const maxChunks = opts.maxChunks ?? 8;
  const blocks = opts.blocks || [];

  if (opts.abortIfBusy !== false) {
    const ps = await ollamaPs(baseUrl);
    if (Array.isArray(ps?.models) && ps.models.length > 0) {
      return {
        ok: false,
        aborted: true,
        reason: 'ollama_busy',
        ps,
        proposals: [],
        grounded: { accepted: [], rejected: [] },
        timing: []
      };
    }
  }

  const chunks = chunkBlocks(blocks, opts.chunkChars || 14000).slice(0, maxChunks);
  const allProposals = [];
  const timing = [];
  const rawChunks = [];

  for (let i = 0; i < chunks.length; i += 1) {
    const chunkBlocksLocal = chunks[i];
    const user = {
      task: 'Extract publisher-asserted IOCs from these canonical document blocks.',
      chunk_index: i + 1,
      chunk_total: chunks.length,
      blocks: flattenBlocksForPrompt(chunkBlocksLocal)
    };
    const t0 = Date.now();
    let data;
    try {
      data = await ollamaChat(
        baseUrl,
        {
          model,
          stream: false,
          format: 'json',
          think: false,
          keep_alive: '2m',
          options: { temperature: 0.1, num_predict: 8192 },
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: JSON.stringify(user) }
          ]
        },
        timeoutMs
      );
    } catch (err) {
      timing.push({ chunk: i + 1, ok: false, error: String(err?.message || err), ms: Date.now() - t0 });
      if (opts.failOpen) continue;
      return {
        ok: false,
        aborted: false,
        reason: 'ollama_error',
        error: String(err?.message || err),
        proposals: allProposals,
        grounded: groundProposals(allProposals, blocks),
        timing,
        rawChunks
      };
    }
    const elapsed = Date.now() - t0;
    const parsed = parseMessageContent(data?.message?.content);
    rawChunks.push({
      chunk: i + 1,
      elapsed_ms: elapsed,
      prompt_eval_count: data?.prompt_eval_count,
      eval_count: data?.eval_count,
      done_reason: data?.done_reason,
      parsed_notes: parsed?.notes || null
    });
    timing.push({
      chunk: i + 1,
      ok: true,
      ms: elapsed,
      prompt_eval_count: data?.prompt_eval_count ?? null,
      eval_count: data?.eval_count ?? null,
      block_count: chunkBlocksLocal.length
    });
    for (const p of parsed.proposals || []) allProposals.push(p);
  }

  // Dedup by type+value (last wins metadata).
  const byKey = new Map();
  for (const p of allProposals) {
    const key = `${String(p.type || '').toLowerCase()}:${String(p.value || '').trim().toLowerCase()}`;
    byKey.set(key, p);
  }
  const deduped = [...byKey.values()];
  const grounded = groundProposals(deduped, blocks);

  // Indicator-oriented set: malicious / uncertain hash_inventory & formal lists.
  const indicatorProposals = grounded.accepted.filter((p) => {
    const a = String(p.assessment || '').toLowerCase();
    const cat = String(p.assertion_category || '').toLowerCase();
    if (a === 'benign' || a === 'contextual') return false;
    if (cat === 'contextual_reference' || cat === 'technical_example') return false;
    return true;
  });

  return {
    ok: true,
    version: SHADOW_QWEN_DISCOVERY_VERSION,
    model,
    baseUrl,
    chunk_count: chunks.length,
    proposals_raw: deduped,
    grounded,
    indicator_proposals: indicatorProposals,
    timing,
    rawChunks
  };
}
