/**
 * Chunked Threat Library AI analysis with merge + checkpoint hooks (semantic-v5).
 *
 * Work split:
 *  - deterministic layer (candidateExtraction / evidencePolicy) decides explicit
 *    IOC assertions, context-only references and non-IOC artifacts;
 *  - the model sees body text chunks (header/footer/navigation stripped), the
 *    resolved indicator list as compact context, and classifies only the
 *    `ai_needed` candidates whose occurrences fall in the chunk;
 *  - every provider call is timed; completed chunks are checkpointed and reused
 *    on retry; the final synthesis is optional and budget-bounded.
 */

import {
  buildSystemPrompt,
  buildRepairPrompt,
  buildChunkPrompt,
  buildSynthesisPrompt,
  formatCandidateEvidenceLine
} from './prompts.js';
import { processAiResponseText, validateAiAnalysis } from './schema.js';
import { callAiProvider } from './client.js';
import { assertAiReady } from './settings.js';
import {
  AI_FAILURE_CODES,
  aiFailure,
  resolveAiTimeoutPolicy,
  resolveRecoveryReserveMs,
  resolveMinPrimaryCallMs,
  resolveMinRepairMs
} from './timeouts.js';
import {
  THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
  buildProviderJsonSchema,
  candidateUpdatesMaxItemsForChunk
} from './contract.js';
import { capRawOutputSample } from './extract.js';
import { chunkCanonicalDocument, flattenCanonicalText, collectBlockIds } from '../canonicalDocument.js';
import { annotateDocumentZones } from '../documentZones.js';

export const SYNTHESIS_CHUNK_KEY = 'synthesis';

/** Zones that never reach the model as body text (pure layout / provenance noise). */
const NON_SEMANTIC_ZONES = new Set(['header_footer', 'navigation', 'source_metadata', 'vendor_about']);

/** Resolved-indicator context caps per chunk (keeps prompts bounded on large reports). */
const MAX_RESOLVED_EXPLICIT_PER_CHUNK = 80;
const MAX_RESOLVED_LOCAL_PER_CHUNK = 40;

/**
 * Blocks worth sending to the model: strip repeated header/footer, navigation,
 * printed source provenance and vendor boilerplate. Reference rows stay out of
 * the body text too — they reach the model as resolved context lines instead.
 * @param {object} document
 */
export function selectSemanticBlocks(document) {
  const annotated = document?.meta?.zones_annotated
    ? document
    : annotateDocumentZones(document, {
        sourceUrl: document?.meta?.source_url || null,
        sourceHost: document?.meta?.source_host || null
      });
  const kept = [];
  let dropped = 0;
  for (const b of annotated.blocks || []) {
    const zone = b.zone || 'report_body';
    if (NON_SEMANTIC_ZONES.has(zone)) {
      dropped += 1;
      continue;
    }
    if (zone === 'reference_section' && (b.type === 'list_item' || b.layout === 'observable_row')) {
      dropped += 1;
      continue;
    }
    if (!String(b.text || '').trim()) {
      dropped += 1;
      continue;
    }
    kept.push(b);
  }
  return { blocks: kept, dropped, total: (annotated.blocks || []).length };
}

/**
 * Build analysis chunks covering the semantic document.
 * max_input_chars = max chars per chunk request (not "truncate and discard").
 * @param {object} document
 * @param {{ maxInputChars?: number, maxChunks?: number }} [opts]
 */
export function buildAnalysisChunks(document, opts = {}) {
  const maxInputChars = Math.max(Number(opts.maxInputChars || 120000), 4000);
  const maxCharsPerChunk = Math.min(14_000, Math.max(4000, maxInputChars - 8000));
  const maxChunks = Math.min(Math.max(Number(opts.maxChunks || 24), 1), 40);
  const semantic = opts.semanticOnly === false ? { blocks: document.blocks || [] } : selectSemanticBlocks(document);
  const blockChunks = chunkCanonicalDocument(
    { ...document, blocks: semantic.blocks.length ? semantic.blocks : document.blocks || [] },
    { maxCharsPerChunk, maxChunks }
  );
  return blockChunks.map((blocks, index) => ({
    chunk_index: index,
    chunk_key: `chunk-${String(index + 1).padStart(3, '0')}`,
    blocks,
    block_ids: blocks.map((b) => b.id).filter(Boolean),
    chars: blocks.reduce((n, b) => n + String(b.text || '').length, 0)
  }));
}

function candidateBlockIds(c) {
  const ids = new Set();
  if (c.block_id) ids.add(c.block_id);
  for (const o of c.occurrences || []) if (o.block_id) ids.add(o.block_id);
  return ids;
}

/**
 * Candidates whose occurrences fall in this chunk (unknown placement → first chunk only).
 */
export function candidatesForChunk(candidates, chunk, isFirst) {
  const idSet = new Set(chunk.block_ids || []);
  return (candidates || []).filter((c) => {
    const ids = candidateBlockIds(c);
    if (!ids.size) return isFirst;
    for (const id of ids) if (idSet.has(id)) return true;
    return false;
  });
}

/**
 * Partition candidates into what the model must classify vs. resolved context.
 * @param {object[]} candidates
 */
export function partitionCandidatesForAi(candidates) {
  const toClassify = [];
  const explicit = [];
  const resolvedOther = [];
  for (const c of candidates || []) {
    if (c.is_ioc === false && c.candidate_type !== 'cve' && c.candidate_type !== 'attack_technique') continue;
    if (c.ai_needed) {
      toClassify.push(c);
    } else if (c.assessment === 'malicious' || c.source_assertion === 'explicit_ioc' || c.source_assertion === 'explicit_c2' || c.source_assertion === 'explicit_operational_infrastructure') {
      explicit.push(c);
    } else {
      resolvedOther.push(c);
    }
  }
  return { toClassify, explicit, resolvedOther };
}

/**
 * Assign stable request-scoped candidate IDs for prompting/joining.
 * @param {object[]} candidates
 */
export function withCandidateIds(candidates) {
  return (candidates || []).map((c, idx) => ({
    ...c,
    candidate_id: c.candidate_id || `cand-${String(idx + 1).padStart(3, '0')}`
  }));
}

function buildCandidateIdMap(candidates) {
  const map = new Map();
  for (const c of candidates || []) {
    if (c.candidate_id) {
      map.set(String(c.candidate_id), {
        candidate_type: c.candidate_type,
        normalized_value: c.normalized_value
      });
    }
  }
  return map;
}

/**
 * Build the user prompt for one chunk from the evidence model.
 */
export function buildChunkRequest({ document, chunk, chunkIndex, chunkTotal, partition, sourceHost }) {
  const isFirst = chunkIndex === 0;
  const toClassify = candidatesForChunk(partition.toClassify, chunk, isFirst);
  const explicitAll = partition.explicit.slice(0, MAX_RESOLVED_EXPLICIT_PER_CHUNK);
  const localResolved = candidatesForChunk(partition.resolvedOther, chunk, false).slice(0, MAX_RESOLVED_LOCAL_PER_CHUNK);
  const resolved = [...explicitAll, ...localResolved];
  const blocksText = flattenCanonicalText(
    { title: document.title, language: document.language, blocks: chunk.blocks },
    { maxChars: 100_000 }
  );
  const user = buildChunkPrompt({
    documentTitle: document.title,
    language: document.language,
    chunkIndex,
    chunkTotal,
    blocksText,
    blockIds: chunk.block_ids,
    toClassify,
    resolved,
    sourceHost
  });
  return { user, toClassify, resolved, promptChars: user.length };
}

export function mergeAnalyses(parts, ctx) {
  const merged = {
    summary: '',
    report_type: null,
    language: null,
    tlp: null,
    confidence: null,
    entities: [],
    candidate_updates: [],
    relationships: []
  };

  const entityMap = new Map();
  const candidateMap = new Map();
  const summaries = [];

  for (const part of parts) {
    if (!part) continue;
    if (part.summary) summaries.push(String(part.summary).trim());
    if (!merged.report_type && part.report_type) merged.report_type = part.report_type;
    if (!merged.language && part.language) merged.language = part.language;
    if (!merged.tlp && part.tlp) merged.tlp = part.tlp;
    if (part.confidence != null) {
      merged.confidence =
        merged.confidence == null ? part.confidence : Math.max(merged.confidence, part.confidence);
    }
    for (const e of part.entities || []) {
      const key = `${e.entity_type}\0${String(e.name || '').trim().toLowerCase()}`;
      if (!entityMap.has(key)) entityMap.set(key, e);
    }
    for (const u of part.candidate_updates || []) {
      const key = `${u.candidate_type}\0${u.normalized_value}`;
      const prev = candidateMap.get(key);
      if (!prev || (Number(u.confidence) || 0) >= (Number(prev.confidence) || 0)) {
        candidateMap.set(key, u);
      }
    }
    for (const r of part.relationships || []) {
      merged.relationships.push(r);
    }
  }

  merged.entities = [...entityMap.values()];
  merged.candidate_updates = [...candidateMap.values()];
  merged.summary = summaries.filter(Boolean).join('\n\n').slice(0, 8000) || 'Analysis complete.';

  return validateAiAnalysis(merged, ctx);
}

function failChunk(code, message, extra = {}) {
  const err = aiFailure(code, message);
  err.details = extra.details || null;
  err.raw_sample = extra.raw_sample || null;
  err.rejected = extra.rejected || null;
  err.progress = extra.progress || null;
  err.schema_version = THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION;
  return err;
}

function timingEntry(kind, chunkKey, started, result, extra = {}) {
  const t = result?.timing || {};
  return {
    ...t,
    kind,
    chunk_key: chunkKey,
    ms: Date.now() - started,
    headers_ms: t.headers_ms ?? null,
    first_token_ms: t.first_token_ms ?? null,
    prompt_chars: t.prompt_chars ?? extra.prompt_chars ?? null,
    output_chars: t.output_chars ?? (result?.text ? result.text.length : null),
    thinking_chars: t.thinking_chars ?? null,
    ...extra
  };
}

/**
 * @param {object} settings
 * @param {{ document: object, candidates: object[] }} input
 * @param {object} [hooks]
 */
export async function analyzeThreatDocument(settings, input, hooks = {}) {
  assertAiReady(settings);
  const policy = resolveAiTimeoutPolicy(settings);
  const analysisStartedAt = hooks.analysisStartedAt || Date.now();
  const deadlineAt = analysisStartedAt + policy.total_analysis_timeout_ms;
  const reserveMs = resolveRecoveryReserveMs(policy);
  const minPrimaryMs = resolveMinPrimaryCallMs(policy);
  const minRepairMs = resolveMinRepairMs(policy);
  const primaryDeadlineAt = deadlineAt - reserveMs;
  const callProvider = hooks.callProvider || callAiProvider;
  const allCandidates = withCandidateIds(input.candidates || []);
  const knownBlockIds = collectBlockIds(input.document);
  const knownCandidateKeys = new Set(
    allCandidates.map((c) => `${c.candidate_type}\0${c.normalized_value}`)
  );
  const candidateIdMap = buildCandidateIdMap(allCandidates);
  const ctx = { knownBlockIds, knownCandidateKeys, candidateIdMap };
  const partition = partitionCandidatesForAi(allCandidates);
  const sourceHost = input.document.meta?.source_host || input.sourceHost || null;

  const chunks = buildAnalysisChunks(input.document, {
    maxInputChars: settings.max_input_chars || 120000
  });
  if (!chunks.length) {
    throw failChunk(AI_FAILURE_CODES.INVALID_AI_RESPONSE, 'No document chunks available for analysis');
  }

  const system = buildSystemPrompt();
  const formatSchemaFull = buildProviderJsonSchema();
  const partials = [];
  /** @type {object[]} */
  const timings = [];
  let aiCalls = 0;
  let completedFromCache = 0;
  let completedNow = 0;

  const progressBase = () => ({
    stage: 'analyzing',
    analysis_chunks_total: chunks.length,
    analysis_chunks_completed: partials.length,
    ai_calls: aiCalls,
    ai_needed_candidates: partition.toClassify.length,
    resolved_candidates: partition.explicit.length + partition.resolvedOther.length,
    schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
    timing: timings.slice(-24),
    last_provider_activity_at: new Date().toISOString()
  });

  const deadlineError = () =>
    failChunk(AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE, undefined, {
      progress: {
        analysis_chunks_total: chunks.length,
        analysis_chunks_completed: partials.length,
        analysis_chunks_remaining: chunks.length - partials.length,
        ai_calls: aiCalls,
        timing: timings,
        elapsed_ms: Date.now() - analysisStartedAt,
        total_analysis_timeout_ms: policy.total_analysis_timeout_ms,
        recovery_reserve_ms: reserveMs
      }
    });

  for (let i = 0; i < chunks.length; i += 1) {
    if (Date.now() > deadlineAt) throw deadlineError();
    if (hooks.shouldCancel && (await hooks.shouldCancel())) {
      throw failChunk(AI_FAILURE_CODES.JOB_CANCELLED);
    }

    const chunk = chunks[i];
    const cached = hooks.loadCompletedChunk ? await hooks.loadCompletedChunk(chunk.chunk_key) : null;
    const cachedBlockIds = Array.isArray(cached?.block_ids) ? cached.block_ids : null;
    const sameBlocks =
      !cachedBlockIds || (cachedBlockIds.length === chunk.block_ids.length && cachedBlockIds.every((id, idx) => id === chunk.block_ids[idx]));
    if (cached?.ok && cached.value && cached.schema_version === THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION && sameBlocks) {
      partials.push(cached.value);
      completedFromCache += 1;
      await hooks.onProgress?.({
        ...progressBase(),
        current_chunk: chunk.chunk_key,
        resumed: true
      });
      continue;
    }

    await hooks.onProgress?.({
      ...progressBase(),
      current_chunk: chunk.chunk_key,
      current_chunk_index: i + 1
    });

    const req = buildChunkRequest({
      document: input.document,
      chunk,
      chunkIndex: i,
      chunkTotal: chunks.length,
      partition,
      sourceHost
    });
    const chunkCands = [...req.toClassify, ...req.resolved];
    const formatSchema = buildProviderJsonSchema({
      maxCandidateUpdates: candidateUpdatesMaxItemsForChunk(req.toClassify.length, req.resolved.length)
    });

    const remainingBeforeCall = deadlineAt - Date.now();
    if (remainingBeforeCall < reserveMs + minPrimaryMs) {
      throw deadlineError();
    }

    let result;
    const started = Date.now();
    try {
      aiCalls += 1;
      result = await callProvider(
        settings,
        { system, user: req.user },
        {
          analysisStartedAt,
          callDeadlineAt: primaryDeadlineAt,
          signal: hooks.signal,
          keepAlive: i < chunks.length - 1 ? '15m' : '5m',
          formatSchema,
          onActivity: async () => {
            await hooks.onProgress?.({
              ...progressBase(),
              current_chunk: chunk.chunk_key,
              current_chunk_index: i + 1
            });
          }
        }
      );
    } catch (err) {
      timings.push(
        timingEntry('chunk', chunk.chunk_key, started, { timing: err?.timing }, {
          prompt_chars: req.promptChars,
          output_chars: err?.timing?.output_chars ?? 0,
          failed: err?.code || 'error',
          http_status: err?.http_status ?? null
        })
      );
      const providerProgress = {
        ...progressBase(),
        current_chunk: chunk.chunk_key,
        current_chunk_index: i + 1,
        analysis_chunks_remaining: chunks.length - partials.length,
        elapsed_ms: Date.now() - analysisStartedAt,
        total_analysis_timeout_ms: policy.total_analysis_timeout_ms,
        recovery_reserve_ms: reserveMs
      };
      if (err?.code === AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE) {
        const e = deadlineError();
        await hooks.markChunkFailed?.(chunk, e.code, e.message, {
          schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
          timing: timings.filter((t) => t.chunk_key === chunk.chunk_key)
        });
        throw e;
      }
      if (err && typeof err === 'object') {
        err.progress = err.progress || providerProgress;
        err.schema_version = err.schema_version || THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION;
        if (err.provider_error && !Array.isArray(err.details)) {
          err.details = [err.provider_error];
        }
      }
      await hooks.markChunkFailed?.(chunk, err?.code || 'ai_failed', err?.message || 'chunk failed', {
        schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
        validation_details: err?.details || [],
        timing: timings.filter((t) => t.chunk_key === chunk.chunk_key)
      });
      throw err;
    }
    timings.push(
      timingEntry('chunk', chunk.chunk_key, started, result, {
        prompt_chars: req.promptChars,
        to_classify: req.toClassify.length,
        resolved: req.resolved.length,
        block_count: chunk.block_ids.length
      })
    );
    const text = result.text;

    const chunkCtx = {
      knownBlockIds: new Set(chunk.block_ids),
      knownCandidateKeys,
      candidateIdMap: buildCandidateIdMap(chunkCands)
    };

    let processed = processAiResponseText(text, chunkCtx);
    let repairAttempted = false;
    if (!processed.ok) {
      // Repair may spend the protected reserve; it must not require lastCall*0.75.
      const remaining = deadlineAt - Date.now();
      if (remaining >= minRepairMs) {
        const repairStarted = Date.now();
        try {
          aiCalls += 1;
          repairAttempted = true;
          const repairUser = buildRepairPrompt({
            errors: processed.details || [{ message: processed.error }],
            previousOutputSample: processed.raw_sample || capRawOutputSample(text)
          });
          const repaired = await callProvider(
            settings,
            { system, user: repairUser },
            {
              analysisStartedAt,
              callDeadlineAt: deadlineAt,
              signal: hooks.signal,
              keepAlive: '5m',
              formatSchema: formatSchemaFull,
              onActivity: async () => {
                await hooks.onProgress?.({
                  ...progressBase(),
                  current_chunk: chunk.chunk_key,
                  current_chunk_index: i + 1,
                  repairing: true
                });
              }
            }
          );
          timings.push(timingEntry('repair', chunk.chunk_key, repairStarted, repaired, { prompt_chars: repairUser.length }));
          processed = processAiResponseText(repaired.text, chunkCtx);
        } catch (err) {
          timings.push(
            timingEntry('repair', chunk.chunk_key, repairStarted, { timing: err?.timing }, {
              failed: err?.code || 'error',
              output_chars: err?.timing?.output_chars ?? 0,
              http_status: err?.http_status ?? null
            })
          );
          if (err?.code === AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE) {
            const e = deadlineError();
            await hooks.markChunkFailed?.(chunk, e.code, e.message, {
              schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
              raw_output_sample: capRawOutputSample(text),
              timing: timings.filter((t) => t.chunk_key === chunk.chunk_key)
            });
            throw e;
          }
          if (err && typeof err === 'object') {
            err.progress = err.progress || {
              ...progressBase(),
              current_chunk: chunk.chunk_key,
              current_chunk_index: i + 1,
              analysis_chunks_remaining: chunks.length - partials.length,
              elapsed_ms: Date.now() - analysisStartedAt,
              total_analysis_timeout_ms: policy.total_analysis_timeout_ms,
              recovery_reserve_ms: reserveMs
            };
            err.schema_version = err.schema_version || THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION;
            if (err.provider_error && !Array.isArray(err.details)) {
              err.details = [err.provider_error];
            }
          }
          await hooks.markChunkFailed?.(chunk, err?.code || 'ai_failed', err?.message || 'repair failed', {
            schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
            validation_details: err?.details || [],
            raw_output_sample: capRawOutputSample(text),
            timing: timings.filter((t) => t.chunk_key === chunk.chunk_key)
          });
          throw err;
        }
      } else {
        processed.details = [
          ...(processed.details || []),
          { path: '(repair)', message: 'Repair skipped: insufficient remaining analysis budget' }
        ];
      }
    }

    if (!processed.ok) {
      const code = processed.code || AI_FAILURE_CODES.AI_VALIDATION;
      const err = failChunk(code, processed.error || 'Chunk validation failed', {
        details: processed.details,
        raw_sample: processed.raw_sample,
        rejected: processed.rejected,
        progress: {
          ...progressBase(),
          current_chunk: chunk.chunk_key,
          current_chunk_index: i + 1,
          analysis_chunks_remaining: chunks.length - partials.length,
          elapsed_ms: Date.now() - analysisStartedAt,
          total_analysis_timeout_ms: policy.total_analysis_timeout_ms,
          recovery_reserve_ms: reserveMs
        }
      });
      await hooks.markChunkFailed?.(chunk, err.code, err.message, {
        schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
        validation_details: processed.details || [],
        raw_output_sample: processed.raw_sample || capRawOutputSample(text),
        rejected_items: processed.rejected || [],
        timing: timings.filter((t) => t.chunk_key === chunk.chunk_key)
      });
      throw err;
    }

    partials.push(processed.value);
    completedNow += 1;
    await hooks.saveChunkResult?.(chunk, processed.value, {
      schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
      rejected_items: processed.rejected || [],
      normalization_notes: processed.normalization_notes || [],
      timing: timings.filter((t) => t.chunk_key === chunk.chunk_key)
    });
    await hooks.onProgress?.({
      ...progressBase(),
      current_chunk: chunk.chunk_key,
      current_chunk_index: i + 1,
      repair_attempted: repairAttempted
    });
  }

  let merged = mergeAnalyses(partials, ctx);
  if (!merged.ok) {
    throw failChunk(merged.code || AI_FAILURE_CODES.AI_VALIDATION, merged.error || 'Merged AI validation failed', {
      details: merged.details
    });
  }

  // Optional synthesis: only over validated partials, only with budget, never fatal.
  let synthesis = { attempted: false, used: false, skipped_reason: partials.length > 1 ? null : 'single_chunk' };
  if (partials.length > 1) {
    const cachedSynth = hooks.loadCompletedChunk ? await hooks.loadCompletedChunk(SYNTHESIS_CHUNK_KEY) : null;
    if (cachedSynth?.ok && cachedSynth.value && cachedSynth.schema_version === THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION) {
      const processed = validateAiAnalysis(cachedSynth.value, ctx);
      if (processed.ok) {
        merged = processed;
        synthesis = { attempted: false, used: true, skipped_reason: 'cached' };
      }
    }
    if (!synthesis.used) {
      const chunkMs = timings.filter((t) => t.kind === 'chunk' && !t.failed).map((t) => t.ms);
      const avgChunkMs = chunkMs.length ? chunkMs.reduce((a, b) => a + b, 0) / chunkMs.length : 0;
      const remaining = deadlineAt - Date.now();
      const needed = Math.max(60_000, avgChunkMs * 1.5);
      if (remaining <= needed) {
        synthesis = { attempted: false, used: false, skipped_reason: 'insufficient_budget' };
      } else if (hooks.shouldCancel && (await hooks.shouldCancel())) {
        throw failChunk(AI_FAILURE_CODES.JOB_CANCELLED);
      } else {
        const partialsText = partials
          .map((p, idx) =>
            `[synth-${idx + 1}] ${JSON.stringify({
              summary: p.summary,
              entities: (p.entities || []).map((e) => ({ type: e.entity_type, name: e.name })),
              candidate_updates: (p.candidate_updates || []).slice(0, 80),
              relationships: (p.relationships || []).slice(0, 40)
            }).slice(0, 3500)}`
          )
          .join('\n');
        const user = buildSynthesisPrompt({ documentTitle: input.document.title, partialsText });
        const started = Date.now();
        synthesis.attempted = true;
        try {
          aiCalls += 1;
          const result = await callProvider(
            settings,
            { system, user },
            {
              analysisStartedAt,
              callDeadlineAt: deadlineAt,
              signal: hooks.signal,
              keepAlive: '5m',
              formatSchema: formatSchemaFull,
              onActivity: async () => {
                await hooks.onProgress?.({ ...progressBase(), synthesizing: true });
              }
            }
          );
          timings.push(timingEntry('synthesis', SYNTHESIS_CHUNK_KEY, started, result, { prompt_chars: user.length }));
          const processed = processAiResponseText(result.text, ctx);
          if (processed.ok) {
            merged = processed;
            synthesis.used = true;
            await hooks.saveChunkResult?.(
              { chunk_index: chunks.length, chunk_key: SYNTHESIS_CHUNK_KEY, block_ids: [] },
              processed.value,
              { schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION, rejected_items: processed.rejected || [] }
            );
          } else {
            synthesis.skipped_reason = 'invalid_output';
          }
        } catch (err) {
          timings.push(timingEntry('synthesis', SYNTHESIS_CHUNK_KEY, started, null, { failed: err?.code || 'error' }));
          if (err?.code === AI_FAILURE_CODES.JOB_CANCELLED) throw err;
          // Deadline or provider failure during optional synthesis → keep merged chunk result.
          synthesis.skipped_reason = err?.code || 'error';
        }
      }
    }
  }

  return {
    ...merged,
    meta: {
      chunks_total: chunks.length,
      chunks_completed: chunks.length,
      chunks_from_cache: completedFromCache,
      chunks_analyzed_now: completedNow,
      ai_calls: aiCalls,
      ai_needed_candidates: partition.toClassify.length,
      resolved_candidates: partition.explicit.length + partition.resolvedOther.length,
      prompt_chars_total: timings.reduce((n, t) => n + (Number(t.prompt_chars) || 0), 0),
      synthesis,
      timing: timings,
      elapsed_ms: Date.now() - analysisStartedAt,
      timeout_policy: { ...policy, recovery_reserve_ms: reserveMs },
      schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
    }
  };
}

export { callAiProvider } from './client.js';
export { maskAiSettingsForClient, assertAiReady } from './settings.js';
export { processAiResponseText, validateAiAnalysis } from './schema.js';
export { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './contract.js';
export { formatCandidateEvidenceLine };
