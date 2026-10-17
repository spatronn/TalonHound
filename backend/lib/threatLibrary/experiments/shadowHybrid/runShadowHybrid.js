/**
 * Shadow Hybrid IOC Extraction PoC orchestrator.
 *
 * READ-ONLY / OFFLINE:
 * - Never writes to PostgreSQL
 * - Never refreshes reports or creates IOCs
 * - Qwen calls are optional and concurrency must be 1
 */

import fs from 'node:fs';
import path from 'node:path';
import { extractReportCandidates } from '../../extractionStages.js';
import { isReportIndicatorMember } from '../../indicatorMembership.js';
import { buildCandidateEvidenceRecord } from '../../evidencePolicy.js';
import { remapMembershipWithSectionTree } from './sectionTreeMembership.js';
import { runIndependentQwenDiscovery } from './qwenDiscovery.js';
import {
  candidateExtractedKeys,
  candidateMemberKeys,
  gtIdentities,
  hybridMemberKeys,
  identity,
  summarizeApproaches
} from './scoring.js';
import { evaluateSelectiveTriggers } from './selectiveTriggers.js';
import { isolateQwenFailure, simulateQwenUnavailable } from './failureIsolation.js';
import { SHADOW_SECTION_TREE_VERSION } from './sectionTree.js';
import { SHADOW_QWEN_DISCOVERY_VERSION } from './qwenDiscovery.js';
import {
  defaultCaseDirs,
  listCaseFiles,
  loadCaseDefinition,
  loadCaseDocument,
  selectCaseFiles,
  SHADOW_CASES_DIR
} from './loadCases.js';

export const SHADOW_HYBRID_POC_VERSION = 'tl-shadow-hybrid-poc-v1';

function persisted(c) {
  return { ...c, evidence: c.evidence || buildCandidateEvidenceRecord(c) };
}

function extractDeterministic(document, caseDef) {
  const report = {
    id: caseDef.id,
    source_type: caseDef.format === 'pdf' ? 'pdf' : 'url',
    source_url: caseDef.source_reference?.url || caseDef.source?.url || null,
    title: caseDef.title || caseDef.id
  };
  return extractReportCandidates(report, document);
}

function selectQwenBlocks(document, tree, selective, opts) {
  const blocks = document.blocks || [];
  if (opts.qwenMode === 'full') return blocks;
  if (opts.qwenMode === 'appendix_window') {
    // Prefer blocks under authoritative ancestry, else last 20% of doc.
    const auth = (tree?.blocks || []).filter((b) => b.authoritative_zone);
    if (auth.length >= 5) return auth;
    return blocks.slice(Math.floor(blocks.length * 0.7));
  }
  // selective: if triggered, use authoritative ancestry ± neighbors; else skip
  if (!selective?.would_trigger && opts.qwenMode === 'selective') return null;
  const auth = (tree?.blocks || []).filter((b) => b.authoritative_zone || b.shadow_heading_zone);
  if (auth.length >= 3) return auth;
  return blocks.slice(Math.floor(blocks.length * 0.65));
}

/**
 * Run one labeled case through all approaches.
 */
export async function runOneCase(caseFilePath, opts = {}) {
  const caseDef = loadCaseDefinition(caseFilePath);
  const document = loadCaseDocument(caseDef, caseFilePath);
  const expected = gtIdentities(caseDef.ground_truth?.indicators || []);
  const t0 = Date.now();

  const det = extractDeterministic(document, caseDef);
  const detCandidates = (det.candidates || []).map(persisted);
  const detMemberKeys = candidateMemberKeys(detCandidates);
  const extractedKeys = candidateExtractedKeys(detCandidates);
  const quality = det.diagnostics?.quality || det.extraction_quality || null;

  const treeResult = remapMembershipWithSectionTree(document, det.candidates || []);
  const treeMemberKeys = treeResult.memberKeys;

  const selective = evaluateSelectiveTriggers(quality, detCandidates, {
    expected,
    deterministicMembers: detMemberKeys
  });

  let qwen = null;
  let qwenKeys = new Set();
  let qwenSkipped = null;
  const runQwen = opts.runQwen === true;
  if (runQwen) {
    const qwenBlocks = selectQwenBlocks(document, treeResult.tree, selective, opts);
    if (!qwenBlocks) {
      qwenSkipped = 'selective_not_triggered';
    } else {
      qwen = await runIndependentQwenDiscovery({
        blocks: qwenBlocks,
        baseUrl: opts.ollamaBaseUrl,
        model: opts.ollamaModel,
        abortIfBusy: opts.abortIfBusy !== false,
        maxChunks: opts.maxChunks ?? (opts.qwenMode === 'full' ? 12 : 4),
        chunkChars: opts.chunkChars,
        failOpen: true
      });
      if (qwen.ok) {
        qwenKeys = new Set((qwen.indicator_proposals || []).map((p) => identity(p.type, p.value)));
      } else if (qwen.aborted) {
        qwenSkipped = 'ollama_busy';
      } else {
        qwenSkipped = qwen.reason || 'ollama_error';
      }
    }
  } else {
    qwenSkipped = 'qwen_disabled';
  }

  const hybridKeys = hybridMemberKeys(detMemberKeys, qwen?.indicator_proposals || [], {
    modeA: caseDef.ground_truth?.provenance?.mode !== 'B'
  });
  // Section-tree + selective Qwen hybrid
  const treeHybridKeys = hybridMemberKeys(treeMemberKeys, qwen?.indicator_proposals || [], {
    modeA: caseDef.ground_truth?.provenance?.mode !== 'B'
  });

  const summary = summarizeApproaches({
    expected,
    deterministicKeys: detMemberKeys,
    sectionTreeKeys: treeMemberKeys,
    qwenKeys,
    hybridKeys,
    extractedKeys
  });
  const treeHybridScore = summarizeApproaches({
    expected,
    deterministicKeys: detMemberKeys,
    sectionTreeKeys: treeMemberKeys,
    qwenKeys,
    hybridKeys: treeHybridKeys,
    extractedKeys
  }).membership.validated_hybrid;

  const isolation = {
    live: isolateQwenFailure(detMemberKeys, qwen),
    simulated_unavailable: simulateQwenUnavailable(detMemberKeys)
  };

  return {
    id: caseDef.id,
    title: caseDef.title || caseDef.id,
    case_file: caseFilePath,
    format: caseDef.format || null,
    mode: caseDef.ground_truth?.provenance?.mode || null,
    expected_count: expected.size,
    elapsed_ms: Date.now() - t0,
    quality_status: quality?.status || null,
    quality_codes: quality?.codes || (quality?.warnings || []).map((w) => w.code).filter(Boolean),
    selective,
    deterministic_member_count: detMemberKeys.size,
    section_tree_member_count: treeMemberKeys.size,
    qwen_proposal_count: qwen?.indicator_proposals?.length ?? 0,
    qwen_grounding_rejected: qwen?.grounded?.rejected?.length ?? 0,
    qwen_skipped: qwenSkipped,
    qwen_timing: qwen?.timing || null,
    scores: {
      ...summary,
      section_tree_plus_selective_qwen: treeHybridScore
    },
    discrepancies: {
      deterministic_fn: summary.membership.deterministic.fn_list,
      section_tree_fn: summary.membership.section_tree.fn_list,
      section_tree_only_correct: summary.section_tree_only_correct,
      qwen_only_correct: summary.qwen_only_correct,
      qwen_fp: summary.membership.qwen_independent.fp_list,
      grounding_rejected: (qwen?.grounded?.rejected || []).slice(0, 20)
    },
    isolation,
    versions: {
      poc: SHADOW_HYBRID_POC_VERSION,
      section_tree: SHADOW_SECTION_TREE_VERSION,
      qwen_discovery: SHADOW_QWEN_DISCOVERY_VERSION,
      candidates: det.diagnostics?.extraction_version || null,
      zones: det.diagnostics?.scope?.zones_version || null,
      quality: quality?.version || null
    },
    det_members_sample: [...detMemberKeys].slice(0, 30),
    tree_members_sample: [...treeMemberKeys].slice(0, 30)
  };
}

function aggregate(results) {
  const approaches = [
    'deterministic',
    'section_tree',
    'qwen_independent',
    'validated_hybrid',
    'section_tree_plus_selective_qwen'
  ];
  const agg = {};
  for (const a of approaches) {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    for (const r of results) {
      const s =
        a === 'section_tree_plus_selective_qwen'
          ? r.scores.section_tree_plus_selective_qwen
          : r.scores.membership[a];
      if (!s) continue;
      tp += s.tp;
      fp += s.fp;
      fn += s.fn;
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : null;
    const recall = tp + fn > 0 ? tp / (tp + fn) : null;
    const f1 = precision != null && recall != null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
    const round = (x) => (x == null ? null : Math.round(x * 10000) / 10000);
    agg[a] = { tp, fp, fn, precision: round(precision), recall: round(recall), f1: round(f1) };
  }

  const selective = {
    cases: results.length,
    would_trigger: results.filter((r) => r.selective?.would_trigger).length,
    clean_but_has_fn: results.filter((r) => r.selective?.clean_but_has_fn).length,
    would_catch_known_fn: results.filter((r) => r.selective?.would_catch_known_fn).length,
    known_fn_cases: results.filter((r) => (r.selective?.known_fn_count || 0) > 0).length
  };

  return { approaches: agg, selective };
}

/**
 * @param {object} opts
 */
export async function runShadowHybridPoc(opts = {}) {
  // cases/ → shadowHybrid/ → experiments/ → threatLibrary/ → lib/ → backend/
  const backendRoot = opts.backendRoot || path.resolve(SHADOW_CASES_DIR, '../../../../..');
  const dirs = opts.caseDirs || defaultCaseDirs(backendRoot);
  const all = listCaseFiles(dirs);
  const files = selectCaseFiles(all, {
    includeControls: opts.includeControls !== false,
    ids: opts.ids || null
  });

  // Optional absolute canonical path for Blinder Tunnel exported on the host.
  if (opts.extraCaseFiles) {
    for (const f of opts.extraCaseFiles) {
      if (f && fs.existsSync(f) && !files.includes(f)) files.push(f);
    }
  }

  const results = [];
  for (const f of files) {
    // Skip non-canonical sources silently (html_file / pdf_items need more loaders).
    try {
      const def = loadCaseDefinition(f);
      if (!['canonical', 'canonical_abs', 'canonical_inline', 'html_file', 'pdf_items'].includes(def.source?.kind)) {
        results.push({ id: def.id, skipped: true, reason: `unsupported_source_kind:${def.source?.kind}` });
        continue;
      }
      // eslint-disable-next-line no-await-in-loop
      const r = await runOneCase(f, opts);
      results.push(r);
      if (opts.onCase) opts.onCase(r);
    } catch (err) {
      results.push({ id: path.basename(f), skipped: true, reason: String(err?.message || err) });
    }
  }

  const scored = results.filter((r) => !r.skipped);
  const report = {
    version: SHADOW_HYBRID_POC_VERSION,
    generated_at: new Date().toISOString(),
    options: {
      runQwen: opts.runQwen === true,
      qwenMode: opts.qwenMode || 'selective',
      includeControls: opts.includeControls !== false,
      case_count_selected: files.length
    },
    aggregate: aggregate(scored),
    failure_isolation_ok: scored.every(
      (r) => r.isolation?.simulated_unavailable?.deterministic_preserved === true
    ),
    results: scored,
    skipped: results.filter((r) => r.skipped)
  };
  return report;
}

export function writeReport(report, outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  return outPath;
}
