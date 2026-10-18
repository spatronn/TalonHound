/**
 * Deterministic Threat Library pipeline stages (no model / provider code).
 *
 * Shared by the full analysis pipeline (pipeline.js) and the deterministic
 * extraction refresh (extractionRefresh.js). This module — like everything it
 * imports — must never import `./ai/*`: extractionRefresh.test.js walks the
 * static import graph of the refresh path and fails if a model client becomes
 * reachable from it.
 */

import { pdfToCanonicalDocument, THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } from './pdfIngest.js';
import { reextractStoredHtmlDocument } from './urlIngest.js';
import { CURRENT_HTML_EXTRACTOR_VERSIONS, titleMeta } from './extract/extractHtml.js';
import { selectHtmlTitle } from './extract/titleSelection.js';
import {
  extractCandidatesWithDiagnostics,
  summarizeCandidateSet,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { applyEvidencePolicy } from './evidencePolicy.js';
import { assessExtractionQuality, compactExtractionQuality } from './extractionQuality.js';
import {
  attachSectionTreeShadowDiagnostics,
  compactSectionTreeShadow,
  getScopeEngine,
  isSectionTreeScopeAuthoritative,
  applySectionTreeAuthority,
  SCOPE_ENGINE_LEGACY
} from './sectionTree/index.js';
import { hostnameFromUrl } from './candidateTyping.js';
import { isOnlyEmbeddedInDnsHostname, sourceTextFromDocument } from './sourceOccurrence.js';
import { bulkMatchCandidates } from './iocMatch.js';
import { deriveMatchState } from './constants.js';
import { readArtifactBuffer } from './artifactStore.js';
import {
  ESCALATING_ASSESSMENTS,
  EVIDENCE_INTEGRITY_VERSION,
  groundAiCandidateUpdate,
  indexDocumentBlocks
} from './evidenceIntegrity.js';
import { getReportById, updateReportPublicationDate } from './store.js';
import { detectReportPublicationDate, resolvePublicationDateUpdate } from './publicationDate.js';
import { createServiceLogger } from '../appLogger.js';

const log = createServiceLogger('threat-library');

export function hasUsableDocument(doc) {
  return Boolean(doc && Array.isArray(doc.blocks) && doc.blocks.length > 0);
}

/**
 * A stored canonical document is reusable only when its extractor contract is
 * current. PDF block segmentation changed in v2 (line/heading/footer-aware) and
 * v3 (table reconstruction); HTML extraction changed in v2 (DOM walk, structured
 * tables). Outdated documents are re-extracted from the stored artifact (PDF
 * upload / retained HTML) — the upload itself is always reused, and a URL is
 * only re-fetched when no HTML was retained.
 * @param {object} report
 * @param {object} doc
 */
export function isDocumentContractCurrent(report, doc) {
  if (!hasUsableDocument(doc)) return false;
  if (report?.source_type === 'pdf') {
    return doc.meta?.extractor === THREAT_LIBRARY_PDF_EXTRACTOR_VERSION;
  }
  if (report?.source_type === 'url') {
    return CURRENT_HTML_EXTRACTOR_VERSIONS.includes(String(doc.meta?.extractor || ''));
  }
  return true;
}

/**
 * Latest retained source HTML for a URL report (null when never retained).
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 */
export async function loadRetainedHtmlArtifact(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT id, storage_key, source_metadata FROM threat_report_artifacts
     WHERE report_id = $1 AND artifact_type = 'url_fetch' AND storage_key IS NOT NULL
     ORDER BY id DESC LIMIT 1`,
    [reportId]
  );
  return rows[0] || null;
}

/**
 * Latest stored PDF upload for a PDF report (null when none was stored).
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 */
export async function loadStoredPdfArtifact(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT * FROM threat_report_artifacts
     WHERE report_id = $1 AND artifact_type = 'pdf_upload' AND storage_key IS NOT NULL
     ORDER BY id DESC LIMIT 1`,
    [reportId]
  );
  return rows[0] || null;
}

/**
 * Rebuild the canonical document from the source retained with the report
 * (stored PDF upload / retained source HTML). Never touches the network:
 * returns null when no retained source exists or it cannot be re-extracted.
 * @param {import('pg').Pool} pool
 * @param {object} report
 * @returns {Promise<{ document: object, sourceHtml: string|null }|null>}
 */
export async function rebuildDocumentFromRetainedSource(pool, report) {
  if (report?.source_type === 'url') {
    const retained = await loadRetainedHtmlArtifact(pool, report.id);
    if (!retained?.storage_key) return null;
    const html = (await readArtifactBuffer(retained.storage_key)).toString('utf8');
    const reextracted = reextractStoredHtmlDocument(html, {
      url: report.source_url,
      finalUrl: retained.source_metadata?.final_url || report.source_url,
      httpStatus: retained.source_metadata?.http_status ?? 200
    });
    return reextracted?.document ? { document: reextracted.document, sourceHtml: html } : null;
  }
  if (report?.source_type === 'pdf') {
    const artifact = await loadStoredPdfArtifact(pool, report.id);
    if (!artifact?.storage_key) return null;
    const pdf = await pdfToCanonicalDocument(await readArtifactBuffer(artifact.storage_key), {
      fileName: report.source_file_name || artifact.file_name
    });
    if (pdf.requiresOcr || !hasUsableDocument(pdf.document)) return null;
    return { document: pdf.document, sourceHtml: null };
  }
  return null;
}

/**
 * Re-select the title of a URL report from its retained source HTML under the
 * current title rules (extract/titleSelection.js). The stored document keeps
 * its blocks; only its title / title provenance change. Never re-fetches;
 * a report without retained HTML (or a non-URL / WeChat-adapter report) keeps
 * its title. Non-fatal.
 * @param {import('pg').Pool} pool
 * @param {object} report
 * @param {{ document: object, sourceHtml?: string|null }} input
 * @returns {Promise<{ document: object, changed: boolean, title?: string, previous_title?: string|null, source?: string|null }>}
 */
export async function reselectReportTitle(pool, report, input) {
  const document = input.document;
  const unchanged = { document, changed: false };
  if (report?.source_type !== 'url' || !hasUsableDocument(document)) return unchanged;
  if (document.meta?.adapter && !['generic_html', 'structured_fallback'].includes(document.meta.adapter)) return unchanged;
  try {
    let html = input.sourceHtml || null;
    if (!html) {
      const retained = await loadRetainedHtmlArtifact(pool, report.id);
      if (!retained?.storage_key) return unchanged;
      html = (await readArtifactBuffer(retained.storage_key)).toString('utf8');
    }
    const selection = selectHtmlTitle(html, { url: report.source_url });
    if (!selection.title) return unchanged;
    const meta = { ...(document.meta || {}) };
    delete meta.site_names;
    delete meta.title_selection;
    const next = { ...document, title: selection.title, meta: { ...meta, ...titleMeta(selection) } };
    const changed = selection.title !== String(report.title || '') || selection.title !== String(document.title || '');
    return {
      document: next,
      changed,
      title: selection.title,
      previous_title: report.title || null,
      source: selection.source
    };
  } catch (err) {
    log.warn('title re-selection failed (non-fatal)', { reportId: report.id, error: err.message });
    return unchanged;
  }
}

/**
 * Detect the source's publication date and persist it under the write policy
 * (existing manual / THIB / stronger values are kept; a retry never nulls a
 * good value). A URL report without HTML in this run reads its retained
 * source HTML; a PDF reads the canonical document only (PDF CreationDate is
 * never used). Non-fatal: the analysis never fails because of a date.
 * @param {import('pg').Pool} pool
 * @param {object} report
 * @param {{ document: object|null, sourceHtml?: string|null }} input
 */
export async function applyPublicationDate(pool, report, input) {
  try {
    let html = input.sourceHtml || null;
    if (!html && report.source_type === 'url') {
      const retained = await loadRetainedHtmlArtifact(pool, report.id);
      if (retained?.storage_key) {
        try {
          html = (await readArtifactBuffer(retained.storage_key)).toString('utf8');
        } catch {
          html = null;
        }
      }
    }
    const detection = detectReportPublicationDate({
      sourceType: report.source_type,
      sourceUrl: report.source_url,
      html,
      document: input.document
    });
    const current = (await getReportById(pool, report.id)) || report;
    const decision = resolvePublicationDateUpdate(current, detection);
    if (decision.action === 'write') {
      await updateReportPublicationDate(pool, report.id, decision.fields);
    }
    const outcome = {
      action: decision.action,
      reason: decision.reason,
      detected: detection.published_at
        ? {
            published_at: detection.published_at,
            published_date: detection.published_date,
            precision: detection.precision,
            source: detection.source,
            raw_value: detection.raw_value,
            evidence: detection.evidence,
            modified_at: detection.modified_at
          }
        : null,
      extractor: detection.extractor
    };
    log.info('publication date resolved', { reportId: report.id, ...outcome });
    return outcome;
  } catch (err) {
    log.warn('publication date detection failed (non-fatal)', { reportId: report.id, error: err.message });
    return { action: 'keep', reason: `error:${err.message}`, detected: null, extractor: null };
  }
}

/**
 * Deterministic candidate extraction under the current contract. Stamps the
 * source provenance + contract version on the document meta (zone / source
 * marking reads them) and returns the stamped document with the candidates.
 * @param {object} report
 * @param {object} document
 */
export function extractReportCandidates(report, document) {
  const sourceUrl = report?.source_url || document?.meta?.source_url || null;
  let sourceHost = document?.meta?.source_host || null;
  if (!sourceHost && sourceUrl) {
    try {
      sourceHost = hostnameFromUrl(sourceUrl);
    } catch {
      sourceHost = null;
    }
  }
  const stamped = {
    ...document,
    meta: {
      ...(document?.meta || {}),
      source_url: sourceUrl,
      source_host: sourceHost,
      candidate_extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
    }
  };
  const extracted = extractCandidatesWithDiagnostics(stamped, {
    sourceUrl,
    observationNotAfter: observationNotAfterFor(report)
  });

  // Authoritative scope engine: exactly one engine owns final membership zones.
  // section_tree remaps occurrence authority from heading ancestry and re-runs
  // evidence policy. legacy keeps linear documentZones unchanged.
  // Invalid THREAT_LIBRARY_SCOPE_ENGINE must fail closed at extraction time
  // rather than silently changing membership semantics.
  getScopeEngine(process.env, { strict: true });
  let candidates = extracted.candidates;
  if (isSectionTreeScopeAuthoritative()) {
    try {
      const applied = applySectionTreeAuthority(stamped, extracted.candidates);
      candidates = applied.candidates;
      extracted.diagnostics = extracted.diagnostics || {};
      extracted.diagnostics.scope_engine = {
        engine: applied.scope_engine,
        version: applied.scope_engine_version,
        section_tree_version: applied.section_tree_version,
        has_authoritative_scope: applied.has_authoritative_scope === true,
        remapped_occurrences: applied.remapped_occurrences,
        demoted_occurrences: applied.demoted_occurrences,
        delegated_scope: applied.delegated_scope === true,
        delegated_occurrences: applied.delegated_occurrences || 0
      };
      stamped.meta.scope_engine = applied.scope_engine;
      stamped.meta.scope_engine_version = applied.scope_engine_version;
      stamped.meta.section_tree_version = applied.section_tree_version;
    } catch (err) {
      // Fail closed to legacy membership rather than shipping partial remap.
      extracted.diagnostics = extracted.diagnostics || {};
      extracted.diagnostics.scope_engine = {
        engine: SCOPE_ENGINE_LEGACY,
        version: null,
        error: String(err?.message || err).slice(0, 240),
        fallback: true
      };
      stamped.meta.scope_engine = SCOPE_ENGINE_LEGACY;
      candidates = extracted.candidates;
    }
  } else {
    stamped.meta.scope_engine = SCOPE_ENGINE_LEGACY;
    extracted.diagnostics = extracted.diagnostics || {};
    extracted.diagnostics.scope_engine = {
      engine: SCOPE_ENGINE_LEGACY,
      version: null
    };
  }

  // Quality warnings after authority remap so they reflect the active engine.
  extracted.diagnostics.quality = assessExtractionQuality({
    blocks: extracted.annotated?.blocks || [],
    candidates,
    diagnostics: extracted.diagnostics,
    sourceHost,
    zonesVersion: extracted.annotated?.meta?.zones_version || null,
    documentMeta: stamped.meta
  });

  // Optional shadow diagnostics (independent of authoritative engine).
  // When section_tree is already authoritative, shadow still compares but must
  // not mutate candidates again.
  attachSectionTreeShadowDiagnostics(stamped, candidates, extracted.diagnostics);

  return {
    document: stamped,
    candidates,
    diagnostics: extracted.diagnostics,
    // Zone-annotated view of `document` (never persisted; read-only consumers).
    annotated: extracted.annotated
  };
}

/**
 * Latest calendar day a publisher observation in this report can carry: the
 * report's publication day when known, never later than today (UTC).
 * @param {{ published_at?: string|Date|null }|null|undefined} report
 * @param {Date} [now]
 * @returns {string} YYYY-MM-DD
 */
export function observationNotAfterFor(report, now = new Date()) {
  const today = now.toISOString().slice(0, 10);
  const raw = report?.published_at;
  if (!raw) return today;
  const published = raw instanceof Date ? raw : new Date(raw);
  if (Number.isNaN(published.getTime())) return today;
  const day = published.toISOString().slice(0, 10);
  return day < today ? day : today;
}

/**
 * Final candidate set = deterministic candidates ∪ AI classification of the
 * `ai_needed` subset. The model output is never the list of indicators: an
 * update only refines a candidate that already exists, explicit assertions can
 * only gain a malicious role, and every candidate passes the evidence policy
 * again. A missing / empty AI result leaves the deterministic set intact.
 *
 * IPv4 / IPv6 proposals are source-grounded when `opts.sourceText` or
 * `opts.document` is provided: a value that occurs only as a prefix/subspan
 * of a larger DNS hostname is dropped, whether it came from a stale
 * deterministic set or from the model. The model is not authoritative about
 * token boundaries. New AI identities are never inserted.
 * @param {object[]} candidates
 * @param {{ candidate_updates?: object[] }|null} aiValue
 * @param {{ sourceText?: string, document?: object }} [opts]
 */
export function mergeAiCandidateUpdates(candidates, aiValue, opts = {}) {
  const sourceText = opts.sourceText || (opts.document ? sourceTextFromDocument(opts.document) : '');
  const keep = (c) => {
    if (!sourceText) return true;
    if (c.candidate_type !== 'ip' && c.candidate_type !== 'ipv6') return true;
    return !isOnlyEmbeddedInDnsHostname(sourceText, c.candidate_type, c.normalized_value);
  };
  const byKey = new Map(
    (candidates || []).filter(keep).map((c) => [`${c.candidate_type}\0${c.normalized_value}`, c])
  );
  // Publisher-evidence integrity: model quotes / blocks / escalations are
  // checked against the canonical document (when one is supplied).
  const blocks = opts.document ? indexDocumentBlocks(opts.document) : null;
  for (const u of aiValue?.candidate_updates || []) {
    const key = `${u.candidate_type}\0${u.normalized_value}`;
    const existing = byKey.get(key);
    if (!existing) continue;
    if (sourceText && (u.candidate_type === 'ip' || u.candidate_type === 'ipv6')) {
      if (isOnlyEmbeddedInDnsHostname(sourceText, u.candidate_type, u.normalized_value)) continue;
    }
    // The deterministic anchor is the publisher evidence; it is kept as-is
    // whatever the model says (first merge wins: replays never move it).
    if (!existing.publisher_evidence) {
      existing.publisher_evidence = { text: existing.evidence_text || null, block_id: existing.block_id || null };
    }
    const grounding = blocks ? groundAiCandidateUpdate(existing, u, blocks) : null;
    const escalates = ESCALATING_ASSESSMENTS.has(String(u.assessment || '').toLowerCase());
    // An unsupported model claim never escalates a candidate: a malicious /
    // suspicious label needs real publisher text naming the value. Demotions
    // (context only, benign roles) are conservative and still apply.
    const applyAssessment = !grounding || grounding.supported || !escalates;
    applyEvidencePolicy(existing, applyAssessment
      ? { assessment: u.assessment, role: u.role || existing.role, confidence: u.confidence ?? existing.confidence }
      : null);
    // Stable record of the model's own output (identical when Refresh replays
    // the same decision): what it said, whether publisher text supports it,
    // and whether it was applied.
    existing.ai_classification = {
      assessment: u.assessment || null,
      role: u.role || null,
      confidence: u.confidence ?? null,
      supported: grounding ? grounding.supported : null,
      applied: applyAssessment,
      integrity_version: EVIDENCE_INTEGRITY_VERSION
    };
    if (u.evidence_text) {
      if (!grounding || grounding.quote === 'grounded') {
        existing.evidence_text = u.evidence_text;
        if (grounding?.quote_block_id) existing.block_id = grounding.quote_block_id;
      } else {
        // Paraphrase / fabricated quote: keep the publisher anchor, retain the
        // model text only as a rejected, auditable suggestion.
        existing.ai_evidence_rejected = { text: String(u.evidence_text).slice(0, 240), reason: grounding.quote };
      }
    }
    if (u.section) existing.section = u.section;
    if (!grounding) {
      if (u.evidence_block_ids?.[0]) existing.block_id = u.evidence_block_ids[0];
    } else if (grounding.cited_block_id && grounding.quote !== 'grounded') {
      existing.block_id = grounding.cited_block_id;
    }
  }
  return [...byKey.values()].map((c) => applyEvidencePolicy(c));
}

/**
 * Match stage: link candidates to local IOC records and derive match_state,
 * then summarize the resolved set (report `candidate_summary`).
 * @param {import('pg').Pool} pool
 * @param {object[]} candidates
 */
export async function matchCandidateSet(pool, candidates) {
  const matched = await bulkMatchCandidates(pool, candidates);
  const resolved = matched.candidates.map((c) => ({
    ...c,
    match_state: deriveMatchState({
      assessment: c.assessment,
      confidence: c.confidence,
      matchedIocId: c.matched_ioc_id,
      valid: c.assessment !== 'invalid'
    })
  }));
  return { candidates: resolved, summary: summarizeResolvedCandidates(resolved) };
}

/**
 * Report-level candidate counts for a resolved (matched) candidate set.
 * @param {object[]} candidates
 */
export function summarizeResolvedCandidates(candidates) {
  const summary = {
    total: candidates.length,
    existing: 0,
    new: 0,
    context_only: 0,
    needs_review: 0,
    invalid: 0
  };
  for (const c of candidates) {
    if (summary[c.match_state] != null) summary[c.match_state] += 1;
  }
  const finalSet = summarizeCandidateSet(candidates);
  summary.explicit_assertions = finalSet.explicit_assertions;
  summary.ai_classified = candidates.filter((c) => c.decision_source === 'ai').length;
  summary.raw_occurrences = finalSet.raw_occurrences;
  summary.non_ioc = finalSet.non_ioc;
  return summary;
}

/**
 * Admin-facing extraction diagnostics persisted with the report (bounded).
 * @param {object|null} diagnostics
 */
export function compactExtractionDiagnostics(diagnostics) {
  const t = diagnostics?.explicit_tables;
  if (!t) return diagnostics && typeof diagnostics === 'object' && diagnostics.explicit_tables === undefined ? diagnostics : null;
  const tr = diagnostics.type_resolution;
  return {
    extraction_version: diagnostics.extraction_version || null,
    type_resolution: tr
      ? {
          syntactic_occurrences: tr.syntactic_occurrences ?? 0,
          network_ioc_candidates: tr.network_ioc_candidates ?? 0,
          artifact_candidates: tr.artifact_candidates ?? 0,
          artifact_occurrences_dropped: tr.artifact_occurrences_dropped ?? 0,
          relative_paths: tr.relative_paths ?? 0,
          canonical_rejections: tr.canonical_rejections ?? 0,
          rejected_values: tr.rejected_values || {},
          excluded_reasons: tr.excluded_reasons || {},
          examples: (tr.examples || []).slice(0, 24),
          scheme_less_resources: tr.scheme_less_resources
            ? {
                count: tr.scheme_less_resources.count ?? 0,
                rejected: tr.scheme_less_resources.rejected || {},
                examples: (tr.scheme_less_resources.examples || []).slice(0, 12)
              }
            : undefined
        }
      : null,
    // Scope decisions (which headings opened / continued / closed authoritative
    // sections, how occurrences were read) — developer diagnostics, bounded.
    scope: diagnostics.scope
      ? {
          zones_version: diagnostics.scope.zones_version || null,
          trace: (diagnostics.scope.trace || []).slice(0, 60),
          occurrence_kinds: diagnostics.scope.occurrence_kinds || {},
          relation_markers: diagnostics.scope.relation_markers || {},
          policy_decisions: diagnostics.scope.policy_decisions || {},
          candidates: (diagnostics.scope.candidates || []).slice(0, 80)
        }
      : undefined,
    quality: diagnostics.quality ? compactExtractionQuality(diagnostics.quality) : undefined,
    scope_engine: diagnostics.scope_engine
      ? {
          engine: diagnostics.scope_engine.engine || null,
          version: diagnostics.scope_engine.version || null,
          section_tree_version: diagnostics.scope_engine.section_tree_version || null,
          has_authoritative_scope: diagnostics.scope_engine.has_authoritative_scope === true,
          remapped_occurrences: diagnostics.scope_engine.remapped_occurrences ?? null,
          demoted_occurrences: diagnostics.scope_engine.demoted_occurrences ?? null,
          error: diagnostics.scope_engine.error || undefined,
          fallback: diagnostics.scope_engine.fallback === true || undefined
        }
      : undefined,
    section_tree_shadow: diagnostics.section_tree_shadow
      ? compactSectionTreeShadow(diagnostics.section_tree_shadow)
      : undefined,
    structural_completeness: diagnostics.structural_completeness
      ? {
          warning: diagnostics.structural_completeness.warning === true,
          degraded_candidates: diagnostics.structural_completeness.degraded_candidates ?? 0,
          tables_not_interpreted: (diagnostics.structural_completeness.tables_not_interpreted || []).slice(0, 20),
          degraded_blocks: (diagnostics.structural_completeness.degraded_blocks || []).slice(0, 20)
        }
      : undefined,
    explicit_tables: {
      tables_seen: t.tables_seen ?? 0,
      ioc_tables: t.ioc_tables ?? 0,
      explicit_tables: t.explicit_tables ?? 0,
      rows_seen: t.rows_seen ?? 0,
      rows_valid: t.rows_valid ?? 0,
      rows_rejected: t.rows_rejected ?? 0,
      values_asserted: t.values_asserted ?? 0,
      candidates_created: t.candidates_created ?? 0,
      explicit_identities: t.explicit_identities ?? 0,
      rejection_reasons: t.rejection_reasons || {},
      inconsistent: t.inconsistent === true,
      missing_identities: (t.missing_identities || []).slice(0, 40),
      dropped_asserted_identities: (t.dropped_asserted_identities || []).slice(0, 40),
      tables: (t.tables || [])
        .filter((x) => x.kind === 'ioc_table' || x.kind === 'identifier_table')
        .slice(0, 60)
        .map((x) => ({
          table_id: x.table_id,
          page: x.page ?? null,
          zone: x.zone || null,
          section_heading: x.section_heading || null,
          kind: x.kind,
          explicit: x.explicit === true,
          reason: x.reason || null,
          columns: x.columns || [],
          rows_seen: x.rows_seen ?? 0,
          rows_valid: x.rows_valid ?? 0,
          rows_rejected: x.rows_rejected ?? 0,
          rejection_reasons: x.rejection_reasons || {},
          rejected_rows: (x.rejected_rows || []).slice(0, 12)
        }))
    }
  };
}
