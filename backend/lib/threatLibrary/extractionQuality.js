/**
 * Deterministic, read-only quality assessment of one extraction result.
 *
 * Runs after candidate extraction (pipeline and Refresh extraction alike) and
 * flags structural situations that usually mean publisher Indicators were lost
 * or non-Indicators promoted. A warning is a signal for an analyst or
 * developer, NEVER a classification: this module does not change candidates,
 * membership, MODE A/B, assessment or review state, and nothing reads its
 * output to promote anything.
 *
 * Every warning carries a stable reason code, a severity, the affected
 * candidate identities, block ids, section context, evidence excerpts, an
 * explanation and the extractor versions that produced it. Thresholds live in
 * EXTRACTION_QUALITY_THRESHOLDS only.
 */

import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { NEGATIVE_ZONES, STRONG_IOC_ZONES, THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';

/** Bump when a check, a reason code or a threshold changes. */
export const EXTRACTION_QUALITY_VERSION = 'tl-quality-v1';

export const QUALITY_SEVERITIES = Object.freeze(['info', 'warning', 'high']);
const SEVERITY_RANK = Object.freeze({ info: 1, warning: 2, high: 3 });

export const QUALITY_CODES = Object.freeze({
  /** Row-shaped IOC values right after / before an authoritative section, but outside it (MODE A). */
  INDICATOR_ROWS_ADJACENT_TO_SCOPE: 'indicator_rows_adjacent_to_authoritative_scope',
  /** Row-shaped IOC values elsewhere outside every authoritative section (MODE A). */
  INDICATOR_ROWS_OUTSIDE_SCOPE: 'indicator_rows_outside_authoritative_scope',
  /** IOC appendix present, row-shaped / appendix hashes extracted, zero hash Indicators. */
  APPENDIX_WITHOUT_HASH_INDICATORS: 'appendix_without_hash_indicators',
  /** IOC appendix present, fewer hash Indicators than non-member row hashes near it. */
  APPENDIX_HASH_INDICATORS_LOW: 'appendix_hash_indicators_low',
  /** Authoritative section holds IOC-shaped text but yields no Indicator. */
  AUTHORITATIVE_SECTION_WITHOUT_INDICATORS: 'authoritative_section_without_indicators',
  /** Authoritative heading with no observable content at all (IOCs may be published elsewhere). */
  AUTHORITATIVE_SECTION_EMPTY: 'authoritative_section_empty',
  /** Prose block inside a curated section whose values were left to the model (structural_completeness). */
  AUTHORITATIVE_VALUES_NOT_ASSERTED: 'authoritative_section_values_not_asserted',
  /** Table inside a curated section not read as an explicit IOC table (structural_completeness). */
  AUTHORITATIVE_TABLE_NOT_INTERPRETED: 'authoritative_table_not_interpreted',
  /** A valid explicit table row asserted an identity that never materialized. */
  EXPLICIT_TABLE_ROWS_DROPPED: 'explicit_table_rows_dropped',
  /** Reserved / loopback identity is a report Indicator (membership gates should prevent it). */
  RESERVED_INDICATOR: 'reserved_or_loopback_indicator',
  /** RFC documentation / example identity is a report Indicator. */
  EXAMPLE_INDICATOR: 'documentation_example_indicator',
  /** An Indicator the source also names as a legitimate / signed component. */
  LEGITIMATE_MARKER_INDICATOR: 'indicator_with_legitimate_marker',
  /** An Indicator that is the publisher's own domain (or its parent / subdomain). */
  PUBLISHER_DOMAIN_INDICATOR: 'publisher_domain_indicator',
  /** An Indicator seen only as the domain part of email addresses. */
  EMAIL_DOMAIN_ONLY_INDICATOR: 'indicator_only_email_domain',
  /** An Indicator without a source block / evidence span. */
  INDICATOR_MISSING_PROVENANCE: 'indicator_missing_provenance'
});

/**
 * Every threshold the checks use. Values are minimums of distinct identities
 * or block distances, chosen so a single narrative mention never warns.
 */
export const EXTRACTION_QUALITY_THRESHOLDS = Object.freeze({
  /** Distinct row-shaped IOC identities in one run outside authoritative scope before it is reported. */
  orphanRunMinValues: 3,
  /** Content blocks allowed between an authoritative block and an orphan run for "adjacent". */
  adjacentScopeMaxGapBlocks: 2,
  /** Non-observable words a block may carry and still read as a merged value list. */
  denseBlockMaxProseTokens: 2,
  /** Non-member row / appendix hashes needed before hash-membership checks apply. */
  appendixHashMinValues: 3,
  /** Bounded lists per warning. */
  maxListedCandidates: 20,
  maxListedBlocks: 20,
  maxEvidence: 5,
  maxWarnings: 40
});

const T = EXTRACTION_QUALITY_THRESHOLDS;
const HASH_TYPES = new Set(['md5', 'sha1', 'sha256']);
const NETWORK_TYPES = new Set(['ip', 'ipv6', 'domain', 'url', 'cidr']);
const IOC_TYPES = new Set([...HASH_TYPES, ...NETWORK_TYPES]);
const ROW_FORMS = new Set(['table_row', 'list_row', 'ip_port']);

/**
 * Non-member policies that depend on scope: the value would be an Indicator
 * had its occurrence been inside an authoritative section. Deterministic
 * semantic exclusions (benign component, provider service, reserved, RFC
 * example, negative zone, report source, non-network typing) are absent:
 * those rows are excluded for a reason other than scope.
 */
const SCOPE_DEPENDENT_POLICIES = new Set([
  'ai_needed_prose_sample_hash',
  'ai_needed_authoritative_narrative',
  'pass',
  'context_only_narrative_with_authoritative_scope',
  'context_only_contextual_mention_in_indicator_section'
]);

const IOC_SHAPE_RE =
  /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b|\b(?:hxxps?|https?):\/\/|\b(?:\d{1,3}\.){3}\d{1,3}\b|\[\.\]/i;

const identity = (c) => `${c.candidate_type}:${c.normalized_value}`;
const isChrome = (b) => b?.layout === 'page_edge' || b?.zone === 'header_footer';
const isContent = (b) => b && b.type !== 'heading' && !isChrome(b);
const excerpt = (text, n = 200) => String(text || '').replace(/\s+/g, ' ').trim().slice(0, n);

function isRowOccurrence(o) {
  if (o?.form === 'email_domain') return false;
  return o?.structural_row === true || o?.row_shape === true || ROW_FORMS.has(String(o?.form || ''));
}

const OBSERVABLE_TOKEN_RE =
  /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|(?:hxxps?|https?):\/\/\S+|(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}(?::\d{1,5})?|\S+(?:\.|\[\.\])[a-z]{2,10})$/i;

/**
 * A block that is a list in all but layout: at least `orphanRunMinValues`
 * observable / file-name tokens and at most `denseBlockMaxProseTokens` other
 * words (a PDF appendix whose "file hash" lines were merged into one
 * paragraph). Read only to locate lost rows, never to assert anything.
 * @param {object} b
 */
function isObservableDenseBlock(b) {
  if (!b || b.type === 'heading' || b.type === 'table') return false;
  const tokens = String(b.text || '').split(/[\s,;|]+/).map((t) => t.replace(/[()[\]"'“”]+$/g, '')).filter(Boolean);
  let observables = 0;
  let prose = 0;
  for (const t of tokens) {
    if (OBSERVABLE_TOKEN_RE.test(t)) observables += 1;
    else prose += 1;
  }
  return observables >= T.orphanRunMinValues && prose <= T.denseBlockMaxProseTokens;
}

function isNonActionable(c) {
  return c.reserved_address === true || c.non_actionable_local === true;
}

/**
 * A candidate that would be an Indicator but for scope: IOC type, not excluded
 * for a semantic reason, not a member.
 */
function isScopeDependentNonMember(c) {
  if (c.__member || c.is_ioc === false || !IOC_TYPES.has(String(c.candidate_type))) return false;
  if (isNonActionable(c) || c.rfc_example === true || c.is_report_source === true) return false;
  if (!SCOPE_DEPENDENT_POLICIES.has(String(c.policy_decision || ''))) return false;
  const occ = Array.isArray(c.occurrences) ? c.occurrences : [];
  return !occ.some((o) => o.relation_marker === 'benign' || o.relation_marker === 'provider');
}

function sameDomainFamily(domain, host) {
  const d = String(domain || '').toLowerCase();
  const h = String(host || '').toLowerCase().replace(/^www\./, '');
  if (!d || !h) return false;
  return d === h || d.endsWith(`.${h}`) || h.endsWith(`.${d}`);
}

/**
 * @param {{
 *   blocks: object[],
 *   candidates: object[],
 *   diagnostics?: object|null,
 *   sourceHost?: string|null,
 *   zonesVersion?: string|null
 * }} input zone-annotated blocks (extraction `annotated.blocks`) and the
 *   extracted candidates (evidence policy applied)
 */
export function assessExtractionQuality(input) {
  const blocks = Array.isArray(input?.blocks) ? input.blocks : [];
  const diagnostics = input?.diagnostics || {};
  const versions = {
    quality: EXTRACTION_QUALITY_VERSION,
    candidates: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
    zones: input?.zonesVersion || THREAT_LIBRARY_DOCUMENT_ZONES_VERSION
  };
  const candidates = (input?.candidates || []).map((c) => ({
    ...c,
    __member: isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) })
  }));
  const modeA = candidates.some((c) => c.document_has_authoritative_scope === true)
    || diagnostics.document_scope?.has_authoritative_indicator_scope === true;
  const blockById = new Map(blocks.map((b) => [b.id, b]));
  const denseBlocks = new Set(blocks.filter(isObservableDenseBlock).map((b) => b.id));
  const rowLike = (o) => isRowOccurrence(o) || denseBlocks.has(o?.block_id);
  const warnings = [];

  const push = (w) => {
    warnings.push({
      code: w.code,
      severity: w.severity,
      explanation: w.explanation,
      candidates: (w.candidates || []).slice(0, T.maxListedCandidates),
      candidate_count: (w.candidates || []).length,
      block_ids: [...new Set(w.block_ids || [])].slice(0, T.maxListedBlocks),
      section: w.section || null,
      evidence: (w.evidence || []).slice(0, T.maxEvidence),
      extractor_version: versions
    });
  };
  const evidenceFor = (ids) => ids
    .map((id) => blockById.get(id))
    .filter(Boolean)
    .map((b) => ({ block_id: b.id, block_type: b.type || null, zone: b.zone || null, text: excerpt(b.text) }));

  /** Blocks of orphan runs adjacent to an authoritative section (check 1 → check 2). */
  const adjacentRunBlocks = new Set();

  // --- 1. Row-shaped IOC values outside every authoritative section (MODE A) ---
  if (modeA) {
    /** block id → identities of scope-dependent non-member row occurrences */
    const orphanByBlock = new Map();
    for (const c of candidates) {
      if (!isScopeDependentNonMember(c)) continue;
      for (const o of c.occurrences || []) {
        if (!o.block_id || !rowLike(o)) continue;
        const z = String(o.zone || '');
        if (STRONG_IOC_ZONES.has(z) || NEGATIVE_ZONES.has(z) || z === 'header_footer') continue;
        if (!orphanByBlock.has(o.block_id)) orphanByBlock.set(o.block_id, new Set());
        orphanByBlock.get(o.block_id).add(identity(c));
      }
    }
    // Runs of consecutive content blocks carrying orphan rows (headings and
    // layout chrome between them do not break a run; other content does).
    const runs = [];
    let run = null;
    for (let i = 0; i < blocks.length; i += 1) {
      const b = blocks[i];
      if (!isContent(b)) continue;
      const ids = orphanByBlock.get(b.id);
      if (ids) {
        if (!run) run = { start: i, end: i, blocks: [], ids: new Set() };
        run.end = i;
        run.blocks.push(b.id);
        for (const id of ids) run.ids.add(id);
      } else if (run) {
        runs.push(run);
        run = null;
      }
    }
    if (run) runs.push(run);

    const authoritativeNear = (from, step) => {
      let gap = 0;
      for (let j = from + step; j >= 0 && j < blocks.length; j += step) {
        const b = blocks[j];
        if (!isContent(b)) continue;
        if (STRONG_IOC_ZONES.has(String(b.zone || ''))) return { block: b, gap };
        gap += 1;
        if (gap > T.adjacentScopeMaxGapBlocks) return null;
      }
      return null;
    };
    for (const r of runs) {
      if (r.ids.size < T.orphanRunMinValues) continue;
      const before = authoritativeNear(r.start, -1);
      const after = authoritativeNear(r.end, 1);
      const near = before || after;
      if (near) for (const id of r.blocks) adjacentRunBlocks.add(id);
      const first = blocks[r.start];
      const heading = first.section_heading || null;
      push({
        code: near ? QUALITY_CODES.INDICATOR_ROWS_ADJACENT_TO_SCOPE : QUALITY_CODES.INDICATOR_ROWS_OUTSIDE_SCOPE,
        severity: near ? 'warning' : 'info',
        explanation: near
          ? `${r.ids.size} row-shaped IOC values under "${heading || 'an unlabelled section'}" sit right ${before ? 'after' : 'before'} ` +
            `an authoritative section ("${near.block.section_heading || near.block.zone}") but are outside it, so MODE A ` +
            'excludes them from Indicators. A sub-heading may have closed the publisher IOC appendix.'
          : `${r.ids.size} row-shaped IOC values under "${heading || 'an unlabelled section'}" are outside every authoritative ` +
            'section; MODE A excludes them from Indicators. Usually an analysis inventory, occasionally a missed appendix.',
        candidates: [...r.ids].sort(),
        block_ids: r.blocks,
        section: {
          heading,
          zone: first.zone || null,
          adjacent_authoritative_block: near ? near.block.id : null,
          adjacent_authoritative_heading: near ? near.block.section_heading || null : null
        },
        evidence: evidenceFor(r.blocks)
      });
    }
  }

  // --- 2. IOC appendix with suspiciously few / zero hash Indicators (MODE A) ---
  // An IOC appendix: any block (its heading included) in an IOC / sample zone.
  const appendixBlocks = blocks.filter((b) => !isChrome(b) && (b.zone === 'explicit_ioc_section' || b.zone === 'sample_table'));
  if (modeA && appendixBlocks.length) {
    const memberHashes = candidates.filter((c) => c.__member && HASH_TYPES.has(c.candidate_type));
    const lostHashes = candidates.filter(
      (c) =>
        HASH_TYPES.has(c.candidate_type) &&
        isScopeDependentNonMember(c) &&
        // Inside the appendix, or in a row run right next to it — never a
        // distant analysis inventory (reported by check 1 as info only).
        (c.occurrences || []).some((o) => STRONG_IOC_ZONES.has(String(o.zone || '')) || adjacentRunBlocks.has(o.block_id))
    );
    if (lostHashes.length >= T.appendixHashMinValues && memberHashes.length < lostHashes.length) {
      const zero = memberHashes.length === 0;
      const blockIds = lostHashes.flatMap((c) => (c.occurrences || []).map((o) => o.block_id).filter(Boolean));
      push({
        code: zero ? QUALITY_CODES.APPENDIX_WITHOUT_HASH_INDICATORS : QUALITY_CODES.APPENDIX_HASH_INDICATORS_LOW,
        severity: zero ? 'high' : 'warning',
        explanation: zero
          ? `The report has a publisher IOC appendix and ${lostHashes.length} hash values inside or right next to it, ` +
            'but no hash is a report Indicator.'
          : `${memberHashes.length} hash Indicators against ${lostHashes.length} non-member hash rows near the IOC appendix.`,
        candidates: lostHashes.map(identity).sort(),
        block_ids: blockIds,
        section: {
          heading: appendixBlocks[0].type === 'heading' ? excerpt(appendixBlocks[0].text, 120) : appendixBlocks[0].section_heading || null,
          zone: appendixBlocks[0].zone,
          member_hashes: memberHashes.length
        },
        evidence: evidenceFor([...new Set(blockIds)])
      });
    }
  }

  // --- 3. Authoritative sections without Indicators ---
  const memberBlocks = new Set(
    candidates.filter((c) => c.__member).flatMap((c) => (c.occurrences || []).map((o) => o.block_id).filter(Boolean))
  );
  for (let i = 0; i < blocks.length; i += 1) {
    const opening = blocks[i];
    if (opening.scope_opening_id !== opening.id || !STRONG_IOC_ZONES.has(String(opening.zone || ''))) continue;
    // Region: the contiguous authoritative run the heading opened (child
    // sub-sections included), up to the first non-authoritative content block.
    const region = [];
    for (let j = i + 1; j < blocks.length; j += 1) {
      const b = blocks[j];
      if (isChrome(b)) continue;
      if (!STRONG_IOC_ZONES.has(String(b.zone || ''))) break;
      if (isContent(b)) region.push(b);
    }
    // A region nested in an earlier opening's region was already assessed.
    const prev = blocks.slice(0, i).reverse().find((b) => !isChrome(b));
    if (prev && STRONG_IOC_ZONES.has(String(prev.zone || ''))) continue;
    const hasMember = region.some((b) => memberBlocks.has(b.id));
    if (hasMember) continue;
    const shaped = region.filter((b) => IOC_SHAPE_RE.test(String(b.text || '')));
    const heading = excerpt(opening.text, 120);
    if (shaped.length) {
      push({
        code: QUALITY_CODES.AUTHORITATIVE_SECTION_WITHOUT_INDICATORS,
        severity: 'warning',
        explanation: `Authoritative section "${heading}" (${opening.zone}) contains IOC-shaped text in ${shaped.length} block(s) but yields no report Indicator.`,
        candidates: [],
        block_ids: [opening.id, ...shaped.map((b) => b.id)],
        section: { heading, zone: opening.zone, opened_by: opening.id },
        evidence: evidenceFor(shaped.map((b) => b.id))
      });
    } else {
      push({
        code: QUALITY_CODES.AUTHORITATIVE_SECTION_EMPTY,
        severity: 'info',
        explanation: `Authoritative heading "${heading}" has no observable content (the publisher may host its IOCs elsewhere).`,
        candidates: [],
        block_ids: [opening.id, ...region.map((b) => b.id)],
        section: { heading, zone: opening.zone, opened_by: opening.id },
        evidence: evidenceFor(region.map((b) => b.id))
      });
    }
  }

  // --- 4. Existing structural diagnostics, as warnings ---
  const sc = diagnostics.structural_completeness || null;
  for (const d of sc?.degraded_blocks || []) {
    push({
      code: QUALITY_CODES.AUTHORITATIVE_VALUES_NOT_ASSERTED,
      severity: 'warning',
      explanation: `${d.ai_needed_values} IOC values in a ${d.block_type || 'block'} inside curated section ` +
        `"${d.section_heading || d.zone}" were not read as publisher rows and were left to the model.`,
      candidates: d.examples || [],
      block_ids: [d.block_id],
      section: { heading: d.section_heading || null, zone: d.zone || null },
      evidence: evidenceFor([d.block_id])
    });
  }
  for (const t of sc?.tables_not_interpreted || []) {
    push({
      code: QUALITY_CODES.AUTHORITATIVE_TABLE_NOT_INTERPRETED,
      severity: 'warning',
      explanation: `A table with ${t.ioc_shaped_values} IOC-shaped values under "${t.section_heading || t.zone}" was not read ` +
        `as an explicit IOC table (${t.reason}).`,
      candidates: [],
      block_ids: [t.block_id],
      section: { heading: t.section_heading || null, zone: t.zone || null },
      evidence: evidenceFor([t.block_id])
    });
  }
  const et = diagnostics.explicit_tables || null;
  if (et?.inconsistent) {
    push({
      code: QUALITY_CODES.EXPLICIT_TABLE_ROWS_DROPPED,
      severity: 'high',
      explanation: `${(et.missing_identities || []).length} identities asserted by valid explicit IOC table rows never became candidates.`,
      candidates: et.missing_identities || [],
      block_ids: [],
      section: null,
      evidence: (et.dropped_asserted_identities || []).map((d) => ({ identity: `${d.type}:${d.value}`, reason: d.reason }))
    });
  }

  // --- 5. Suspicious Indicators (legitimate / reserved / publisher / provenance) ---
  const groups = new Map();
  const flag = (code, c) => {
    if (!groups.has(code)) groups.set(code, []);
    groups.get(code).push(c);
  };
  for (const c of candidates) {
    if (!c.__member) continue;
    const occ = Array.isArray(c.occurrences) ? c.occurrences : [];
    if (isNonActionable(c)) flag(QUALITY_CODES.RESERVED_INDICATOR, c);
    if (c.rfc_example === true) flag(QUALITY_CODES.EXAMPLE_INDICATOR, c);
    if (occ.some((o) => o.relation_marker === 'benign')) flag(QUALITY_CODES.LEGITIMATE_MARKER_INDICATOR, c);
    if (c.candidate_type === 'domain' && input?.sourceHost && sameDomainFamily(c.normalized_value, input.sourceHost)) {
      flag(QUALITY_CODES.PUBLISHER_DOMAIN_INDICATOR, c);
    }
    if (occ.length && occ.every((o) => o.form === 'email_domain')) flag(QUALITY_CODES.EMAIL_DOMAIN_ONLY_INDICATOR, c);
    if (!occ.some((o) => o.block_id) || !(c.evidence_text || occ.some((o) => o.surrounding_text))) {
      flag(QUALITY_CODES.INDICATOR_MISSING_PROVENANCE, c);
    }
  }
  const SUSPICIOUS = {
    [QUALITY_CODES.RESERVED_INDICATOR]: ['high', 'Reserved / loopback identities are report Indicators; membership gates should exclude them.'],
    [QUALITY_CODES.EXAMPLE_INDICATOR]: ['warning', 'Documentation / example identities (RFC 2606 / 5737 style) are report Indicators.'],
    [QUALITY_CODES.LEGITIMATE_MARKER_INDICATOR]: ['warning', 'Report Indicators that the source also describes as legitimate / signed components.'],
    [QUALITY_CODES.PUBLISHER_DOMAIN_INDICATOR]: ['warning', "Report Indicators in the publisher's own domain family."],
    [QUALITY_CODES.EMAIL_DOMAIN_ONLY_INDICATOR]: ['warning', 'Report Indicators that occur only as the domain part of email addresses (contact / sender context).'],
    [QUALITY_CODES.INDICATOR_MISSING_PROVENANCE]: ['warning', 'Report Indicators without a source block or evidence span.']
  };
  for (const [code, list] of groups) {
    const [severity, explanation] = SUSPICIOUS[code];
    const blockIds = list.flatMap((c) => (c.occurrences || []).map((o) => o.block_id).filter(Boolean));
    push({
      code,
      severity,
      explanation: `${list.length} ${explanation.charAt(0).toLowerCase()}${explanation.slice(1)}`,
      candidates: list.map(identity).sort(),
      block_ids: blockIds,
      section: null,
      evidence: evidenceFor([...new Set(blockIds)])
    });
  }

  warnings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.code.localeCompare(b.code));
  const counts = { high: 0, warning: 0, info: 0 };
  for (const w of warnings) counts[w.severity] += 1;
  const status = counts.high ? 'high' : counts.warning ? 'warning' : counts.info ? 'info' : 'clean';
  return {
    version: EXTRACTION_QUALITY_VERSION,
    mode: modeA ? 'A' : 'B',
    status,
    counts,
    warnings: warnings.slice(0, T.maxWarnings),
    warnings_total: warnings.length,
    extractor_versions: versions,
    thresholds: { ...EXTRACTION_QUALITY_THRESHOLDS }
  };
}

/**
 * Persistable, bounded copy for analysis_progress.extraction_diagnostics.
 * @param {ReturnType<typeof assessExtractionQuality>|null|undefined} quality
 */
export function compactExtractionQuality(quality) {
  if (!quality || typeof quality !== 'object') return null;
  return {
    version: quality.version || null,
    mode: quality.mode || null,
    status: quality.status || 'clean',
    counts: quality.counts || { high: 0, warning: 0, info: 0 },
    warnings_total: quality.warnings_total ?? (quality.warnings || []).length,
    extractor_versions: quality.extractor_versions || null,
    warnings: (quality.warnings || []).slice(0, T.maxWarnings).map((w) => ({
      code: w.code,
      severity: w.severity,
      explanation: String(w.explanation || '').slice(0, 400),
      candidates: (w.candidates || []).slice(0, T.maxListedCandidates).map((x) => String(x).slice(0, 200)),
      candidate_count: w.candidate_count ?? (w.candidates || []).length,
      block_ids: (w.block_ids || []).slice(0, T.maxListedBlocks),
      section: w.section || null,
      evidence: (w.evidence || []).slice(0, T.maxEvidence),
      extractor_version: w.extractor_version || null
    }))
  };
}
