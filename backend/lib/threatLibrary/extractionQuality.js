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
import { textDescribesValueAsBenign } from './indicatorScope.js';
import { hasDelegatedDnsSuffix, suffixStrength } from './observableTypeResolver.js';
import { refangTextForExtraction } from './defang.js';
import { annotateSectionTree } from './sectionTree/annotate.js';

/**
 * Bump when a check, a reason code or a threshold changes.
 * v2: "adjacent" rows are rows right AFTER an authoritative section (the
 * direction scope loss pushes them); rows that only precede an appendix are
 * analysis content and report as info.
 * v3 (production read-only scan + independent real-report ground truth):
 * a table not read as an explicit IOC table no longer warns when every IOC
 * value in it is a report Indicator anyway; values left to the model no longer
 * warn when each is a parent platform of a more specific Indicator; new
 * check 6 reports Indicators whose only authority is structural discovery (an
 * IOC-shaped body table header or an unlabelled observable list).
 * v4 (P1 structural reliability): check 7 flags row-shaped non-members whose
 * section heading still names an IOC / C2 appendix (premature scope close /
 * nested-heading loss) even when the orphan-run length is below the v3
 * threshold; check 8 flags IOC-looking body tables that sit outside every
 * headed appendix (authority risk even when membership was correctly withheld).
 * v5 (refresh membership reconciliation): check 9, on a fresh extraction
 * that replays stored analyst state (Refresh extraction, Retry / Re-run AI),
 * compares the deterministic publisher membership with the membership after
 * replayed analyst state (withReplayMembershipDivergence). An explicit
 * analyst override (promote_to_ioc, Context Only review) is a note; any other
 * divergence warns. Checks 1-8 are unchanged.
 * v6 (six-report audit): checks that compare against evidence independent of
 * the membership decision itself. Check 10: hash / IPv4 tokens written in an
 * IOC-table indicator cell of an authoritative section that never became a
 * candidate (a cell parse kept only its leading file identity). Check 11: an
 * indicator column inferred from content beside a header-declared hash
 * column of another hash type (certificate thumbprints / serials). Check 12:
 * an Indicator domain with a weak, undelegated suffix (system identifiers read
 * as hosts). Check 5 also reads the occurrence text, not only the relation
 * marker, for a legitimate / benign description of an Indicator.
 * v7 (nine-report audit): check 13 reports delegated authority (every formal
 * IOC section empty, Indicators from body assertions); check 14 lists hash-
 * shaped values kept as non-file digests; check 15 flags an Indicator the
 * publisher both asserts and calls legitimate / dual-use; post-merge checks
 * 16–18 (withPostMergeQuality) record rejected model quotes, unsupported model
 * escalations and malicious-assessed non-members (MODE A suppression).
 * v8 (ten-report audit): under the section-tree engine, check 6 treats a
 * discovery block nested under a publisher IOC heading as governed by it.
 * v9 (31-report audit): under the section-tree engine the reported MODE is
 * the tree's authoritative-scope decision (the one membership uses), not the
 * legacy linear document scope.
 * v10 (30-report audit): checks grounded in the confirmed failure categories.
 * Check 19 lists directory URLs excluded as incomplete prefixes although the
 * publisher listed them in an IOC section; check 20 lists table reference-
 * column values kept as context and warns on an Indicator read from a
 * reference-labelled column; check 21 warns on a file-hash Indicator whose own
 * row / sentence calls the digest a key, certificate, fingerprint or banner
 * hash; check 22 reports a downloadable IOC package the publisher announces
 * (overlaid at read time when no IOC Source was discovered); post-merge check
 * 23 warns when the model demoted rows of a table whose sibling rows of the
 * same type are Indicators. A typed-artifact cell value no longer counts as a
 * dropped explicit-table row.
 */
export const EXTRACTION_QUALITY_VERSION = 'tl-quality-v10';

export const QUALITY_SEVERITIES = Object.freeze(['info', 'warning', 'high']);
const SEVERITY_RANK = Object.freeze({ info: 1, warning: 2, high: 3 });

export const QUALITY_CODES = Object.freeze({
  /** Row-shaped IOC values right after an authoritative section, but outside it (MODE A). */
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
  /** Indicators whose only authority is structural discovery (body table header / unlabelled list). */
  INDICATORS_FROM_STRUCTURAL_DISCOVERY: 'indicators_from_structural_discovery',
  /**
   * Row-shaped values under an IOC/C2 section heading but outside authoritative
   * zones (premature appendix close, nested list heading loss, metadata mis-zone).
   */
  APPENDIX_HEADING_NONMEMBER_ROWS: 'appendix_heading_nonmember_rows',
  /**
   * An IOC-looking body table outside every headed appendix — structural
   * authority risk even when the values correctly stayed non-Indicators.
   */
  BODY_IOC_TABLE_OUTSIDE_APPENDIX: 'body_ioc_table_outside_appendix',
  /**
   * Replayed analyst state moves report Indicator membership away from the
   * deterministic publisher reading (refresh / retry; check 9).
   */
  ANALYST_STATE_MEMBERSHIP_DIVERGENCE: 'analyst_state_membership_divergence',
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
  INDICATOR_MISSING_PROVENANCE: 'indicator_missing_provenance',
  /** A hash / IPv4 written in an authoritative IOC-table indicator cell never became a candidate (check 10). */
  TABLE_OBSERVABLE_NOT_EXTRACTED: 'table_observable_not_extracted',
  /** Content-inferred indicator column of another hash type beside a declared hash column (check 11). */
  CONTENT_INFERRED_HASH_COLUMN: 'content_inferred_hash_column',
  /** An Indicator domain whose suffix is weak and not delegated (check 12). */
  UNDELEGATED_SUFFIX_DOMAIN_INDICATOR: 'undelegated_suffix_domain_indicator',
  /** Every formal IOC section empty: Indicators come from delegated body assertions (check 13). */
  DELEGATED_AUTHORITY_APPLIED: 'delegated_authority_applied',
  /** Hash-shaped values the publisher labelled as non-file digests (check 14). */
  NON_FILE_DIGEST_RECLASSIFIED: 'non_file_digest_reclassified',
  /** An Indicator the publisher both asserts and calls legitimate / dual-use (check 15). */
  PUBLISHER_STANCE_CONFLICT: 'publisher_stance_conflict',
  /** Model evidence quotes not found verbatim in the document (post-merge check 16). */
  AI_EVIDENCE_UNGROUNDED: 'ai_evidence_ungrounded',
  /** Model malicious / suspicious labels without publisher support, not applied (check 17). */
  AI_ESCALATION_UNSUPPORTED: 'ai_escalation_unsupported',
  /** Candidates assessed malicious that are not report Indicators (check 18, explains suppression). */
  MALICIOUS_ASSESSED_NON_MEMBERS: 'malicious_assessed_non_members',
  /** Directory URLs excluded as incomplete prefixes although listed in an IOC section (check 19). */
  IOC_SECTION_URL_PREFIX_EXCLUDED: 'ioc_section_url_prefix_excluded',
  /** Table reference-column values (tool homepage / download / source links) kept as context (check 20). */
  REFERENCE_COLUMN_CONTEXT: 'reference_column_values_context',
  /** An Indicator read only from a table column whose header names a reference / source / download link (check 20). */
  REFERENCE_COLUMN_INDICATOR: 'reference_column_indicator',
  /** A file-hash Indicator whose own row or sentence calls the digest a key / certificate / fingerprint / banner hash (check 21). */
  NON_FILE_DIGEST_SUSPECT: 'non_file_digest_indicator_suspect',
  /** The publisher announces a downloadable IOC package (STIX / JSON / CSV / repository) (check 22). */
  IOC_PACKAGE_ANNOUNCED: 'ioc_package_announced',
  /** Model-demoted table rows beside Indicator rows of the same table and type (post-merge check 23). */
  AI_DEMOTED_TABLE_ROWS: 'ai_demoted_table_rows'
});

/** A table column header that names where something is published (check 20). */
const REFERENCE_HEADER_RE =
  /^(?:sources?|references?|refs?|downloads?|download\s+(?:link|links|url|urls|page|location)|(?:tool\s+)?home\s*pages?|projects?|project\s+(?:page|url|site|link)s?|repository|repositories|repos?|websites?)$/i;
/** Non-file digest vocabulary written next to a hash (check 21). */
const NON_FILE_DIGEST_WORDS_RE =
  /\b(?:(?:public|private|host|server|ssh)\s+(?:[a-z0-9-]+\s+){0,2}keys?|fingerprints?|thumbprints?|certificates?|serial\s+(?:number|no)|banner[\s_-]*\d*[\s_-]*hash|jarm|ja3s?|ja4|imphash|ssdeep|tlsh|build[\s-]*id)\b/i;
const FILE_SUBJECT_RE = /\b(?:file|sample|binary|executable|payload|dll|exe|loader|dropper|implant|script|archive|installer|malware|backdoor|trojan|ransomware|encryptor)\b/i;
/** A downloadable IOC package announced in the document text (check 22). */
const IOC_PACKAGE_LEAD_IN_RE =
  /\b(?:a\s+downloadable\s+(?:copy|list|version|file|set)\s+of\s+(?:the\s+)?(?:[\w.,]+\s+){0,3}(?:iocs?|indicators?)|downloadable\s+iocs?|(?:iocs?|indicators?|observables)\s+(?:are|is)\s+(?:also\s+)?available\s+(?:for\s+download|in\s+(?:stix|json|csv|ecs|misp|txt))|available\s+for\s+download\s+in\s+(?:both\s+)?(?:ecs|stix|json|csv|misp))\b/i;

/**
 * Every threshold the checks use. Values are minimums of distinct identities
 * or block distances, chosen so a single narrative mention never warns.
 */
export const EXTRACTION_QUALITY_THRESHOLDS = Object.freeze({
  /** Distinct row-shaped IOC identities in one run outside authoritative scope before it is reported. */
  orphanRunMinValues: 3,
  /** Distinct non-member rows under an IOC/C2 heading (check 7) before warning. */
  appendixHeadingNonmemberMinValues: 2,
  /** Distinct IOC-typed cells in a body table (check 8) before reporting. */
  bodyIocTableMinValues: 3,
  /** Content blocks allowed between a preceding authoritative block and an orphan run for "adjacent". */
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

/** Standalone hash / IPv4 tokens of one indicator cell, lower-cased (URL / path components excluded). */
const CELL_HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const CELL_IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?$/;
function cellObservableTokens(cell) {
  const out = [];
  for (const raw of refangTextForExtraction(String(cell || '')).split(/[\s,;|]+/)) {
    if (!raw || raw.includes('/') || raw.includes('\\')) continue;
    const tok = raw.replace(/^[(\[{<"'“‘]+|[)\]}>"'”’.,:;]+$/g, '');
    if (CELL_HASH_RE.test(tok)) out.push(tok.toLowerCase());
    else if (CELL_IPV4_RE.test(tok)) out.push(tok.split(':')[0]);
  }
  return out;
}

/** Special-use / alternative-root suffixes that are legitimately undelegated in ICANN DNS. */
const SPECIAL_USE_SUFFIXES = new Set(['onion', 'bit', 'i2p', 'exit', 'loki', 'eth', 'coin', 'lib', 'bazar', 'emc']);
function isUndelegatedWeakDomain(value) {
  const labels = String(value || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length < 2 || SPECIAL_USE_SUFFIXES.has(labels[labels.length - 1])) return false;
  return suffixStrength(labels) === 'weak' && !hasDelegatedDnsSuffix(labels.join('.'));
}

/** An occurrence whose own text describes the value as a legitimate / benign component. */
function occurrenceDescribesBenign(c, o) {
  const text = o?.surrounding_text || '';
  return Boolean(text) && textDescribesValueAsBenign(text, [c.normalized_value, o.original_value, c.original_value]);
}
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

/**
 * Zone reasons that grant authoritative scope from block shape alone, with no
 * publisher heading: an IOC-shaped table header in body text, or a run of
 * observable-only rows (documentZones applyObservableListZones).
 */
const STRUCTURAL_DISCOVERY_REASONS = new Set(['ioc_table', 'observable_list']);

/** Host part of a domain / URL identity, lower-cased (null for other types). */
function hostOf(c) {
  const v = String(c?.normalized_value || '').toLowerCase();
  if (c?.candidate_type === 'domain') return v;
  if (c?.candidate_type === 'url') {
    const m = v.match(/^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/);
    return m ? m[1] : null;
  }
  return null;
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
  // MODE as membership sees it: under the section-tree engine the tree decides
  // (the legacy linear scope may disagree, tl-quality-v9); candidates carry the
  // same flag. Legacy keeps the linear document scope.
  const sectionTreeMode = diagnostics.scope_engine?.engine === 'section_tree' && diagnostics.scope_engine?.fallback !== true &&
    typeof diagnostics.scope_engine?.has_authoritative_scope === 'boolean';
  const modeA = candidates.some((c) => c.document_has_authoritative_scope === true) ||
    (sectionTreeMode ? diagnostics.scope_engine.has_authoritative_scope === true
      : diagnostics.document_scope?.has_authoritative_indicator_scope === true);
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
      // Scope loss pushes rows out AFTER an authoritative section (a heading
      // closes the section going forward), so only an authoritative block
      // right before the run makes it "adjacent". Rows that merely precede an
      // appendix are ordinary analysis content (reported as info).
      const before = authoritativeNear(r.start, -1);
      const near = before;
      if (near) for (const id of r.blocks) adjacentRunBlocks.add(id);
      const first = blocks[r.start];
      const heading = first.section_heading || null;
      push({
        code: near ? QUALITY_CODES.INDICATOR_ROWS_ADJACENT_TO_SCOPE : QUALITY_CODES.INDICATOR_ROWS_OUTSIDE_SCOPE,
        severity: near ? 'warning' : 'info',
        explanation: near
          ? `${r.ids.size} row-shaped IOC values under "${heading || 'an unlabelled section'}" sit right after ` +
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
  /** block id → IOC-typed candidates with an occurrence in it */
  const iocByBlock = new Map();
  for (const c of candidates) {
    if (!IOC_TYPES.has(String(c.candidate_type))) continue;
    for (const o of c.occurrences || []) {
      if (!o.block_id) continue;
      if (!iocByBlock.has(o.block_id)) iocByBlock.set(o.block_id, new Set());
      iocByBlock.get(o.block_id).add(c);
    }
  }
  const memberHosts = candidates.filter((c) => c.__member).map(hostOf).filter(Boolean);
  // A platform named in prose ("github.com", "workers.dev") whose specific
  // campaign host / URL is already an Indicator: nothing was lost.
  const coveredByMember = (c) => {
    const h = hostOf(c);
    return Boolean(h) && memberHosts.some((m) => m === h || m.endsWith(`.${h}`));
  };
  // A row the publisher itself calls a legitimate / benign component is
  // excluded on purpose (row-level benign assertion), not lost.
  // Reserved / loopback / link-local values (a YARA string "169.254.0.1") are
  // never Indicators either, so a table holding them lost nothing.
  const deliberatelyExcluded = (c) => [
    'context_only_benign_component',
    'context_only_reserved_address',
    'context_only_non_actionable_local',
    'context_only_rfc_example'
  ].includes(String(c.policy_decision || ''));
  const blockFullyCaptured = (blockId, covered) => {
    const list = [...(iocByBlock.get(blockId) || [])];
    return list.length > 0 && list.every((c) => c.__member || deliberatelyExcluded(c) || (covered && coveredByMember(c)));
  };
  const sc = diagnostics.structural_completeness || null;
  for (const d of sc?.degraded_blocks || []) {
    if (blockFullyCaptured(d.block_id, true)) continue;
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
    // Rows inherited the section's authority without the explicit-table path:
    // every IOC value is an Indicator, so the table lost nothing.
    if (blockFullyCaptured(t.block_id, false)) continue;
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
    if (occ.some((o) => o.relation_marker === 'benign' || occurrenceDescribesBenign(c, o))) {
      flag(QUALITY_CODES.LEGITIMATE_MARKER_INDICATOR, c);
    }
    if (c.candidate_type === 'domain' && isUndelegatedWeakDomain(c.normalized_value)) flag(QUALITY_CODES.UNDELEGATED_SUFFIX_DOMAIN_INDICATOR, c);
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
    [QUALITY_CODES.INDICATOR_MISSING_PROVENANCE]: ['warning', 'Report Indicators without a source block or evidence span.'],
    [QUALITY_CODES.UNDELEGATED_SUFFIX_DOMAIN_INDICATOR]: ['warning', 'Report Indicator domains whose last label is not a delegated DNS suffix (system / code identifiers read as hosts?).']
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

  // --- 6. Indicators whose only authority is structural discovery ---
  // A body table with an IOC-shaped header or an unlabelled observable list
  // grants MODE A scope without a publisher heading. When the publisher also
  // has a headed IOC section, values found ONLY in such blocks are usually
  // analysis attributes (resolution IPs, triaged look-alike samples); with no
  // headed section they may be services the text names as legitimate.
  // A discovery block still governed by a publisher IOC opener (a sub-heading
  // closed the zone, discovery re-opened it) is the publisher appendix, not a
  // body attribute: an opener stays active until a non-authoritative heading
  // of the same or a higher level (level-less openers — PDF, bold paragraphs —
  // close only on a levelled heading).
  const governed = new Set();
  let opener = null;
  for (const b of blocks) {
    if (isChrome(b)) continue;
    const strong = STRONG_IOC_ZONES.has(String(b.zone || ''));
    if (strong && b.scope_opening_id === b.id) opener = { level: Number(b.level) || null };
    else if (opener && b.type === 'heading' && !strong && Number(b.level) && (!opener.level || Number(b.level) <= opener.level)) opener = null;
    if (opener) governed.add(b.id);
  }
  // Section-tree engine: membership authority follows heading ancestry, so a
  // discovery block nested under a publisher IOC heading (an H3 subgroup of the
  // "Indicators of Compromise" H2) is governed by that heading even where the
  // linear zone pass closed and re-opened the zone.
  if (diagnostics.scope_engine?.engine === 'section_tree' && blocks.length) {
    try {
      for (const tb of annotateSectionTree({ blocks, meta: input?.documentMeta || {} }).blocks || []) {
        if (tb?.id && tb.authoritative_ancestor_id) governed.add(tb.id);
      }
    } catch {
      // Diagnostics only: fall back to the linear reading.
    }
  }
  const isDiscoveryBlock = (b) => Boolean(b) && !b.scope_opening_id && !governed.has(b.id) &&
    STRUCTURAL_DISCOVERY_REASONS.has(String(b.zone_reason || ''));
  const discoveryOnly = [];
  let headedMembers = 0;
  for (const c of candidates) {
    if (!c.__member) continue;
    const strong = (c.occurrences || []).filter((o) => STRONG_IOC_ZONES.has(String(o.zone || '')) && o.block_id);
    if (!strong.length) continue;
    if (strong.every((o) => isDiscoveryBlock(blockById.get(o.block_id)))) discoveryOnly.push(c);
    else headedMembers += 1;
  }
  if (discoveryOnly.length) {
    const blockIds = [...new Set(discoveryOnly.flatMap((c) => (c.occurrences || []).map((o) => o.block_id).filter(Boolean)))]
      .filter((id) => isDiscoveryBlock(blockById.get(id)));
    const reasons = [...new Set(blockIds.map((id) => blockById.get(id)?.zone_reason).filter(Boolean))].sort();
    const headed = headedMembers > 0;
    push({
      code: QUALITY_CODES.INDICATORS_FROM_STRUCTURAL_DISCOVERY,
      severity: headed ? 'warning' : 'info',
      explanation: headed
        ? `${discoveryOnly.length} Indicators come only from body ${reasons.join(' / ')} blocks outside the publisher's headed ` +
          'IOC section; check they are publisher indicators, not analysis attributes or triaged look-alikes.'
        : `${discoveryOnly.length} Indicators come only from an unlabelled ${reasons.join(' / ')} (no publisher IOC heading); ` +
          'check the surrounding text does not describe them as legitimate services.',
      candidates: discoveryOnly.map(identity).sort(),
      block_ids: blockIds,
      section: { zone_reasons: reasons, headed_indicators: headedMembers },
      evidence: evidenceFor(blockIds)
    });
  }

  // --- 7. Row-shaped non-members still under an IOC / C2 section heading ---
  // Catches premature appendix closure and nested-list heading loss where only
  // one or two values fall out (below orphanRunMinValues) but the heading text
  // still names Indicators / C2 / samples.
  const APPENDIX_HEADING_RE =
    /\b(?:indicators?\s+of\s+compromise|indicators?|iocs?|compromise\s+indicators?|c2s?|c&c|command\s*(?:and|&)\s*control|samples?|hashes?|md5|sha-?1|sha-?256)\b/i;
  if (modeA) {
    const byHeading = new Map();
    for (const c of candidates) {
      if (!isScopeDependentNonMember(c)) continue;
      for (const o of c.occurrences || []) {
        if (!o.block_id || !rowLike(o)) continue;
        const z = String(o.zone || '');
        if (STRONG_IOC_ZONES.has(z) || NEGATIVE_ZONES.has(z) || z === 'header_footer') continue;
        const heading = String(o.section_heading || blockById.get(o.block_id)?.section_heading || '').trim();
        if (!heading || !APPENDIX_HEADING_RE.test(heading)) continue;
        if (!byHeading.has(heading)) byHeading.set(heading, { ids: new Set(), blocks: new Set() });
        byHeading.get(heading).ids.add(identity(c));
        byHeading.get(heading).blocks.add(o.block_id);
      }
    }
    for (const [heading, group] of byHeading) {
      if (group.ids.size < T.appendixHeadingNonmemberMinValues) continue;
      const blockIds = [...group.blocks];
      push({
        code: QUALITY_CODES.APPENDIX_HEADING_NONMEMBER_ROWS,
        severity: 'warning',
        explanation:
          `${group.ids.size} row-shaped IOC values sit under section heading "${heading}" but are outside every ` +
          'authoritative zone, so MODE A excludes them from Indicators. Nested list headings or a sibling ' +
          'sub-heading may have closed the publisher appendix early.',
        candidates: [...group.ids].sort(),
        block_ids: blockIds,
        section: { heading, zone: null },
        evidence: evidenceFor(blockIds)
      });
    }
  }

  // --- 8. Body tables that still grant Indicator membership outside a headed
  // appendix opener (structural discovery / residual self-proving). Analysis
  // tables that correctly withheld membership stay silent — P1 already demotes
  // Domain|IP|First seen style grids; warning only when Indicators remain.
  const hasHeadedAppendix = blocks.some(
    (b) =>
      (b.zone === 'explicit_ioc_section' || b.zone === 'sample_table' || b.zone === 'c2_section') &&
      (b.scope_opening_id === b.id || b.type === 'heading')
  );
  // Delegated scope (every headed appendix empty): body tables ARE the publisher
  // inventory there; check 13 reports that case instead.
  if (hasHeadedAppendix && diagnostics.scope_engine?.delegated_scope !== true) {
    for (const b of blocks) {
      if (b.type !== 'table' || !b.table || isChrome(b)) continue;
      // Tables already inside the publisher's headed IOC / C2 / sample appendix
      // are not "body" tables. operational_infrastructure stays eligible — it can
      // grant exclusive Indicators outside the headed appendix.
      if (
        b.zone === 'explicit_ioc_section' ||
        b.zone === 'c2_section' ||
        b.zone === 'sample_table'
      ) {
        continue;
      }
      const headerText = (b.table.headers || []).map((c) => String(c || '')).join(' ');
      const looksIocHeader =
        /\b(?:md5|sha-?1|sha-?256|sha-?512|domain|domains|url|urls|ip|ips|ipv4|ipv6|c2|indicator|hash|hashes|host|hosts)\b/i.test(
          headerText
        );
      if (!looksIocHeader) continue;
      const inTable = [...(iocByBlock.get(b.id) || [])];
      // Only identities whose Indicator membership depends on this body table
      // (every strong occurrence is this block, or the block is non-strong and
      // still the sole occurrence). Shared appendix duplicates do not count.
      const exclusiveMembers = inTable.filter((c) => {
        if (!c.__member) return false;
        const strong = (c.occurrences || []).filter((o) => STRONG_IOC_ZONES.has(String(o.zone || '')) && o.block_id);
        if (strong.length) return strong.every((o) => o.block_id === b.id);
        const all = (c.occurrences || []).filter((o) => o.block_id);
        return all.length > 0 && all.every((o) => o.block_id === b.id);
      });
      if (!exclusiveMembers.length) continue;
      push({
        code: QUALITY_CODES.BODY_IOC_TABLE_OUTSIDE_APPENDIX,
        severity: 'warning',
        explanation:
          `Body table under "${b.section_heading || 'unlabelled analysis'}" contributed ` +
          `${exclusiveMembers.length} Indicator(s) that do not also appear under the headed appendix — ` +
          'verify they are publisher-asserted, not analysis attributes.',
        candidates: exclusiveMembers.map(identity).sort(),
        block_ids: [b.id],
        section: { heading: b.section_heading || null, zone: b.zone || null, zone_reason: b.zone_reason || null },
        evidence: evidenceFor([b.id])
      });
    }
  }

  // --- 10. Observables written in authoritative IOC-table indicator cells
  // that never became candidates. Independent of membership: the cell text is
  // compared with the candidate set, so a value dropped before it ever was a
  // candidate (a cell read only as its leading file identity) is visible.
  const candidateValues = new Set(candidates.map((c) => String(c.normalized_value || '').toLowerCase()));
  const missingByTable = new Map();
  for (const b of blocks) {
    const interp = b?.ioc_table;
    if (b?.type !== 'table' || !interp || !STRONG_IOC_ZONES.has(String(b.zone || ''))) continue;
    if (interp.kind !== 'ioc_table' && interp.kind !== 'artifact_table') continue;
    // An artifact table returns before indicator_columns is set: read the intents.
    const cols = Array.isArray(interp.indicator_columns) && interp.indicator_columns.length
      ? interp.indicator_columns
      : (interp.columns || []).filter((c) => c.intent === 'indicator').map((c) => c.index);
    for (const row of interp.rows || []) {
      for (const col of cols) {
        for (const tok of cellObservableTokens(row.cells?.[col])) {
          if (candidateValues.has(tok)) continue;
          if (!missingByTable.has(b.id)) missingByTable.set(b.id, { ids: new Set(), heading: b.section_heading || null, zone: b.zone || null });
          missingByTable.get(b.id).ids.add(tok);
        }
      }
    }
  }
  for (const [blockId, m] of missingByTable) {
    push({
      code: QUALITY_CODES.TABLE_OBSERVABLE_NOT_EXTRACTED,
      severity: 'warning',
      explanation: `${m.ids.size} hash / IPv4 value(s) written in the indicator column of an IOC table under ` +
        `"${m.heading || m.zone}" never became candidates (a mixed cell may have been read only as its file name / path).`,
      candidates: [...m.ids].sort(),
      block_ids: [blockId],
      section: { heading: m.heading, zone: m.zone },
      evidence: evidenceFor([blockId])
    });
  }

  // --- 11. Content-inferred hash column beside a header-declared hash column.
  // A second hash-shaped column whose header names no hash type is usually an
  // attribute of the sample (certificate thumbprint / serial), not a sample.
  for (const b of blocks) {
    const interp = b?.ioc_table;
    if (b?.type !== 'table' || !interp || !Array.isArray(interp.columns)) continue;
    const typesByCol = new Map();
    for (const row of interp.rows || []) {
      for (const v of row.values || []) {
        if (!HASH_TYPES.has(String(v.candidate_type))) continue;
        if (!typesByCol.has(v.column_index)) typesByCol.set(v.column_index, new Set());
        typesByCol.get(v.column_index).add(v.candidate_type);
      }
    }
    const declared = interp.columns.filter((c) => c.intent === 'indicator' && c.method === 'header' && typesByCol.has(c.index));
    if (!declared.length) continue;
    const declaredTypes = new Set(declared.flatMap((c) => [...typesByCol.get(c.index)]));
    const inferred = interp.columns.filter(
      (c) => c.intent === 'indicator' && (c.method === 'content' || c.method === 'content_override') &&
        typesByCol.has(c.index) && [...typesByCol.get(c.index)].every((t) => !declaredTypes.has(t))
    );
    for (const col of inferred) {
      const ids = (interp.rows || []).flatMap((r) => (r.values || []).filter((v) => v.column_index === col.index).map((v) => `${v.candidate_type}:${v.normalized_value}`));
      push({
        code: QUALITY_CODES.CONTENT_INFERRED_HASH_COLUMN,
        severity: 'warning',
        explanation: `Column "${col.header || col.index}" was read as an indicator column from its content (${[...typesByCol.get(col.index)].join('/')}) ` +
          `beside the declared ${[...declaredTypes].join('/')} column; it may hold an attribute of the sample (e.g. a certificate thumbprint).`,
        candidates: [...new Set(ids)].sort(),
        block_ids: [b.id],
        section: { heading: b.section_heading || null, zone: b.zone || null },
        evidence: evidenceFor([b.id])
      });
    }
  }

  // --- 13. Delegated authority (every formal IOC section empty; section-tree) ---
  const scopeEngine = diagnostics.scope_engine || {};
  if (scopeEngine.delegated_scope === true) {
    const delegatedMembers = candidates.filter((c) => c.__member &&
      (c.occurrences || []).some((o) => o.zone === 'delegated_ioc_scope' && o.asserted === true));
    push({
      code: QUALITY_CODES.DELEGATED_AUTHORITY_APPLIED,
      severity: 'warning',
      explanation: 'Every formal Indicators-of-Compromise section of this report is empty (the publisher released its IOCs ' +
        `elsewhere). ${delegatedMembers.length} Indicator(s) come from the publisher's own assertions in the body ` +
        '(operational statements, endpoints, rows of network/indicator-typed table columns); narrative mentions stayed Context Only. ' +
        "Review them, and attach the publisher's IOC file as a linked IOC Source when it is available.",
      candidates: delegatedMembers.map(identity).sort(),
      block_ids: [],
      section: { heading: null, zone: 'delegated_ioc_scope' }
    });
  }

  // --- 14. Non-file digests reclassified (build-id / certificate / vhash / key / trivial digest) ---
  const digests = candidates.filter((c) => c.digest_kind);
  if (digests.length) {
    const kinds = [...new Set(digests.map((c) => c.digest_kind))].sort();
    push({
      code: QUALITY_CODES.NON_FILE_DIGEST_RECLASSIFIED,
      severity: 'info',
      explanation: `${digests.length} hash-shaped value(s) are labelled as ${kinds.join(', ')} by the publisher and were kept as ` +
        'context, not as file-hash Indicators.',
      candidates: digests.map((c) => `${c.digest_kind}:${c.normalized_value}`).sort(),
      block_ids: digests.flatMap((c) => (c.occurrences || []).map((o) => o.block_id)).filter(Boolean)
    });
  }

  // --- 15. Publisher stance conflict (legitimate / dual-use AND asserted) ---
  const conflicts = candidates.filter((c) => c.__member && c.stance_conflict === true);
  if (conflicts.length) {
    push({
      code: QUALITY_CODES.PUBLISHER_STANCE_CONFLICT,
      severity: 'warning',
      explanation: `${conflicts.length} Indicator(s) are asserted by the publisher in one place and described as legitimate / ` +
        'dual-use / not inherently malicious in another; the assertion keeps membership — review the publisher stance.',
      candidates: conflicts.map(identity).sort(),
      block_ids: conflicts.flatMap((c) => (c.occurrences || []).map((o) => o.block_id)).filter(Boolean)
    });
  }

  // --- 19. Directory URLs excluded as incomplete prefixes inside an IOC section ---
  const prefixExcluded = candidates.filter((c) => c.incomplete_url_prefix === true &&
    (c.occurrences || []).some((o) => STRONG_IOC_ZONES.has(String(o.zone || ''))));
  if (prefixExcluded.length) {
    push({
      code: QUALITY_CODES.IOC_SECTION_URL_PREFIX_EXCLUDED,
      severity: 'info',
      explanation: `${prefixExcluded.length} URL(s) ending in "/" are listed inside a publisher IOC section but were excluded as ` +
        'incomplete path prefixes of longer sibling URLs (they are not single-value IOC rows). Confirm the publisher did not ' +
        'intend the directory itself as an indicator.',
      candidates: prefixExcluded.map(identity).sort(),
      block_ids: prefixExcluded.flatMap((c) => (c.occurrences || []).map((o) => o.block_id)).filter(Boolean)
    });
  }

  // --- 20. Table reference columns (tool homepage / download / source links) ---
  const referenceContext = candidates.filter((c) => c.policy_decision === 'context_only_reference_column');
  if (referenceContext.length) {
    push({
      code: QUALITY_CODES.REFERENCE_COLUMN_CONTEXT,
      severity: 'info',
      explanation: `${referenceContext.length} link(s) from a table reference column (where a listed tool is published) were ` +
        'kept as Context Only, not as actor infrastructure.',
      candidates: referenceContext.map(identity).sort(),
      block_ids: referenceContext.flatMap((c) => (c.occurrences || []).map((o) => o.block_id)).filter(Boolean)
    });
  }
  const referenceMembers = candidates.filter((c) => c.__member &&
    (c.table_rows || []).length > 0 &&
    (c.table_rows || []).every((r) => REFERENCE_HEADER_RE.test(String(r.column_header || '').trim())));
  if (referenceMembers.length) {
    push({
      code: QUALITY_CODES.REFERENCE_COLUMN_INDICATOR,
      severity: 'warning',
      explanation: `${referenceMembers.length} Indicator(s) come only from a table column whose header names a reference / ` +
        'source / download link; check that the publisher attributes them to the actor rather than citing where a tool is published.',
      candidates: referenceMembers.map(identity).sort(),
      block_ids: referenceMembers.flatMap((c) => (c.table_rows || []).map((r) => r.table_id)).filter(Boolean)
    });
  }

  // --- 21. File-hash Indicators described as keys / certificates / fingerprints / banner hashes ---
  const digestSuspects = candidates.filter((c) => {
    if (!c.__member || !HASH_TYPES.has(String(c.candidate_type))) return false;
    const texts = [
      ...(c.table_rows || []).map((r) => r.description || ''),
      ...(c.occurrences || []).map((o) => o.surrounding_text || '')
    ].filter(Boolean);
    return texts.some((t) => NON_FILE_DIGEST_WORDS_RE.test(t) && !FILE_SUBJECT_RE.test(t.replace(NON_FILE_DIGEST_WORDS_RE, ' ')));
  });
  if (digestSuspects.length) {
    push({
      code: QUALITY_CODES.NON_FILE_DIGEST_SUSPECT,
      severity: 'warning',
      explanation: `${digestSuspects.length} file-hash Indicator(s) sit in a row / sentence that calls the digest a key, ` +
        'certificate, fingerprint or banner hash and names no file; such digests identify no sample, review the hash type.',
      candidates: digestSuspects.map(identity).sort(),
      block_ids: digestSuspects.flatMap((c) => (c.occurrences || []).map((o) => o.block_id)).filter(Boolean)
    });
  }

  // --- 22. Downloadable IOC package announced by the publisher ---
  const packageBlocks = blocks.filter((b) => IOC_PACKAGE_LEAD_IN_RE.test(refangTextForExtraction(String(b.text || ''))));
  if (packageBlocks.length) {
    push({
      code: QUALITY_CODES.IOC_PACKAGE_ANNOUNCED,
      severity: 'info',
      explanation: 'The publisher announces a downloadable IOC package (STIX / JSON / CSV / repository). It may hold indicators ' +
        'or hash types the page does not list; it is reviewed as a linked IOC Source (never ingested automatically).',
      candidates: [],
      block_ids: packageBlocks.map((b) => b.id),
      evidence: evidenceFor(packageBlocks.map((b) => b.id))
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
 * Divergence causes of check 9. `analyst_promotion` / `analyst_exclusion` are
 * explicit, recorded analyst decisions; `unexplained` means replay changed
 * membership with no such decision (a reconciliation defect).
 */
export const REPLAY_DIVERGENCE_CAUSES = Object.freeze({
  ANALYST_PROMOTION: 'analyst_promotion',
  ANALYST_EXCLUSION: 'analyst_exclusion',
  UNEXPLAINED: 'unexplained'
});

const identityOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const memberOf = (c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) });

/**
 * Check 9: membership divergence between the deterministic publisher reading
 * and the candidate set after analyst-state replay. Pure; never changes
 * candidates. Returns null when the two agree.
 * @param {{ deterministic: object[], final: object[], previousRows?: object[] }} input
 */
export function assessReplayMembershipDivergence({ deterministic, final, previousRows = [] }) {
  const priorByKey = new Map((previousRows || []).map((r) => [identityOf(r), r]));
  const det = new Map((deterministic || []).map((c) => [identityOf(c), memberOf(c)]));
  const C = REPLAY_DIVERGENCE_CAUSES;
  const items = [];
  for (const c of final || []) {
    const k = identityOf(c);
    if (!det.has(k)) continue;
    const before = det.get(k);
    const after = memberOf(c);
    if (before === after) continue;
    const prior = priorByKey.get(k) || null;
    const ev = prior?.evidence && typeof prior.evidence === 'object' ? prior.evidence : {};
    const review = String(prior?.review_status || 'pending').toLowerCase();
    let cause = C.UNEXPLAINED;
    if (after && ev.promoted_from && typeof ev.promoted_from === 'object' && review === 'approved') cause = C.ANALYST_PROMOTION;
    else if (!after && review === 'context_only') cause = C.ANALYST_EXCLUSION;
    items.push({ identity: k, direction: after ? 'added_by_replay' : 'removed_by_replay', cause });
  }
  if (!items.length) return null;
  const unexplained = items.filter((x) => x.cause === C.UNEXPLAINED);
  const count = (cause) => items.filter((x) => x.cause === cause).length;
  const parts = [
    count(C.ANALYST_PROMOTION) ? `${count(C.ANALYST_PROMOTION)} kept as Indicator(s) by an explicit analyst promotion` : null,
    count(C.ANALYST_EXCLUSION) ? `${count(C.ANALYST_EXCLUSION)} publisher Indicator(s) excluded by an analyst Context Only decision` : null,
    unexplained.length ? `${unexplained.length} changed by replayed state with no analyst decision that explains it` : null
  ].filter(Boolean);
  return {
    code: QUALITY_CODES.ANALYST_STATE_MEMBERSHIP_DIVERGENCE,
    severity: unexplained.length ? 'warning' : 'info',
    explanation: `Indicators differ from the publisher reading after analyst decisions were re-applied: ${parts.join('; ')}. Nothing was changed.`,
    candidates: (unexplained.length ? unexplained : items).map((x) => x.identity).sort(),
    candidate_count: items.length,
    divergence: {
      added_by_replay: items.filter((x) => x.direction === 'added_by_replay').length,
      removed_by_replay: items.filter((x) => x.direction === 'removed_by_replay').length,
      causes: Object.fromEntries(Object.values(C).map((cause) => [cause, count(cause)]))
    }
  };
}

/**
 * Quality record with check 9 merged in (counts / status recomputed). Returns
 * the input unchanged when there is no divergence (or no quality record).
 * @param {object|null} quality assessExtractionQuality result
 * @param {{ deterministic: object[], final: object[], previousRows?: object[] }} input
 */
export function withReplayMembershipDivergence(quality, input) {
  if (!quality || typeof quality !== 'object') return quality;
  // Idempotent: a record that already carries check 9 is re-derived, not appended to.
  const code = QUALITY_CODES.ANALYST_STATE_MEMBERSHIP_DIVERGENCE;
  const stale = (quality.warnings || []).filter((x) => x.code === code);
  if (stale.length) {
    const counts = { ...(quality.counts || { high: 0, warning: 0, info: 0 }) };
    for (const x of stale) counts[x.severity] = Math.max(0, (counts[x.severity] || 0) - 1);
    quality = {
      ...quality,
      counts,
      status: counts.high ? 'high' : counts.warning ? 'warning' : counts.info ? 'info' : 'clean',
      warnings: (quality.warnings || []).filter((x) => x.code !== code),
      warnings_total: Math.max(0, (quality.warnings_total ?? (quality.warnings || []).length) - stale.length)
    };
  }
  const w = assessReplayMembershipDivergence(input);
  if (!w) return quality;
  const warning = {
    code: w.code,
    severity: w.severity,
    explanation: w.explanation,
    candidates: w.candidates.slice(0, T.maxListedCandidates),
    candidate_count: w.candidate_count,
    block_ids: [],
    section: null,
    evidence: [],
    divergence: w.divergence,
    extractor_version: quality.extractor_versions || null
  };
  const warnings = [...(quality.warnings || []), warning]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.code.localeCompare(b.code));
  const counts = { ...(quality.counts || { high: 0, warning: 0, info: 0 }) };
  counts[w.severity] = (counts[w.severity] || 0) + 1;
  const status = counts.high ? 'high' : counts.warning ? 'warning' : counts.info ? 'info' : 'clean';
  return {
    ...quality,
    status,
    counts,
    warnings: warnings.slice(0, T.maxWarnings),
    warnings_total: (quality.warnings_total ?? (quality.warnings || []).length) + 1
  };
}

const POST_MERGE_CODES = Object.freeze([
  QUALITY_CODES.AI_EVIDENCE_UNGROUNDED,
  QUALITY_CODES.AI_ESCALATION_UNSUPPORTED,
  QUALITY_CODES.MALICIOUS_ASSESSED_NON_MEMBERS,
  QUALITY_CODES.AI_DEMOTED_TABLE_ROWS
]);

/**
 * Checks 16–18 on the candidate set AFTER the model merge (pipeline and
 * Refresh extraction): model quotes that were rejected because they are not
 * in the document, model escalations that were not applied for lack of
 * publisher support, and malicious-assessed candidates that stay outside the
 * Indicators set (explains MODE A suppression). Diagnostic only.
 * @param {object[]} candidates merged candidates
 * @returns {object[]} warnings
 */
export function assessPostMergeQuality(candidates) {
  const list = Array.isArray(candidates) ? candidates : [];
  const out = [];
  const rejected = list.filter((c) => c.ai_evidence_rejected);
  if (rejected.length) {
    out.push({
      code: QUALITY_CODES.AI_EVIDENCE_UNGROUNDED,
      severity: 'info',
      explanation: `${rejected.length} model evidence quote(s) do not occur in the report text; the publisher excerpt was kept ` +
        'and the model text is stored only as a rejected suggestion.',
      candidates: rejected.map(identityOf).sort()
    });
  }
  const unsupported = list.filter((c) => c.ai_classification && c.ai_classification.applied === false);
  if (unsupported.length) {
    out.push({
      code: QUALITY_CODES.AI_ESCALATION_UNSUPPORTED,
      severity: 'warning',
      explanation: `${unsupported.length} model malicious / suspicious label(s) cite no publisher text naming the value and were not applied.`,
      candidates: unsupported.map(identityOf).sort()
    });
  }
  // Check 23: a model Context Only decision on table rows whose sibling rows
  // (same table, same type) are Indicators: the MODE B split where a
  // structured inventory degraded to row-by-row model reading.
  const tableIdsOf = (c) => [...new Set((c.occurrences || [])
    .filter((o) => o.block_type === 'table' || o.form === 'table_row')
    .map((o) => o.block_id)
    .filter(Boolean))];
  const memberTables = new Set();
  for (const c of list) if (memberOf(c)) for (const t of tableIdsOf(c)) memberTables.add(`${t}\0${c.candidate_type}`);
  const demotedRows = list.filter((c) => c.decision_source === 'ai' && c.assessment === 'context_only' && c.is_ioc !== false &&
    !memberOf(c) && tableIdsOf(c).some((t) => memberTables.has(`${t}\0${c.candidate_type}`)));
  if (demotedRows.length) {
    out.push({
      code: QUALITY_CODES.AI_DEMOTED_TABLE_ROWS,
      severity: 'warning',
      explanation: `${demotedRows.length} table row value(s) were set to Context Only by the model while other rows of the same ` +
        'table and type are Indicators. A publisher inventory read row by row can split arbitrarily: review the table as a whole.',
      candidates: demotedRows.map(identityOf).sort()
    });
  }
  const suppressed = list.filter((c) =>
    (c.assessment === 'malicious' || c.assessment === 'suspicious') && c.is_ioc !== false && !memberOf(c));
  if (suppressed.length) {
    out.push({
      code: QUALITY_CODES.MALICIOUS_ASSESSED_NON_MEMBERS,
      severity: 'info',
      explanation: `${suppressed.length} candidate(s) are assessed malicious but are not report Indicators: the publisher curated ` +
        'its IOC set (MODE A) and does not assert these values there. They stay visible under All for review.',
      candidates: suppressed.map(identityOf).sort()
    });
  }
  return out;
}

/**
 * Quality record with checks 16–18 merged in (idempotent; counts / status recomputed).
 * @param {object|null} quality
 * @param {object[]} candidates merged candidates
 */
export function withPostMergeQuality(quality, candidates) {
  if (!quality || typeof quality !== 'object') return quality;
  const kept = (quality.warnings || []).filter((w) => !POST_MERGE_CODES.includes(w.code));
  const added = assessPostMergeQuality(candidates).map((w) => ({
    code: w.code,
    severity: w.severity,
    explanation: w.explanation,
    candidates: w.candidates.slice(0, T.maxListedCandidates),
    candidate_count: w.candidates.length,
    block_ids: [],
    section: null,
    evidence: [],
    extractor_version: quality.extractor_versions || null
  }));
  const warnings = [...kept, ...added]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.code.localeCompare(b.code));
  const counts = { high: 0, warning: 0, info: 0 };
  for (const w of warnings) counts[w.severity] = (counts[w.severity] || 0) + 1;
  const removed = (quality.warnings || []).length - kept.length;
  return {
    ...quality,
    status: counts.high ? 'high' : counts.warning ? 'warning' : counts.info ? 'info' : 'clean',
    counts,
    warnings: warnings.slice(0, T.maxWarnings),
    warnings_total: Math.max(0, (quality.warnings_total ?? (quality.warnings || []).length) - removed) + added.length
  };
}

/**
 * Stored quality record of a report row (analysis_progress.extraction_diagnostics.quality),
 * or null when the report predates tl-quality-v1 (filled by the next import / Refresh extraction).
 * @param {{ analysis_progress?: object|null }|null|undefined} row
 */
export function storedExtractionQuality(row) {
  const q = row?.analysis_progress?.extraction_diagnostics?.quality;
  return q && typeof q === 'object' ? q : null;
}

/**
 * Client summary without parser internals (status, counts, reason codes).
 * @param {object|null|undefined} quality stored / computed quality record
 */
export function extractionQualitySummary(quality) {
  if (!quality || typeof quality !== 'object') return null;
  const warnings = Array.isArray(quality.warnings) ? quality.warnings : [];
  return {
    version: quality.version || null,
    status: quality.status || 'clean',
    mode: quality.mode || null,
    counts: quality.counts || { high: 0, warning: 0, info: 0 },
    codes: [...new Set(warnings.map((w) => w.code).filter(Boolean))],
    warnings_total: quality.warnings_total ?? warnings.length
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
      ...(w.divergence ? { divergence: w.divergence } : {}),
      extractor_version: w.extractor_version || null
    }))
  };
}
