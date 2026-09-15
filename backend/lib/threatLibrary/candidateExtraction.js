/**
 * Deterministic IOC / identifier candidate extraction from canonical documents.
 *
 * Model: a candidate is an observable identity (type + normalized value) that
 * aggregates source OCCURRENCES. Every occurrence points at a real text span in
 * a canonical block. Parser-derived facts about a value (the host of a URL, the
 * port of an IP:port endpoint) are kept as `parsed` metadata on that candidate
 * and never become occurrences of another candidate. A standalone host
 * candidate therefore only exists when the report itself mentions the host
 * outside URL syntax (independent evidence).
 *
 * Typed indicator tables (canonical `table` blocks interpreted by
 * tableSemantics) are extracted row by row: the indicator cell is the
 * assertion, the declared-type cell is a typing hint, the description cell is
 * provenance. A value that appears only inside a description cell is related
 * context of that row, never a standalone candidate (same rule as URL hosts).
 */

import { normalizeObservable } from '../observable-normalization.js';
import { isValidIpAddress } from '../publicIp.js';
import { refangObservable, refangTextForExtraction } from './defang.js';
import { annotateDocumentZones, NEGATIVE_ZONES, STRONG_IOC_ZONES } from './documentZones.js';
import {
  resolveDottedTokenType,
  hostnameFromUrl,
  pathBasenameFromUrl
} from './candidateTyping.js';
import { applyEvidencePolicy } from './evidencePolicy.js';
import { isObservableOnlyLine } from './pdfLayout.js';
import { normalizeCandidateValue } from './candidateValue.js';
import { parseIndicatorCell } from './tableSemantics.js';
import { discoverDocumentIndicatorScope, isIndicatorRowShape } from './indicatorScope.js';
import {
  NON_NETWORK_RESOLVED_TYPES,
  RESOLVED_TYPES,
  buildTypeResolutionRecord,
  validateCanonicalIocValue,
  validateUrlCandidate
} from './observableTypeResolver.js';

export { normalizeCandidateValue } from './candidateValue.js';

/**
 * Bump when derivation / evidence semantics change. Older candidate sets are
 * rebuilt from the canonical document on the next analysis run.
 * v5: source-scope promotion (authoritative indicator sections vs narrative
 * context), provider/service relation, CIDR as a first-class candidate type.
 * v6: central observable-type resolver — dotted technical identifiers
 * (mutex / class / config keys) and relative paths / routes are never domain /
 * URL candidates; they are retained as non-IOC `technical_artifact` /
 * `relative_path` / `file_path` context with an explainable `type_resolution`
 * record; canonical-shape gate on every network candidate; declared-type
 * sub-headings ("Domain", "IP Addresses") continue an open IOC section.
 * v7: section scope model — descriptive indicator headings open a confirmed
 * authoritative section, sub-labelled short groups inherit it, and every
 * occurrence carries a structural kind (row vs narrative) + relation marker so
 * zone membership alone never asserts maliciousness; scheme-less host/path
 * resources are one URL occurrence (exact source spelling, no invented scheme,
 * path preserved, host as parsed metadata).
 */
export const THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION = 'tl-candidates-v7';

/**
 * Relation classification must see the clause around THIS observable, not the
 * first 280 characters of a long PDF paragraph (which may be a different
 * sentence, or a running footer glued onto a C2 discussion).
 * @param {string} text
 * @param {string} value
 */
export function surroundingWindow(text, value, radius = 140) {
  const hay = String(text || '');
  if (!hay) return null;
  const needles = [...new Set([
    String(value || ''),
    String(value || '').replace(/\./g, '[.]'),
    String(value || '').replace(/\[\.\]/g, '.')
  ])].filter(Boolean);
  const low = hay.toLowerCase();
  let idx = -1;
  let nlen = 0;
  for (const n of needles) {
    const i = low.indexOf(String(n).toLowerCase());
    if (i >= 0) {
      idx = i;
      nlen = String(n).length;
      break;
    }
  }
  if (idx < 0) return hay.slice(0, Math.min(280, hay.length));
  const start = Math.max(0, idx - radius);
  return hay.slice(start, idx + nlen + radius);
}

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b/g;
const IPV4_PORT_RE = /\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))[:：](\d{1,5})\b/g;
const IPV6_RE = /\b(?:(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:)\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"'`)\]]+/gi;
/**
 * Scheme-less network resource: DNS-shaped host + path ("js.cache-mcp.com/layer.js").
 * The publisher gave no scheme, so none is invented: the exact host/path is
 * the value. Not preceded by a scheme separator, "@" or another label.
 */
const HOST_PATH_RE = /(?<![\w@:\/.\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?::\d{1,5})?(\/[^\s<>"'`)\]，。；]+)/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b/gi;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

const MAX_TABLE_ROWS_PER_CANDIDATE = 20;

export const OCCURRENCE_FORMS = Object.freeze({
  STANDALONE: 'standalone',
  URL: 'url',
  IP_PORT: 'ip_port',
  LIST_ROW: 'list_row',
  TABLE_ROW: 'table_row'
});

function stripUrlTrailingPunct(urlish) {
  return String(urlish || '').replace(/[),.;:!?\]。，；]+$/g, '');
}

/**
 * The publisher's own spelling of a refanged token (defanged host dots kept),
 * so evidence shows "js.cache-mcp[.]com/layer.js" rather than a rewritten form.
 * @param {string} blockText
 * @param {string} refanged
 * @param {string} host
 */
function sourceSpelling(blockText, refanged) {
  const hay = String(blockText || '');
  if (hay.includes(refanged)) return refanged;
  // Publishers defang any subset of the dots ("js.cache-mcp[.]com/layer.js"):
  // every "." may appear as ".", "[.]", "(.)" or "{.}" in the source.
  const pattern = String(refanged)
    .replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&')
    .replace(/\\\./g, '(?:\\.|\\[\\.\\]|\\(\\.\\)|\\{\\.\\})');
  try {
    const m = hay.match(new RegExp(pattern, 'i'));
    if (m) return m[0];
  } catch {
    /* fall through */
  }
  return refanged;
}

/**
 * Parse port from an http(s) URL when explicitly present.
 * @param {string} url
 */
function portFromUrl(url) {
  try {
    const u = new URL(String(url));
    return u.port ? Number(u.port) : null;
  } catch {
    return null;
  }
}

/**
 * @param {Array<[number, number]>} spans
 * @param {number} start
 * @param {number} end
 */
function insideAnySpan(spans, start, end) {
  for (const [s, e] of spans) {
    if (start >= s && end <= e) return true;
  }
  return false;
}

/**
 * Candidate key used everywhere (DB unique constraint mirrors it).
 * @param {string} type
 * @param {string} value
 */
export function candidateKey(type, value) {
  return `${type}\0${value}`;
}

/**
 * Values mentioned inside a description cell (related context, not assertions).
 * @param {string|null} description
 */
function relatedValuesFromDescription(description) {
  if (!description) return [];
  const parsed = parseIndicatorCell(description, null);
  return parsed.values
    .filter((v) => v.is_ioc !== false)
    .filter((v) => v.candidate_type !== 'domain' || v.normalized_value.includes('.'))
    .map((v) => (v.port ? `${v.normalized_value}:${v.port}` : v.normalized_value))
    .slice(0, 8);
}

/**
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 * @param {{ sourceUrl?: string|null }} [opts]
 * @returns {{ candidates: object[], diagnostics: object }}
 */
export function extractCandidatesWithDiagnostics(doc, opts = {}) {
  const sourceUrl = opts.sourceUrl || doc.meta?.source_url || doc.meta?.sourceUrl || null;
  let sourceHost = '';
  try {
    if (sourceUrl) sourceHost = hostnameFromUrl(sourceUrl);
  } catch {
    sourceHost = '';
  }
  const normalizedSourceUrl = sourceUrl ? normalizeObservable('url', refangObservable(sourceUrl)) : null;

  const annotated = annotateDocumentZones(doc, { sourceUrl, sourceHost });
  const documentScope = discoverDocumentIndicatorScope(annotated.blocks || []);
  /** @type {Map<string, object>} */
  const byKey = new Map();
  const urlPathBasenames = new Set();
  const knownUrlHosts = new Set();
  /** host → Set<url candidate key> (parser-derived metadata index, not occurrences) */
  const urlHostIndex = new Map();
  if (sourceHost) knownUrlHosts.add(sourceHost.toLowerCase());

  const diagnostics = {
    extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
    explicit_tables: {
      tables_seen: 0,
      ioc_tables: 0,
      explicit_tables: 0,
      rows_seen: 0,
      rows_valid: 0,
      rows_rejected: 0,
      values_asserted: 0,
      candidates_created: 0,
      rejection_reasons: {},
      inconsistent: false,
      missing_identities: [],
      tables: []
    },
    /** Observable-type resolution: what the syntax guessed vs what the source supports. */
    type_resolution: {
      syntactic_occurrences: 0,
      network_ioc_candidates: 0,
      artifact_candidates: 0,
      artifact_occurrences_dropped: 0,
      relative_paths: 0,
      canonical_rejections: 0,
      rejected_values: {},
      excluded_reasons: {},
      examples: [],
      /** Host/path resources written without a scheme: preserved verbatim as URL values. */
      scheme_less_resources: { count: 0, rejected: {}, examples: [] }
    }
  };
  const typeDiag = diagnostics.type_resolution;
  const countReason = (bucket, reason) => {
    bucket[reason] = (bucket[reason] || 0) + 1;
  };
  const rememberExample = (record) => {
    if (typeDiag.examples.length < 24) typeDiag.examples.push(record);
  };
  /** identities asserted by explicit tables → must exist as candidates */
  const explicitTableKeys = new Set();

  function occurrenceFor(block, extra = {}, focusValue = '') {
    const zone = block?.zone || 'unknown';
    const text = extra.rowText || (block?.text ? String(block.text) : null);
    const focus = extra.originalValue || focusValue;
    const form = extra.form || OCCURRENCE_FORMS.STANDALONE;
    // Structural reading is decided here, where the whole block is visible:
    // row placement (list / table / observable-row layout / discovered list)
    // or a short "value – note" / "label: value" line.
    const structuralRow =
      form === OCCURRENCE_FORMS.TABLE_ROW ||
      form === OCCURRENCE_FORMS.LIST_ROW ||
      form === OCCURRENCE_FORMS.IP_PORT ||
      block?.type === 'list_item' ||
      block?.layout === 'observable_row' ||
      block?.zone_reason === 'observable_list' ||
      block?.zone_reason === 'cidr_list' ||
      block?.zone_reason === 'ioc_table';
    const rowShape = !structuralRow && text ? isIndicatorRowShape(text, focus || focusValue) : false;
    return {
      block_id: block?.id || null,
      page: block?.page ?? null,
      zone,
      zone_reason: block?.zone_reason || null,
      scope_opening_id: block?.scope_opening_id || null,
      section_kind: zone,
      section_heading: block?.section_heading || null,
      block_type: block?.type || null,
      layout: block?.layout || null,
      form,
      structural_row: structuralRow,
      row_shape: rowShape,
      port: extra.port ?? null,
      table_row: extra.tableRow ? extra.tableRow.row_index : null,
      surrounding_text: text ? surroundingWindow(text, focus) : null,
      typing_reason: extra.typingReason || null
    };
  }

  function pushOccurrence(entry, block, extra = {}) {
    const occ = occurrenceFor(block, extra, entry.normalized_value || entry.original_value);
    if (!Array.isArray(entry.occurrences)) entry.occurrences = [];
    const dup = entry.occurrences.find(
      (o) => o.block_id && o.block_id === occ.block_id && (o.table_row == null || o.table_row === occ.table_row)
    );
    if (dup) {
      // Same block: keep one occurrence but remember a stronger assertion form / port.
      if (occ.port != null && dup.port == null) dup.port = occ.port;
      if (dup.form === OCCURRENCE_FORMS.STANDALONE && occ.form !== OCCURRENCE_FORMS.STANDALONE) dup.form = occ.form;
      if (occ.port != null) rememberPort(entry, occ.port);
      return;
    }
    entry.occurrences.push(occ);
    if (occ.port != null) rememberPort(entry, occ.port);
  }

  function rememberPort(entry, port) {
    if (!Array.isArray(entry.parsed.ports)) entry.parsed.ports = [];
    if (!entry.parsed.ports.includes(port)) entry.parsed.ports.push(port);
  }

  function evidenceTextFor(block, extra = {}) {
    if (extra.rowText) return String(extra.rowText).slice(0, 500);
    if (!block?.text) return null;
    const text = String(block.text).slice(0, 500);
    if ((block.type === 'list_item' || block.layout === 'observable_row') && block.section_heading) {
      return `${String(block.section_heading).slice(0, 80)}: ${text}`.slice(0, 500);
    }
    return text;
  }

  /**
   * Create-or-get the candidate entry for a resolved identity and attach one
   * occurrence (row provenance, evidence anchor preference).
   * @param {object} spec
   */
  function materialize(spec) {
    const { candidateType, normalizedValue, originalValue, n, block, extra, typingMeta, isIoc, artifactKind, typingSignals, syntaxGuess } = spec;
    const zone = block?.zone || 'unknown';
    const key = candidateKey(candidateType, normalizedValue);
    let entry = byKey.get(key);
    if (!entry) {
      entry = {
        candidate_type: candidateType,
        original_value: originalValue,
        normalized_value: normalizedValue,
        assessment: isIoc && !n.likelyContextOnly ? 'unknown' : 'context_only',
        role: n.likelyContextOnly ? (n.reservedAddress ? 'reference' : 'legitimate_service') : isIoc ? 'unknown' : 'reference',
        confidence: n.likelyContextOnly ? 0.75 : null,
        evidence_text: evidenceTextFor(block, extra),
        block_id: block?.id || null,
        page_number: block?.page ?? null,
        section: zone,
        zone,
        is_ioc: isIoc,
        resolved_type: typingMeta.resolved_type || candidateType,
        typing_reason: typingMeta.typing_reason || null,
        artifact_kind: isIoc ? null : artifactKind || null,
        syntax_guess: syntaxGuess,
        typing_signals: typingSignals || null,
        occurrences: [],
        parsed: n.parsed && typeof n.parsed === 'object' ? { ...n.parsed } : {},
        table_rows: [],
        derived_from: null,
        is_direct_source_observable: true,
        is_parser_derived_metadata: false,
        extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
      };
      if (n.likelyContextOnly && !n.reservedAddress) entry.rfc_example = true;
      if (n.reservedAddress) entry.reserved_address = true;
      // Report's own source URL / host is provenance, never a finding.
      if (
        (candidateType === 'domain' && sourceHost && normalizedValue === sourceHost) ||
        (candidateType === 'url' && normalizedSourceUrl && normalizedValue === normalizedSourceUrl)
      ) {
        entry.is_report_source = true;
      }
      byKey.set(key, entry);
    }
    pushOccurrence(entry, block, { ...extra, typingReason: typingMeta.typing_reason || null });
    if (extra.tableRow && entry.table_rows.length < MAX_TABLE_ROWS_PER_CANDIDATE) {
      entry.table_rows.push(extra.tableRow);
    }
    // Prefer strong-zone evidence text / anchor block
    const anchorIsStrong = STRONG_IOC_ZONES.has(entry.zone);
    if (STRONG_IOC_ZONES.has(block?.zone) && (block?.text || extra.rowText) && !anchorIsStrong) {
      entry.evidence_text = evidenceTextFor(block, extra);
      entry.block_id = block.id;
      entry.page_number = block.page ?? null;
      entry.section = block.zone;
      entry.zone = block.zone;
      if (extra.originalValue) entry.original_value = extra.originalValue;
    } else if (NEGATIVE_ZONES.has(entry.zone) && !NEGATIVE_ZONES.has(block?.zone) && block?.text) {
      // Body mention beats a footer/reference anchor for display purposes
      entry.evidence_text = evidenceTextFor(block, extra);
      entry.block_id = block.id;
      entry.page_number = block.page ?? null;
      entry.section = block.zone || 'unknown';
      entry.zone = block.zone || 'unknown';
    }
    return entry;
  }

  /**
   * Dotted tokens are typed once per document: every occurrence is resolved
   * against its own context (label, clause, zone, form) and the readings are
   * weighed together, so "Exploit.in" mentioned beside the word "module" in
   * one sentence does not split the same token into two identities.
   * @type {Map<string, { token: string, occurrences: object[] }>}
   */
  const pendingDotted = new Map();

  /**
   * @param {string} raw
   * @param {string|null} hintType
   * @param {object} block
   * @param {{ form?: string, port?: number|null, typing?: object, originalValue?: string, tableRow?: object, rowText?: string, typeLabel?: string|null, declaredType?: string|null, explicitTable?: boolean }} [extra]
   */
  function add(raw, hintType, block, extra = {}) {
    typeDiag.syntactic_occurrences += 1;
    const n = normalizeCandidateValue(raw, hintType);
    if (!n.ok) {
      countReason(typeDiag.rejected_values, n.error || 'unrecognized');
      return null;
    }
    const typingMeta = { ...(extra.typing || {}) };
    const zone = block?.zone || 'unknown';
    const strongZone = STRONG_IOC_ZONES.has(zone);

    // Dotted tokens: resolve per occurrence, decide per document (see pendingDotted).
    if (n.candidateType === 'domain') {
      const token = String(extra.originalValue || n.originalValue || raw).trim().replace(/\.$/, '');
      const typed = resolveDottedTokenType(token, {
        surroundingText: surroundingWindow(extra.rowText || block?.text || '', token, 160),
        typeLabel: extra.typeLabel || block?.type_label || null,
        declaredType: extra.declaredType || block?.declared_type_label || null,
        zone,
        blockType: block?.type || null,
        form: extra.form || OCCURRENCE_FORMS.STANDALONE,
        strongZone,
        urlPathBasenames,
        knownUrlHosts
      });
      if (typed.kind === 'skip') {
        countReason(typeDiag.rejected_values, typed.reason);
        return null;
      }
      const id = n.normalizedValue;
      if (!pendingDotted.has(id)) pendingDotted.set(id, { token, occurrences: [] });
      pendingDotted.get(id).occurrences.push({ n, block, extra, typed, token, strongZone });
      return { deferred: true, candidate_type: 'domain', normalized_value: n.normalizedValue, is_ioc: true, typed };
    }

    let candidateType = n.candidateType;
    let isIoc = n.isIoc !== false && candidateType !== 'cve' && candidateType !== 'attack_technique';
    let artifactKind = typingMeta.artifact_kind || null;
    const syntaxGuess = NON_NETWORK_RESOLVED_TYPES.has(candidateType)
      ? candidateType === RESOLVED_TYPES.TECHNICAL_ARTIFACT
        ? 'domain'
        : 'url'
      : candidateType;
    if (NON_NETWORK_RESOLVED_TYPES.has(candidateType)) {
      isIoc = false;
      typingMeta.resolved_type = candidateType;
      typingMeta.typing_reason = typingMeta.typing_reason || n.typingReason || null;
      artifactKind = artifactKind || (candidateType === RESOLVED_TYPES.TECHNICAL_ARTIFACT ? 'identifier' : 'path');
      countReason(typeDiag.excluded_reasons, typingMeta.typing_reason || candidateType);
    } else if (candidateType === 'url') {
      typingMeta.resolved_type = 'url';
      typingMeta.typing_reason = typingMeta.typing_reason || n.typingReason || 'absolute_url';
    }
    return materialize({
      candidateType,
      normalizedValue: n.normalizedValue,
      originalValue: extra.originalValue || n.originalValue,
      n,
      block,
      extra,
      typingMeta,
      isIoc,
      artifactKind,
      typingSignals: typingMeta.typing_signals || null,
      syntaxGuess
    });
  }

  /** Evidence weight of one occurrence reading (domain vs artifact). */
  const READING_WEIGHT = Object.freeze({
    declared_network_type: 100,
    mutex_label: 100, code_label: 100, config_label: 100, registry_label: 100, file_label: 100, path_label: 100,
    command_label: 100, process_label: 100, metadata_label: 100,
    network_relation: 50,
    single_instance_identifier_context: 50, inline_artifact_label: 50,
    url_host: 40, explicit_indicator_row: 40, url_path_basename: 40,
    code_identifier_shape: 30, code_context: 30, multi_dot_ext: 30, file_extension: 30, extension_without_host_context: 20,
    method_suffix: 30, code_block_weak_suffix: 20,
    network_context: 10, network_context_mixed_case: 10,
    artifact_context: 10, code_context_label: 10, config_context: 10, registry_context: 10, path_context: 10,
    command_context: 10, process_context: 10, metadata_context: 10, file_context: 10,
    hostname_shape: 1,
    no_network_semantics: 1
  });

  /**
   * Decide every deferred dotted token and materialize its candidate.
   */
  function resolvePendingDotted() {
    for (const [, pending] of pendingDotted) {
      let domainScore = 0;
      let artifactScore = 0;
      let best = null;
      for (const occ of pending.occurrences) {
        const w = READING_WEIGHT[occ.typed.reason] ?? 5;
        if (occ.typed.kind === 'domain') domainScore += w;
        else artifactScore += w;
        if (!best || w > best.w) best = { w, occ };
      }
      const isDomain = domainScore > artifactScore;
      const winning = pending.occurrences
        .filter((o) => (o.typed.kind === 'domain') === isDomain)
        .sort((a, b) => (READING_WEIGHT[b.typed.reason] ?? 5) - (READING_WEIGHT[a.typed.reason] ?? 5))[0] || best.occ;
      const typed = winning.typed;
      const labelled = pending.occurrences.some((o) => (o.typed.kind === 'domain') === isDomain && o.typed.labelled);
      const asserted = pending.occurrences.some(
        (o) => o.extra.form === OCCURRENCE_FORMS.TABLE_ROW || o.extra.form === OCCURRENCE_FORMS.LIST_ROW || o.strongZone
      );
      if (!isDomain) {
        countReason(typeDiag.excluded_reasons, typed.reason);
        const retain = labelled || asserted;
        if (!retain) {
          // Incidental identifiers in prose (bytes.Index, Foo.Bar.Baz) are not report intelligence.
          typeDiag.artifact_occurrences_dropped += pending.occurrences.length;
          rememberExample(
            buildTypeResolutionRecord({
              raw: pending.token,
              syntaxGuess: 'domain',
              resolvedType: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
              reason: typed.reason,
              promotion: 'excluded',
              signals: typed.signals
            })
          );
          continue;
        }
      }
      const candidateType = isDomain ? 'domain' : RESOLVED_TYPES.TECHNICAL_ARTIFACT;
      for (const occ of pending.occurrences) {
        const typingMeta = {
          ...(occ.extra.typing || {}),
          resolved_type: candidateType,
          typing_reason: typed.reason,
          occurrence_reason: occ.typed.reason
        };
        const entry = materialize({
          candidateType,
          normalizedValue: isDomain ? occ.n.normalizedValue : pending.token,
          originalValue: occ.extra.originalValue || occ.n.originalValue,
          n: occ.n,
          block: occ.block,
          extra: { ...occ.extra, typing: { ...(occ.extra.typing || {}), typing_reason: occ.typed.reason } },
          typingMeta: { ...typingMeta, typing_reason: typed.reason },
          isIoc: isDomain,
          artifactKind: isDomain ? null : typed.artifact_kind,
          typingSignals: typed.signals,
          syntaxGuess: 'domain'
        });
        // pushOccurrence recorded the document-level reason; keep the per-occurrence one too.
        const last = entry.occurrences[entry.occurrences.length - 1];
        if (last && last.block_id === (occ.block?.id || null)) last.typing_reason = occ.typed.reason;
        if (occ.extra.explicitTable && entry.is_ioc !== false) {
          explicitTableKeys.add(candidateKey(entry.candidate_type, entry.normalized_value));
        }
      }
      const entry = byKey.get(candidateKey(candidateType, isDomain ? pending.occurrences[0].n.normalizedValue : pending.token));
      if (entry) {
        entry.type_scores = { domain: domainScore, artifact: artifactScore };
      }
    }
    pendingDotted.clear();
  }

  const blocks = annotated.blocks || [];
  // Format-agnostic "indicator row": PDF list rows, HTML <li>/<td>, or any line that is a single observable.
  const isObservableRow = (block) =>
    block.type === 'list_item' ||
    block.layout === 'observable_row' ||
    ((block.type === 'list' || block.type === 'table') && isObservableOnlyLine(block.text || ''));

  /** Blocks handled row-by-row (typed indicator tables) — skipped by the regex passes. */
  const tableHandled = new Set();

  // Pass 0: typed indicator tables — every valid row is a source assertion with row provenance.
  for (const block of blocks) {
    if (block.type !== 'table' || !block.table) continue;
    const t = diagnostics.explicit_tables;
    t.tables_seen += 1;
    const interp = block.ioc_table;
    const summary = {
      table_id: block.id,
      page: block.page ?? null,
      zone: block.zone || null,
      section_heading: block.section_heading || null,
      kind: interp?.kind || 'not_ioc_table',
      explicit: Boolean(interp?.explicit),
      reason: interp?.reason || null,
      columns: Array.isArray(interp?.columns) ? interp.columns.map((c) => ({ index: c.index, header: c.header, intent: c.intent, method: c.method })) : [],
      rows_seen: interp?.stats?.rows_seen ?? 0,
      rows_valid: interp?.stats?.rows_valid ?? 0,
      rows_rejected: interp?.stats?.rows_rejected ?? 0,
      rejection_reasons: interp?.stats?.rejection_reasons || {},
      rejected_rows: []
    };
    t.tables.push(summary);
    if (!interp || (interp.kind !== 'ioc_table' && interp.kind !== 'artifact_table')) continue;
    if (interp.kind === 'ioc_table') t.ioc_tables += 1;
    if (interp.explicit) t.explicit_tables += 1;
    tableHandled.add(block.id);
    t.rows_seen += summary.rows_seen;
    t.rows_valid += summary.rows_valid;
    t.rows_rejected += summary.rows_rejected;
    for (const [reason, n] of Object.entries(summary.rejection_reasons)) {
      t.rejection_reasons[reason] = (t.rejection_reasons[reason] || 0) + n;
    }
    for (const row of interp.rows || []) {
      if (row.status !== 'valid') {
        if (summary.rejected_rows.length < 12) summary.rejected_rows.push({ row_index: row.row_index, reason: row.reason });
        continue;
      }
      const rowText = [row.type_cell, row.values[0]?.indicator_cell, row.description].filter(Boolean).join(' | ');
      const related = relatedValuesFromDescription(row.description);
      for (const v of row.values) {
        t.values_asserted += 1;
        const tableRow = {
          table_id: block.id,
          page: block.page ?? null,
          row_index: row.row_index,
          column_index: v.column_index,
          declared_type: v.declared_type || null,
          type_cell: row.type_cell,
          indicator_cell: v.indicator_cell,
          raw_value: v.raw,
          description: row.description,
          explicit: Boolean(interp.explicit),
          declared_type_mismatch: v.declared_type_mismatch === true || undefined,
          related_values: related.length ? related : undefined,
          resolved_type: v.resolved_type || v.candidate_type,
          typing_reason: v.typing_reason || undefined
        };
        const entry = add(v.refanged, v.candidate_type, block, {
          form: OCCURRENCE_FORMS.TABLE_ROW,
          port: v.port ?? null,
          originalValue: v.raw,
          tableRow,
          rowText,
          typeLabel: row.type_cell || null,
          declaredType: v.declared_type || null,
          typing: {
            typing_reason: v.typing_reason || null,
            artifact_kind: v.artifact_kind || null,
            typing_signals: v.typing_signals || null
          },
          explicitTable: Boolean(interp.explicit)
        });
        if (entry && !entry.deferred && interp.explicit && entry.is_ioc !== false) {
          explicitTableKeys.add(candidateKey(entry.candidate_type, entry.normalized_value));
        }
      }
    }
  }

  // Pass 1: URLs — one candidate per URL; host/port/basename are parsed metadata only.
  /** @type {Map<string, Array<[number, number]>>} block id → URL spans */
  const urlSpansByBlock = new Map();
  for (const block of blocks) {
    if (tableHandled.has(block.id)) continue;
    const text = refangTextForExtraction(block.text || '');
    if (!text.trim()) continue;
    const spans = [];
    for (const m of text.matchAll(URL_RE)) {
      const url = stripUrlTrailingPunct(m[0]);
      if (!url) continue;
      spans.push([m.index, m.index + url.length]);
      const host = hostnameFromUrl(url);
      const base = pathBasenameFromUrl(url);
      if (host) knownUrlHosts.add(host);
      if (base && base.includes('.')) urlPathBasenames.add(base.toLowerCase());
      const isRow = isObservableRow(block);
      const entry = add(url, 'url', block, { form: isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.URL });
      if (entry) {
        if (host && !entry.parsed.host) {
          entry.parsed.host = host;
          entry.parsed.host_kind = isValidIpAddress(host) ? 'ip' : 'domain';
        }
        const port = portFromUrl(url);
        if (port != null) rememberPort(entry, port);
        if (base && !entry.parsed.path_basename) entry.parsed.path_basename = base;
        if (host) {
          if (!urlHostIndex.has(host)) urlHostIndex.set(host, new Set());
          urlHostIndex.get(host).add(candidateKey('url', entry.normalized_value));
        }
      }
    }
    // Pass 1b: scheme-less host/path resources ("js.cache-mcp[.]com/layer.js").
    // One URL occurrence in the publisher's exact spelling — no scheme is
    // invented, the path stays in the value, the host is parsed metadata only
    // (same no-over-derivation rule as absolute URLs) and the basename never
    // becomes a domain / artifact of its own.
    for (const m of text.matchAll(HOST_PATH_RE)) {
      const start = m.index;
      const raw = stripUrlTrailingPunct(m[0]);
      if (!raw || insideAnySpan(spans, start, start + raw.length)) continue;
      const v = validateUrlCandidate(raw);
      if (!v.ok || v.reason !== 'scheme_less_url_with_dns_host' || v.host_kind !== 'domain') {
        countReason(typeDiag.scheme_less_resources.rejected, v.reason || 'invalid');
        continue;
      }
      const path = raw.slice(raw.indexOf('/'));
      if (path.length < 2) continue;
      spans.push([start, start + raw.length]);
      const base = pathBasenameFromUrl(`http://${raw}`);
      if (v.host) knownUrlHosts.add(v.host);
      if (base && base.includes('.')) urlPathBasenames.add(base.toLowerCase());
      const isRow = isObservableRow(block);
      const entry = add(raw, 'url', block, {
        form: isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.URL,
        originalValue: sourceSpelling(block.text, raw),
        typing: { typing_reason: 'scheme_less_url_with_dns_host' }
      });
      typeDiag.scheme_less_resources.count += 1;
      if (entry) {
        entry.parsed.scheme = null;
        entry.parsed.scheme_less = true;
        entry.parsed.path = path;
        if (v.host && !entry.parsed.host) {
          entry.parsed.host = v.host;
          entry.parsed.host_kind = 'domain';
        }
        if (base && !entry.parsed.path_basename) entry.parsed.path_basename = base;
        if (!urlHostIndex.has(v.host)) urlHostIndex.set(v.host, new Set());
        urlHostIndex.get(v.host).add(candidateKey('url', entry.normalized_value));
        if (typeDiag.scheme_less_resources.examples.length < 12) {
          typeDiag.scheme_less_resources.examples.push({
            block_id: block.id,
            raw: raw.slice(0, 200),
            resolved: { candidate_type: 'url', normalized_value: entry.normalized_value, host: v.host, path },
            decision: 'preserved_as_scheme_less_url',
            not_promotable_as: 'absolute_url_without_scheme'
          });
        }
      }
    }
    if (spans.length) urlSpansByBlock.set(block.id, spans);
  }

  // Pass 2: other observables. Host-like matches inside a URL span are the URL's
  // own host component — not an independent assertion — and are skipped.
  for (const block of blocks) {
    if (tableHandled.has(block.id)) continue;
    const text = refangTextForExtraction(block.text || '');
    if (!text.trim()) continue;
    const urlSpans = urlSpansByBlock.get(block.id) || [];
    const isRow = isObservableRow(block);
    const standaloneForm = isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.STANDALONE;
    /** @type {Array<[number, number]>} */
    const consumed = [];

    // IP:port endpoints (direct C2 endpoint assertions)
    for (const m of text.matchAll(IPV4_PORT_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      const port = Number(m[2]);
      if (!Number.isFinite(port) || port < 1 || port > 65535) continue;
      const entry = add(m[1], 'ip', block, { form: OCCURRENCE_FORMS.IP_PORT, port });
      if (entry) {
        // Keep the faithful source spelling when the endpoint form is the first sighting
        if (entry.occurrences.length === 1 && !entry.original_value.includes(':')) {
          entry.original_value = `${m[1]}:${m[2]}`;
        }
        consumed.push([start, end]);
      }
    }

    for (const m of text.matchAll(IPV4_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end)) continue;
      if (String(m[0]).includes('/')) add(m[0], 'cidr', block, { form: standaloneForm });
      else add(m[0], 'ip', block, { form: standaloneForm });
    }
    for (const m of text.matchAll(IPV6_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      add(m[0], 'ipv6', block, { form: standaloneForm });
    }
    for (const m of text.matchAll(SHA256_RE)) add(m[0], 'sha256', block, { form: standaloneForm });
    for (const m of text.matchAll(SHA1_RE)) add(m[0], 'sha1', block, { form: standaloneForm });
    for (const m of text.matchAll(MD5_RE)) add(m[0], 'md5', block, { form: standaloneForm });
    for (const m of text.matchAll(CVE_RE)) add(m[0], 'cve', block, { form: standaloneForm });
    for (const m of text.matchAll(ATTACK_RE)) {
      if (/^T(1\d{3}|10\d{2}|11\d{2}|12\d{2}|15\d{2}|16\d{2})/.test(m[0])) {
        add(m[0], 'attack_technique', block, { form: standaloneForm });
      }
    }
    for (const m of text.matchAll(DOMAIN_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      // Original spelling: identifier segmentation (Loader.Program.Main) is case-visible.
      add(m[0], 'domain', block, { form: standaloneForm, originalValue: m[0] });
    }
  }

  // Decide deferred dotted tokens (domain vs technical artifact) per document.
  resolvePendingDotted();

  // Finalize: evidence policy + parser-derived host cross references
  const out = [];
  for (const entry of byKey.values()) {
    if (entry.candidate_type === 'url' && entry.parsed.host) {
      const hostType = entry.parsed.host_kind === 'ip' ? 'ip' : 'domain';
      const hostKey = candidateKey(hostType, entry.parsed.host);
      entry.parsed.host_independently_asserted = byKey.has(hostKey);
    }
    if ((entry.candidate_type === 'ip' || entry.candidate_type === 'domain') && urlHostIndex.has(entry.normalized_value)) {
      entry.parsed.also_url_host_of = [...urlHostIndex.get(entry.normalized_value)].map((k) => k.split('\0')[1]).slice(0, 20);
    }
    if (entry.table_rows.length) {
      entry.parsed.table_rows = entry.table_rows.length;
      entry.parsed.declared_types = [...new Set(entry.table_rows.map((r) => r.declared_type).filter(Boolean))];
    } else {
      delete entry.table_rows;
    }
    entry.occurrence_count = entry.occurrences.length;
    entry.document_has_authoritative_scope = documentScope.has_authoritative_indicator_scope;
    applyEvidencePolicy(entry);
    const canonical = entry.is_ioc !== false ? validateCanonicalIocValue(entry.candidate_type, entry.normalized_value) : null;
    if (canonical && !canonical.ok) typeDiag.canonical_rejections += 1;
    entry.type_resolution = buildTypeResolutionRecord({
      raw: entry.original_value,
      syntaxGuess: entry.syntax_guess || entry.candidate_type,
      resolvedType: entry.resolved_type || entry.candidate_type,
      reason: entry.typing_reason || (entry.is_ioc === false ? entry.policy_decision : 'syntax_valid'),
      promotion: entry.is_ioc === false || entry.assessment === 'context_only' ? 'excluded' : 'eligible',
      signals: entry.typing_signals || undefined,
      normalizedPath: entry.parsed?.normalized_path || null,
      port: entry.parsed?.port ?? null,
      canonical
    });
    if (entry.artifact_kind) entry.type_resolution.artifact_kind = entry.artifact_kind;
    if (entry.type_scores) entry.type_resolution.scores = entry.type_scores;
    delete entry.typing_signals;
    delete entry.syntax_guess;
    delete entry.type_scores;
    if (NON_NETWORK_RESOLVED_TYPES.has(entry.candidate_type)) {
      typeDiag.artifact_candidates += 1;
      if (entry.candidate_type === RESOLVED_TYPES.RELATIVE_PATH || entry.candidate_type === RESOLVED_TYPES.FILE_PATH) typeDiag.relative_paths += 1;
      rememberExample(entry.type_resolution);
    } else if (entry.is_ioc !== false) {
      typeDiag.network_ioc_candidates += 1;
    }
    out.push(entry);
  }

  // Completeness gate: every identity a valid explicit table row asserted must
  // be a persisted candidate. A mismatch is an internal extraction bug, not a
  // source problem, and is surfaced for diagnosis rather than hidden.
  const t = diagnostics.explicit_tables;
  const created = out.filter((c) => Array.isArray(c.table_rows) && c.table_rows.some((r) => r.explicit));
  t.candidates_created = created.length;
  const createdKeys = new Set(created.map((c) => candidateKey(c.candidate_type, c.normalized_value)));
  t.missing_identities = [...explicitTableKeys].filter((k) => !createdKeys.has(k)).map((k) => k.replace('\0', ':'));
  t.inconsistent = t.missing_identities.length > 0;
  t.explicit_identities = explicitTableKeys.size;
  diagnostics.document_scope = documentScope;
  diagnostics.scope = buildScopeDiagnostics(annotated, out);

  return { candidates: out, diagnostics };
}

/**
 * Developer diagnostics for scope decisions: which headings opened / continued
 * / closed authoritative sections, and how occurrences were read (row vs
 * narrative, relation marker) per zone. Bounded; not analyst UI.
 * @param {object} annotated zone-annotated document
 * @param {object[]} candidates
 */
export function buildScopeDiagnostics(annotated, candidates) {
  const kinds = {};
  const markers = {};
  const byPolicy = {};
  const perCandidate = [];
  for (const c of candidates || []) {
    byPolicy[c.policy_decision || 'none'] = (byPolicy[c.policy_decision || 'none'] || 0) + 1;
    const occ = Array.isArray(c.occurrences) ? c.occurrences : [];
    for (const o of occ) {
      const k = o.occurrence_kind || 'unclassified';
      kinds[k] = (kinds[k] || 0) + 1;
      const m = o.relation_marker || 'none';
      markers[m] = (markers[m] || 0) + 1;
    }
    if (perCandidate.length < 80 && c.is_ioc !== false) {
      perCandidate.push({
        type: c.candidate_type,
        value: String(c.normalized_value || '').slice(0, 120),
        assessment: c.assessment,
        policy: c.policy_decision || null,
        ai_needed: c.ai_needed === true,
        occurrences: occ.slice(0, 6).map((o) => ({
          block_id: o.block_id,
          zone: o.zone,
          zone_reason: o.zone_reason || null,
          opened_by: o.scope_opening_id || null,
          heading: o.section_heading ? String(o.section_heading).slice(0, 80) : null,
          kind: o.occurrence_kind || null,
          relation: o.source_relation || null,
          marker: o.relation_marker || null,
          asserted: o.asserted === true
        }))
      });
    }
  }
  return {
    zones_version: annotated?.meta?.zones_version || null,
    trace: Array.isArray(annotated?.meta?.scope_trace) ? annotated.meta.scope_trace.slice(0, 60) : [],
    occurrence_kinds: kinds,
    relation_markers: markers,
    policy_decisions: byPolicy,
    candidates: perCandidate
  };
}

/**
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 * @param {{ sourceUrl?: string|null }} [opts]
 */
export function extractCandidatesFromDocument(doc, opts = {}) {
  return extractCandidatesWithDiagnostics(doc, opts).candidates;
}

/**
 * Review-set partition used by the pipeline, prompts and UI summaries.
 * @param {object[]} candidates
 */
export function summarizeCandidateSet(candidates) {
  const s = {
    total: 0,
    ioc_candidates: 0,
    explicit_assertions: 0,
    table_assertions: 0,
    body_assertions: 0,
    context_only: 0,
    non_ioc: 0,
    ai_needed: 0,
    raw_occurrences: 0
  };
  for (const c of candidates || []) {
    s.total += 1;
    s.raw_occurrences += Array.isArray(c.occurrences) ? c.occurrences.length : 0;
    if (c.is_ioc === false) {
      s.non_ioc += 1;
      continue;
    }
    if (c.assessment === 'context_only') {
      s.context_only += 1;
      continue;
    }
    s.ioc_candidates += 1;
    if (c.source_assertion === 'explicit_ioc' || c.source_assertion === 'explicit_c2' || c.source_assertion === 'explicit_operational_infrastructure') s.explicit_assertions += 1;
    else s.body_assertions += 1;
    if (Array.isArray(c.table_rows) ? c.table_rows.length : c.parsed?.table_rows) s.table_assertions += 1;
    if (c.ai_needed) s.ai_needed += 1;
  }
  return s;
}
