/**
 * Candidate accumulator: the one place an observed token becomes (or fails to
 * become) a candidate. Owns the identity map; the document passes feed it through
 * add() and read only the entries it returns.
 */

import { NEGATIVE_ZONES, STRONG_IOC_ZONES } from './documentZones.js';
import { resolveDottedTokenType, hostnameFromUrl } from './candidateTyping.js';
import { normalizeCandidateValue } from './candidateValue.js';
import { isCredentialLabeledHex, isIndicatorRowShape, lineContainingObservable, tableRowProviderOwnedByOperation } from './indicatorScope.js';
import { FILE_EXT_HINT, NON_NETWORK_RESOLVED_TYPES, RESOLVED_TYPES, buildTypeResolutionRecord, hasDelegatedDnsSuffix, isMutexLabeledValue, parseArtifactTypeLabel } from './observableTypeResolver.js';
import { isOnlyEmbeddedInDnsHostname } from './sourceOccurrence.js';
import { DIGEST_KINDS, NON_FILE_DIGEST_KINDS, classifyHexDigest } from './digestSemantics.js';
import { samePublisherHostFamily, surroundingWindow, URL_SCHEME_PREFIX_RE, markTruncatedUrlDuplicates, MAX_TABLE_ROWS_PER_CANDIDATE, OCCURRENCE_FORMS, annotatedDigestWindow, locateInBlockText, HASH_CANDIDATE_TYPES, MIN_TRUNCATED_DIGEST_PREFIX, candidateKey, digestColumnHeader } from './candidateHelpers.js';

/**
 * @param {{
 *   blocks: object[], tableOrdinals: Map, listLeadIns: Map, valueLineLeadIns: Map, codeListNames: Map,
 *   sourceHost: string, normalizedSourceUrl: string|null, typeDiag: object, explicitTableAssertions: object,
 *   referenceColumnValues: Map, noteRejectedToken: Function, extractionVersion: string
 * }} ctx
 */
export function createCandidateAccumulator(ctx) {
  const {
    tableOrdinals, listLeadIns, valueLineLeadIns, codeListNames, sourceHost, normalizedSourceUrl,
    typeDiag, explicitTableAssertions, referenceColumnValues, noteRejectedToken, extractionVersion
  } = ctx;
  /** @type {Map<string, object>} */
  const byKey = new Map();
  const urlPathBasenames = new Set();
  const knownUrlHosts = new Set();
  /** host → Set<url candidate key> (parser-derived metadata index, not occurrences) */
  const urlHostIndex = new Map();
  if (sourceHost) knownUrlHosts.add(sourceHost.toLowerCase());
  const countReason = (bucket, reason) => {
    bucket[reason] = (bucket[reason] || 0) + 1;
  };
  const rememberExample = (record) => {
    if (typeDiag.examples.length < 24) typeDiag.examples.push(record);
  };
  /** Last rejection reason from add(); diagnostic only. */
  let lastAddRejection = null;

  function occurrenceFor(block, extra = {}, focusValue = '') {
    const zone = block?.zone || 'unknown';
    const text = extra.rowText || (block?.text ? String(block.text) : null);
    const focus = extra.originalValue || focusValue;
    const form = extra.form || OCCURRENCE_FORMS.STANDALONE;
    // Structural reading is decided here, where the whole block is visible:
    // row placement (list / table / observable-row layout / discovered list)
    // or a short "value – note" / "label: value" line.
    // The domain inside an email address ("ops@mail.example") is never an
    // indicator row by itself, whatever line / list the address sits on.
    const emailPart = form === OCCURRENCE_FORMS.EMAIL_DOMAIN;
    const structuralRow = !emailPart && (
      form === OCCURRENCE_FORMS.TABLE_ROW ||
      form === OCCURRENCE_FORMS.LIST_ROW ||
      form === OCCURRENCE_FORMS.IP_PORT ||
      block?.type === 'list_item' ||
      block?.layout === 'observable_row' ||
      block?.zone_reason === 'observable_list' ||
      block?.zone_reason === 'cidr_list' ||
      block?.zone_reason === 'ioc_table');
    const rowShape = !emailPart && !structuralRow && text ? isIndicatorRowShape(text, focus || focusValue) : false;
    const located = locateInBlockText(block?.text, focus || focusValue);
    const tableOrdinal = block?.type === 'table' ? tableOrdinals.get(block?.id) : undefined;
    return {
      ...(located ? { char_start: located.start, char_end: located.end } : {}),
      ...(Number.isInteger(tableOrdinal) ? { table_index: tableOrdinal } : {}),
      ...(extra.tableRow && Number.isInteger(extra.tableRow.column_index) ? { table_column: extra.tableRow.column_index } : {}),
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
      // A table row is one publisher record. The 140-character focus window
      // ends before a description that follows a long filename, so only the
      // last digest of "hash hash hash | Long Name.exe | Legitimate binary"
      // used to see the benign statement (tl-candidates-v47).
      surrounding_text: (extra.evidenceRowText || text)
        ? (form === OCCURRENCE_FORMS.TABLE_ROW
          ? String(extra.evidenceRowText || text).slice(0, 500)
          : surroundingWindow(extra.evidenceRowText || text, focus, 140, extra.focusOrdinal || 0))
        : null,
      typing_reason: extra.typingReason || null,
      ...(extra.referenceCell === true ? { reference_cell: true } : {}),
      ...(extra.descriptionCell === true ? { description_cell: true } : {}),
      ...(extra.truncatedDigest === true ? { truncated_digest: true } : {}),
      ...(extra.hostsFileEntry === true ? { hosts_file_entry: true } : {}),
      ...(block?.list_stance ? { list_stance: block.list_stance } : {}),
      ...(codeListNames.has(block?.id) ? { code_list_name: codeListNames.get(block.id).slice(0, 64) } : {}),
      ...(form === OCCURRENCE_FORMS.STANDALONE && valueLineLeadIns.has(block?.id)
        ? { value_line_lead_in: valueLineLeadIns.get(block.id).slice(0, 400) }
        : {}),
      ...(form === OCCURRENCE_FORMS.TABLE_ROW && extra.tableRow &&
        tableRowProviderOwnedByOperation(block, extra.tableRow.source_row_index ?? extra.tableRow.row_index)
        ? { operator_owned_row: true }
        : {})
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
    if (extra.evidenceRowText || extra.rowText) return String(extra.evidenceRowText || extra.rowText).slice(0, 500);
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
        extraction_version: extractionVersion
      };
      if (n.likelyContextOnly && !n.reservedAddress && !n.nonActionableLocal) entry.rfc_example = true;
      if (n.reservedAddress) entry.reserved_address = true;
      if (n.nonActionableLocal) entry.non_actionable_local = true;
      // Report's own source URL / host (and same-site subdomains) are provenance,
      // never findings — e.g. report.ncsc.gov.uk on an ncsc.gov.uk advisory.
      if (candidateType === 'domain' && sourceHost && samePublisherHostFamily(normalizedValue, sourceHost)) {
        entry.is_report_source = true;
      } else if (candidateType === 'url') {
        const urlHost = hostnameFromUrl(normalizedValue);
        if (
          (normalizedSourceUrl && normalizedValue === normalizedSourceUrl) ||
          (sourceHost && urlHost && samePublisherHostFamily(urlHost, sourceHost))
        ) {
          entry.is_report_source = true;
        }
      }
      byKey.set(key, entry);
    }
    pushOccurrence(entry, block, { ...extra, typingReason: typingMeta.typing_reason || null });
    if (extra.tableRow && entry.table_rows.length < MAX_TABLE_ROWS_PER_CANDIDATE) {
      entry.table_rows.push(extra.tableRow);
    }
    anchorEntry(entry, block, extra);
    return entry;
  }

  /**
   * Evidence anchor preference after an occurrence joined `entry`: a strong
   * IOC zone beats a weaker one, a body mention beats a footer / reference.
   * @param {object} entry
   * @param {object} block
   * @param {object} extra
   */
  function anchorEntry(entry, block, extra) {
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
  }

  /**
   * Hashes the publisher cut short with an ellipsis ("SHA256: e76f54b7…"),
   * waiting for the document's full digests to exist (tl-candidates-v54).
   * @type {Array<{ prefix: string, labelLength: number|null, spelling: string, block: object, linkExtra: object, fallback: (() => void)|null }>}
   */
  const deferredTruncatedDigests = [];

  /**
   * @param {{ prefix: string, label_length?: number|null, labelLength?: number|null, spelling: string }} trunc
   * @param {object} block
   * @param {object} linkExtra occurrence extra for the linked full digest
   * @param {(() => void)|null} fallback what the cell produced before this contract
   */
  function deferTruncatedDigest(trunc, block, linkExtra, fallback) {
    deferredTruncatedDigests.push({
      prefix: trunc.prefix,
      labelLength: trunc.label_length ?? trunc.labelLength ?? null,
      spelling: trunc.spelling,
      block,
      linkExtra,
      fallback: fallback || null
    });
  }

  /**
   * A truncated digest is a prefix of exactly one full digest elsewhere in the
   * report: the full digest then also occurs where the publisher wrote the
   * truncation (the same row, with that row's zone / table provenance), the
   * way markTruncatedUrlDuplicates ties a cut-short URL to its full form.
   * Several or no full digests: the cell reads as before (no invention).
   */
  function resolveTruncatedDigests() {
    const digests = [...byKey.values()].filter((e) => HASH_CANDIDATE_TYPES.has(e.candidate_type) && e.normalized_value);
    for (const d of deferredTruncatedDigests) {
      const matches = digests.filter((e) => {
        const value = String(e.normalized_value).toLowerCase();
        if (value.length <= d.prefix.length || !value.startsWith(d.prefix)) return false;
        return !d.labelLength || value.length === d.labelLength;
      });
      if (matches.length !== 1 || d.prefix.length < MIN_TRUNCATED_DIGEST_PREFIX) {
        if (d.fallback) d.fallback();
        continue;
      }
      const entry = matches[0];
      const extra = { ...d.linkExtra, originalValue: d.spelling, truncatedDigest: true };
      pushOccurrence(entry, d.block, extra);
      if (extra.tableRow && entry.table_rows.length < MAX_TABLE_ROWS_PER_CANDIDATE) {
        entry.table_rows.push({ ...extra.tableRow, raw_value: d.spelling, truncated_digest: true });
      }
      const original = entry.original_value;
      anchorEntry(entry, d.block, extra);
      // The anchor takes the publisher's spelling of a value; this one is a
      // truncation, never the digest's own spelling.
      entry.original_value = original;
      entry.parsed.truncated_in_table = true;
      entry.parsed.truncated_spellings = [...new Set([...(entry.parsed.truncated_spellings || []), d.spelling])].slice(0, 4);
    }
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
    lastAddRejection = null;
    const n = normalizeCandidateValue(raw, hintType);
    if (!n.ok) {
      lastAddRejection = n.error || 'unrecognized';
      countReason(typeDiag.rejected_values, lastAddRejection);
      noteRejectedToken(raw, hintType, block, lastAddRejection, 'invalid');
      return null;
    }
    if (extra.referenceCell !== true &&
        referenceColumnValues.get(block?.id)?.has(`${n.candidateType}:${String(n.normalizedValue).toLowerCase()}`)) {
      extra = { ...extra, referenceCell: true, typingReason: extra.typingReason || 'reference_column' };
    }
    // Credential / token labels: a hex run is not a malware hash just because
    // it matches md5/sha length. Hash vocabulary on the same label ("SHA-256:",
    // "Hardcoded Hash:") keeps the hash reading; length/type still follow value.
    if (n.candidateType === 'md5' || n.candidateType === 'sha1' || n.candidateType === 'sha256') {
      const hay = extra.rowText || block?.text || '';
      const line = lineContainingObservable(hay, n.normalizedValue) || hay;
      if (isCredentialLabeledHex(line, n.normalizedValue)) {
        lastAddRejection = 'credential_labeled_hex';
        countReason(typeDiag.rejected_values, lastAddRejection);
        noteRejectedToken(n.normalizedValue, n.candidateType, block, lastAddRejection);
        return null;
      }
      // The value's own type label (sub-heading / table type cell) names a
      // mutex: a hex mutex name is not a file digest, whatever its length.
      // Only the mutex family is decisive — "Configuration" / "Registry"
      // headings can sit over genuine file hashes. A declared hash type wins.
      const ownLabel = extra.typeLabel || block?.type_label || null;
      const declaredHash = /^(?:md5|sha1|sha256|hash)$/.test(String(extra.declaredType || block?.declared_type_label || ''));
      if (!declaredHash && ((ownLabel && parseArtifactTypeLabel(ownLabel)?.kind === 'mutex') || isMutexLabeledValue(line, n.normalizedValue))) {
        countReason(typeDiag.excluded_reasons, 'mutex_type_label');
        return materialize({
          candidateType: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
          normalizedValue: n.normalizedValue,
          originalValue: extra.originalValue || n.originalValue,
          n,
          block,
          extra,
          typingMeta: { resolved_type: RESOLVED_TYPES.TECHNICAL_ARTIFACT, typing_reason: 'mutex_type_label' },
          isIoc: false,
          artifactKind: 'mutex',
          typingSignals: null,
          syntaxGuess: n.candidateType
        });
      }
      // Build-ids, certificate thumbprints, vhash / fuzzy hashes, keys and
      // digests of trivial inputs share the hex shape but name no file: keep
      // them as report context (technical artifact), never as a sample hash.
      // Table rows: the caption / section heading names the subject a bare
      // algorithm label leaves open ("Custom certificate …" > "SHA-256 | <v>").
      // List items: the lead-in sentence, else the heading the list sits under
      // ("### SSL Thumbprint" then a bare hex item) (tl-candidates-v41).
      const scopeLabel = block?.type === 'table'
        ? block?.table?.caption || block?.section || null
        : block?.type === 'list' ? listLeadIns.get(block.id) || block?.section || null : null;
      // A table cell is labelled by its column header ("Imphash | Cluster |
      // Role"), not by the last cell of the previous row (tl-candidates-v41).
      const columnHeader = extra.tableRow?.column_header || digestColumnHeader(block, n.normalizedValue);
      // In a "<hash> (<label>)" run the label is the parenthetical after the
      // hash, never the previous row's ("… (Ligolo TLS certificate) <hash> (agent)").
      const digest = classifyHexDigest(annotatedDigestWindow(line, n.normalizedValue) || line, n.normalizedValue, {
        scopeLabel,
        columnHeader,
        rowDescription: extra.tableRow?.description || null
      });
      if (NON_FILE_DIGEST_KINDS.has(digest.kind) && digest.kind !== DIGEST_KINDS.CREDENTIAL) {
        countReason(typeDiag.excluded_reasons, `non_file_digest_${digest.kind}`);
        const artifact = materialize({
          candidateType: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
          normalizedValue: n.normalizedValue,
          originalValue: extra.originalValue || n.originalValue,
          n,
          block,
          extra,
          typingMeta: {
            resolved_type: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
            typing_reason: `non_file_digest_${digest.kind}`
          },
          isIoc: false,
          artifactKind: digest.kind,
          typingSignals: null,
          syntaxGuess: n.candidateType
        });
        if (artifact) {
          artifact.digest_kind = digest.kind;
          artifact.digest_shape = n.candidateType;
        }
        return artifact;
      }
    }
    // IP/IPv6: reject when this block's only evidence is a numeric prefix of a
    // larger DNS token. Do not consult originalValue/raw — those may already be
    // the carved IP. Unknown spelling (no hit) is not treated as embedding.
    if (n.candidateType === 'ip' || n.candidateType === 'ipv6') {
      const sourceHay = extra.rowText || block?.text || '';
      if (sourceHay && isOnlyEmbeddedInDnsHostname(sourceHay, n.candidateType, n.normalizedValue)) {
        lastAddRejection = 'embedded_in_dns_hostname';
        countReason(typeDiag.rejected_values, lastAddRejection);
        noteRejectedToken(n.normalizedValue, n.candidateType, block, lastAddRejection);
        return null;
      }
    }
    const typingMeta = { ...(extra.typing || {}) };
    const zone = block?.zone || 'unknown';
    const strongZone = STRONG_IOC_ZONES.has(zone);

    // Dotted tokens: resolve per occurrence, decide per document (see pendingDotted).
    if (n.candidateType === 'domain') {
      // Typing reads the publisher's spelling: a defang marker ("[.]") is the
      // network assertion that keeps a mixed-case host a domain (v50).
      let token = String(extra.typingSpelling || extra.originalValue || n.originalValue || raw).trim().replace(/\.$/, '');
      // "fqdn://ipfs[.]io" is the publisher's spelling of the host. Typing the
      // scheme-prefixed original returns skip and drops the table row
      // (tl-candidates-v46).
      // "tcp://host:443" / "udp://" / "tls://" / "socks5://" name the host the
      // same way (tl-candidates-v54).
      token = token.replace(/^(?:fqdn|tcp|udp|tls|ssl|socks[45]h?):\/\//i, '').replace(/\/+$/, '');
      // "host:port" endpoint rows: the port is recorded on the occurrence; the
      // host alone is typed (tl-table-v12).
      if (extra.port != null) token = token.replace(new RegExp(`[:：]${extra.port}[.,;]*$`), '');
      // A publisher wildcard cell asserts its base domain: type that name,
      // not the glob (tl-candidates-v54).
      if (extra.wildcardApex === true) token = token.replace(/^\*\./, '');
      const form = extra.form || OCCURRENCE_FORMS.STANDALONE;
      const lineText = extra.rowText || block?.text || '';
      const typed = resolveDottedTokenType(token, {
        surroundingText: surroundingWindow(lineText, token, 160),
        typeLabel: extra.typeLabel || block?.type_label || null,
        declaredType: extra.declaredType || block?.declared_type_label || null,
        zone,
        blockType: block?.type || null,
        form,
        // Same focus-aware row reading occurrenceFor records as row_shape: a
        // <br>-split HTML line ("evil-host[.]com") is an indicator row for this
        // token even though its block is a paragraph, while a file name in a
        // hash row's description ("<sha256> - loader.node") is not.
        indicatorRow: strongZone && form !== OCCURRENCE_FORMS.EMAIL_DOMAIN && isIndicatorRowShape(lineText, token),
        strongZone,
        urlPathBasenames,
        knownUrlHosts
      });
      if (typed.kind === 'skip') {
        lastAddRejection = typed.reason;
        countReason(typeDiag.rejected_values, lastAddRejection);
        noteRejectedToken(n.normalizedValue, 'domain', block, lastAddRejection);
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
    single_instance_identifier_context: 50, inline_artifact_label: 50, path_segment: 50,
    url_host: 40, explicit_indicator_row: 40, url_path_basename: 40,
    code_identifier_shape: 30, code_context: 30, multi_dot_ext: 30, file_extension: 30, extension_without_host_context: 20,
    method_suffix: 30, code_call: 30, code_block_weak_suffix: 20,
    network_context: 10, network_context_mixed_case: 10, title_case_tld_list: 35,
    artifact_context: 10, code_context_label: 10, config_context: 10, registry_context: 10, path_context: 10,
    command_context: 10, process_context: 10, metadata_context: 10, file_context: 10,
    hostname_shape: 1,
    no_network_semantics: 1
  });

  /**
   * Decide every deferred dotted token and materialize its candidate.
   */
  function resolvePendingDotted() {
    // Same value already typed as an artifact by a source-typed table row
    // ("File Name" column): that reading votes too, so one value never splits
    // into a domain (body mentions) and an artifact (the table).
    const tableArtifacts = new Map();
    for (const entry of byKey.values()) {
      if (!NON_NETWORK_RESOLVED_TYPES.has(entry.candidate_type)) continue;
      if (!entry.occurrences.some((o) => o.form === OCCURRENCE_FORMS.TABLE_ROW)) continue;
      tableArtifacts.set(String(entry.normalized_value).toLowerCase(), entry);
    }
    for (const [id, pending] of pendingDotted) {
      let domainScore = 0;
      let artifactScore = 0;
      let best = null;
      for (const occ of pending.occurrences) {
        const w = READING_WEIGHT[occ.typed.reason] ?? 5;
        if (occ.typed.kind === 'domain') domainScore += w;
        else artifactScore += w;
        if (!best || w > best.w) best = { w, occ };
      }
      const tableArtifact = tableArtifacts.get(String(id).toLowerCase()) || null;
      if (tableArtifact) artifactScore += READING_WEIGHT[tableArtifact.typing_reason] ?? READING_WEIGHT.file_label;
      // A source-declared network type from a typed Domain *table* cell is never
      // outvoted: explicit indicator tables stay complete. Heading-inherited
      // "Domains" labels only force domain for real delegated DNS suffixes —
      // eight `Node.js` prose mentions must not become a domain because one tag
      // inherited the preceding Domains sub-heading.
      const declaredNetwork = pending.occurrences.some((o) => {
        if (o.typed.reason !== 'declared_network_type') return false;
        if (o.extra.form === OCCURRENCE_FORMS.TABLE_ROW) return true;
        return hasDelegatedDnsSuffix(String(o.n.normalizedValue || ''));
      });
      // Nor is a domain reading of the publisher's own indicator row for this
      // exact token: narrative code-shaped spellings of the same value elsewhere
      // (`iRM eViLhOsT[.]COM` in an obfuscated command) cannot demote a curated
      // IOC entry. Only the focused row's own domain reading counts — an
      // artifact reading of a row (file extension, code shape) never does.
      // File-extension tokens without a delegated DNS suffix never count as an
      // asserted-row network reading (tag "Node.js" under Domains and IPs).
      const assertedRowNetwork = pending.occurrences.some((o) => {
        if (o.typed.kind !== 'domain' || o.typed.signals?.explicit_indicator_row !== true) return false;
        const last = String(o.n.normalizedValue || '')
          .toLowerCase()
          .split('.')
          .filter(Boolean)
          .pop();
        if (last && FILE_EXT_HINT.has(last) && !hasDelegatedDnsSuffix(String(o.n.normalizedValue || ''))) {
          return false;
        }
        return true;
      });
      const isDomain = declaredNetwork || assertedRowNetwork || domainScore > artifactScore;
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
        // A table-typed artifact identity already exists: body mentions attach to it.
        const retain = labelled || asserted || Boolean(tableArtifact);
        if (!retain) {
          // Incidental identifiers in prose (bytes.Index, Foo.Bar.Baz) are not report intelligence.
          typeDiag.artifact_occurrences_dropped += pending.occurrences.length;
          noteRejectedToken(pending.token, 'domain', pending.occurrences[0]?.block, `incidental_identifier:${typed.reason}`, 'unsupported');
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
      // Artifact reading joins the table's artifact identity when one exists.
      const artifactValue = !isDomain && tableArtifact && tableArtifact.candidate_type === candidateType
        ? tableArtifact.normalized_value
        : pending.token;
      for (const occ of pending.occurrences) {
        const typingMeta = {
          ...(occ.extra.typing || {}),
          resolved_type: candidateType,
          typing_reason: typed.reason,
          occurrence_reason: occ.typed.reason
        };
        const entry = materialize({
          candidateType,
          normalizedValue: isDomain ? occ.n.normalizedValue : artifactValue,
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
      }
      const entry = byKey.get(candidateKey(candidateType, isDomain ? pending.occurrences[0].n.normalizedValue : artifactValue));
      if (entry) {
        entry.type_scores = { domain: domainScore, artifact: artifactScore };
      }
    }
    pendingDotted.clear();
  }

  /** "Host/path" identity of a URL value: scheme dropped, host case-folded, path verbatim. */
  function hostPathIdentity(value) {
    const rest = String(value || '').replace(URL_SCHEME_PREFIX_RE, '');
    const slash = rest.indexOf('/');
    if (slash <= 0) return null;
    return `${rest.slice(0, slash).toLowerCase()}${rest.slice(slash)}`;
  }

  function foldSchemeLessUrlAliases() {
    /** host/path → absolute URL entries with that host/path */
    const absolute = new Map();
    for (const entry of byKey.values()) {
      if (entry.candidate_type !== 'url' || !URL_SCHEME_PREFIX_RE.test(entry.normalized_value)) continue;
      const id = hostPathIdentity(entry.normalized_value);
      if (!id) continue;
      if (!absolute.has(id)) absolute.set(id, []);
      absolute.get(id).push(entry);
    }
    for (const [key, alias] of [...byKey]) {
      // Scheme-less spellings come from prose / rows (Pass 1b) and table cells alike.
      if (alias.candidate_type !== 'url' || URL_SCHEME_PREFIX_RE.test(alias.normalized_value)) continue;
      const targets = absolute.get(hostPathIdentity(alias.normalized_value)) || [];
      if (targets.length !== 1) continue;
      const target = targets[0];
      for (const occ of alias.occurrences) {
        const dup = target.occurrences.some(
          (o) => o.block_id && o.block_id === occ.block_id && (o.table_row == null || o.table_row === occ.table_row)
        );
        if (!dup) target.occurrences.push(occ);
      }
      for (const row of alias.table_rows || []) {
        if (target.table_rows.length < MAX_TABLE_ROWS_PER_CANDIDATE) target.table_rows.push(row);
      }
      if (STRONG_IOC_ZONES.has(alias.zone) && !STRONG_IOC_ZONES.has(target.zone)) {
        target.evidence_text = alias.evidence_text;
        target.block_id = alias.block_id;
        target.page_number = alias.page_number;
        target.section = alias.section;
        target.zone = alias.zone;
      }
      target.parsed.scheme_less_aliases = [...(target.parsed.scheme_less_aliases || []), alias.original_value].slice(0, 8);
      for (const keys of urlHostIndex.values()) {
        if (keys.delete(key)) keys.add(candidateKey('url', target.normalized_value));
      }
      explicitTableAssertions.rememberAlias('url', alias.normalized_value, target.normalized_value);
      byKey.delete(key);
    }
  }

  return {
    byKey,
    urlHostIndex,
    urlPathBasenames,
    knownUrlHosts,
    add,
    rememberPort,
    countReason,
    rememberExample,
    deferTruncatedDigest,
    resolveTruncatedDigests,
    resolvePendingDotted,
    foldSchemeLessUrlAliases,
    lastRejection: () => lastAddRejection
  };
}
