/**
 * Extraction quality presentation (report `extraction_quality`, tl-quality-v1).
 *
 * Quality warnings are automatic signals, not confirmed extraction errors:
 * nothing about the report changes because of them. This module turns the
 * stable reason codes into analyst wording and keeps parser internals (block
 * ids, zone names, extractor versions, thresholds) out of the UI.
 */

export const QUALITY_DISCLAIMER =
  'Automatic checks, not confirmed errors. They point at places where the Indicators list may be incomplete or include something it should not. Nothing was changed.';

const STATUS = Object.freeze({
  clean: { label: 'No issues found', tone: 'success' },
  info: { label: 'Notes only', tone: 'info' },
  warning: { label: 'Review suggested', tone: 'warning' },
  high: { label: 'Likely incomplete', tone: 'danger' }
});

const SEVERITY = Object.freeze({
  high: { label: 'Likely issue', tone: 'danger', rank: 3 },
  warning: { label: 'Check', tone: 'warning', rank: 2 },
  info: { label: 'Note', tone: 'info', rank: 1 }
});

/** Reason code → analyst wording. `why` explains what the check saw. */
export const QUALITY_CODE_COPY = Object.freeze({
  indicator_rows_adjacent_to_authoritative_scope: {
    title: 'Indicator-like rows just outside the IOC section',
    why: 'These values are laid out like the publisher’s IOC list and sit right next to it, but were read as outside it, so they are not Indicators. A sub-heading may have ended the IOC section early.'
  },
  indicator_rows_outside_authoritative_scope: {
    title: 'Indicator-like rows outside the IOC section',
    why: 'Values laid out as a list or table outside the publisher’s IOC section are not Indicators. This is usually an analysis table, occasionally a missed IOC list.'
  },
  appendix_without_hash_indicators: {
    title: 'No file hashes became Indicators',
    why: 'The report has an IOC section and lists file hashes in or right next to it, but none of them is an Indicator.'
  },
  appendix_hash_indicators_low: {
    title: 'Fewer hash Indicators than expected',
    why: 'More file hashes in or right next to the IOC section were left out than included.'
  },
  authoritative_section_without_indicators: {
    title: 'IOC section produced no Indicators',
    why: 'A section the publisher labels as IOCs contains indicator-like text, but no Indicator came from it.'
  },
  authoritative_section_empty: {
    title: 'IOC heading without values',
    why: 'The publisher may list its IOCs elsewhere, for example in a linked repository. Add it as an IOC Source if so.'
  },
  authoritative_section_values_not_asserted: {
    title: 'IOC section values written as running text',
    why: 'Values inside the IOC section were not laid out as a list, so they were not taken as publisher-listed Indicators.'
  },
  authoritative_table_not_interpreted: {
    title: 'Table in the IOC section not recognised',
    why: 'A table with indicator-like values in the IOC section was not read as an indicator table.'
  },
  explicit_table_rows_dropped: {
    title: 'Indicator table rows were dropped',
    why: 'Values listed in an indicator table did not become candidates.'
  },
  table_observable_not_extracted: {
    title: 'Hash or IP in the IOC table was not read',
    why: 'A hash or IP address written in the indicator column of an IOC table did not become a candidate. The cell may combine a file name or path with the value.'
  },
  content_inferred_hash_column: {
    title: 'Second hash column may be a certificate attribute',
    why: 'A column whose header names no hash type was read as hashes next to the declared hash column. It may hold certificate thumbprints or serials rather than samples.'
  },
  undelegated_suffix_domain_indicator: {
    title: 'Indicator domain with a non-public suffix',
    why: 'The domain ends in a suffix that does not exist in public DNS. It may be a system or code identifier rather than a host.'
  },
  indicators_from_structural_discovery: {
    title: 'Indicators taken from a table or list without an IOC heading',
    why: 'These Indicators come only from a table or list that looked like an IOC list, not from the publisher’s IOC section. Check they are not lookup results, look-alike samples or services the report calls legitimate.'
  },
  appendix_heading_nonmember_rows: {
    title: 'IOC-section heading with rows left out',
    why: 'Values under an Indicators or C2 heading were not kept inside that section, so they are not Indicators. A nested list heading or sibling sub-heading may have closed the section early.'
  },
  analyst_state_membership_divergence: {
    title: 'Analyst decisions change the publisher Indicators',
    why: 'After a refresh, re-applied analyst decisions keep or remove Indicators differently from how the publisher’s text reads. An explicit promotion or Context Only decision is expected; any other difference should be checked.'
  },
  body_ioc_table_outside_appendix: {
    title: 'Body table contributed Indicators outside the IOC section',
    why: 'An analysis table that looks like an IOC inventory produced Indicators that do not also appear under the publisher’s headed IOC section. Confirm they are publisher-asserted, not lookup attributes.'
  },
  reserved_or_loopback_indicator: {
    title: 'Reserved or local address is an Indicator',
    why: 'Private, reserved or loopback addresses are not attacker infrastructure.'
  },
  documentation_example_indicator: {
    title: 'Example value is an Indicator',
    why: 'Documentation / example names (such as example.com) are rarely real infrastructure.'
  },
  indicator_with_legitimate_marker: {
    title: 'Indicator also described as legitimate',
    why: 'The report also calls this value a legitimate or signed component.'
  },
  publisher_domain_indicator: {
    title: 'Publisher’s own domain is an Indicator',
    why: 'The value belongs to the publisher’s own domain.'
  },
  indicator_only_email_domain: {
    title: 'Indicator seen only in an email address',
    why: 'The domain appears only as part of an email address, often a contact or sender address.'
  },
  indicator_missing_provenance: {
    title: 'Indicator without source evidence',
    why: 'No source passage is recorded for this Indicator.'
  },
  delegated_authority_applied: {
    title: 'IOC section is empty — Indicators come from the report body',
    why: 'Every IOC heading in this report only points elsewhere (for example a download link). These Indicators come from the publisher’s own statements in the body: C2 endpoints, download sources, analysed samples and infrastructure table columns. Narrative mentions stayed Context Only. Review them, and add the publisher’s IOC file as an IOC Source when available.'
  },
  non_file_digest_reclassified: {
    title: 'Hash-shaped values that are not file hashes',
    why: 'The publisher labels these values as build IDs, certificate fingerprints, VirusTotal / fuzzy hashes, keys or digests of trivial strings. They were kept as context, not as file-hash Indicators.'
  },
  publisher_stance_conflict: {
    title: 'Indicator also called legitimate or dual-use',
    why: 'The publisher lists this value as an indicator in one place and describes it as legitimate, dual-use or not inherently malicious in another. It stays an Indicator; check the publisher’s stance before acting on it.'
  },
  ai_evidence_ungrounded: {
    title: 'Model quote not found in the report',
    why: 'The model proposed an evidence quote that does not appear in the report text. The publisher’s own passage was kept; the model text is stored only as a rejected suggestion.'
  },
  ai_escalation_unsupported: {
    title: 'Model malicious label without supporting text',
    why: 'The model labelled these values malicious or suspicious but cited no report passage that names them. The label was not applied.'
  },
  malicious_assessed_non_members: {
    title: 'Malicious-looking values outside the publisher’s IOC list',
    why: 'These values are assessed malicious but the publisher did not list them in its IOC section, so they are not Indicators. They stay visible under All.'
  },
  ioc_section_url_prefix_excluded: {
    title: 'Directory URL excluded as an incomplete prefix',
    why: 'A URL ending in “/” was treated as an incomplete prefix of a longer sibling URL. If the publisher listed that directory as its own IOC-table row, review whether it should be an Indicator.'
  },
  reference_column_values_context: {
    title: 'Tool Source / Reference links kept as Context Only',
    why: 'URLs from Source, Reference, Download or Homepage columns describe where a tool is published, not actor infrastructure. They stay Context Only.'
  },
  resolution_column_values_context: {
    title: 'Resolved addresses kept as Context Only',
    why: 'Addresses from a Resolved IP / A record column are what a listed domain resolved to — often shared CDN infrastructure. The row’s own domain or IP is the Indicator; these stay Context Only.'
  },
  reference_column_indicator: {
    title: 'Indicator came only from a reference-labelled column',
    why: 'This Indicator was read only from a table column whose header names a reference, source or download link. Confirm the publisher attributes it to the actor before acting on it.'
  },
  non_file_digest_indicator_suspect: {
    title: 'File-hash Indicator that may be a key or banner digest',
    why: 'The row or sentence calls this digest a key, certificate, fingerprint or banner hash and does not name a file. Such digests usually identify no sample — review the hash type.'
  },
  ioc_package_announced: {
    title: 'Publisher announces a downloadable IOC package',
    why: 'The report points at a STIX, JSON, CSV or repository pack that may hold additional indicators. Review it as a linked IOC Source; nothing is ingested automatically.'
  },
  ai_demoted_table_rows: {
    title: 'Model demoted some rows of an Indicator table',
    why: 'The model set some table-row values to Context Only while other rows of the same table and type remain Indicators. Review the table as a whole — a publisher inventory should not split arbitrarily.'
  },
  file_name_column_network_conflict: {
    title: 'Filename-column typing discarded a network IOC',
    why: 'An IOC-table value was typed as a file name because sibling cells were filenames, while the publisher row still describes a domain, C2 host, or contacted infrastructure. Confirm the network identity was not dropped.'
  }
});

const GENERIC = Object.freeze({ title: 'Extraction check', why: 'An automatic check flagged this report.' });

/** `type:value` identity → display parts (the type is before the first colon). */
export function splitIdentity(identity) {
  const s = String(identity || '');
  const i = s.indexOf(':');
  if (i <= 0) return { type: '', value: s };
  return { type: s.slice(0, i), value: s.slice(i + 1) };
}

const TYPE_LABELS = Object.freeze({
  md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', ip: 'IP', ipv6: 'IPv6', domain: 'Domain', url: 'URL', cidr: 'CIDR'
});

export function identityTypeLabel(type) {
  return TYPE_LABELS[String(type || '').toLowerCase()] || String(type || '').toUpperCase();
}

function contextLine(w) {
  const s = w?.section || {};
  const heading = s.heading ? `“${s.heading}”` : null;
  if (s.adjacent_authoritative_heading && heading) return `Under ${heading}, next to “${s.adjacent_authoritative_heading}”.`;
  if (heading) return `Section ${heading}.`;
  return null;
}

/**
 * @param {object|null|undefined} quality report.extraction_quality
 * @param {{ maxValues?: number }} [opts]
 */
export function describeExtractionQuality(quality, opts = {}) {
  const maxValues = opts.maxValues ?? 5;
  if (!quality || typeof quality !== 'object') {
    return {
      assessed: false,
      statusLabel: 'Not checked yet',
      tone: 'muted',
      headline: 'Extraction checks run on import and on Refresh extraction.',
      items: [],
      attention: 0
    };
  }
  const status = STATUS[quality.status] ? quality.status : 'clean';
  const items = (Array.isArray(quality.warnings) ? quality.warnings : [])
    .map((w, idx) => {
      const copy = QUALITY_CODE_COPY[w.code] || GENERIC;
      const sev = SEVERITY[w.severity] || SEVERITY.info;
      const values = (Array.isArray(w.candidates) ? w.candidates : []).map(splitIdentity);
      const total = Number.isFinite(Number(w.candidate_count)) ? Number(w.candidate_count) : values.length;
      return {
        key: `${w.code}-${idx}`,
        code: w.code,
        severity: w.severity,
        severityLabel: sev.label,
        tone: sev.tone,
        rank: sev.rank,
        title: copy.title,
        why: copy.why,
        context: contextLine(w),
        values: values.slice(0, maxValues).map((v) => ({ ...v, typeLabel: identityTypeLabel(v.type) })),
        moreValues: Math.max(0, total - Math.min(values.length, maxValues))
      };
    })
    .sort((a, b) => b.rank - a.rank);
  const attention = items.filter((i) => i.severity === 'high' || i.severity === 'warning').length;
  const notes = items.length - attention;
  const headline = attention
    ? `${attention} ${attention === 1 ? 'check needs' : 'checks need'} review${notes ? ` · ${notes} ${notes === 1 ? 'note' : 'notes'}` : ''}`
    : notes
      ? `${notes} ${notes === 1 ? 'note' : 'notes'}, nothing that needs review`
      : 'No issues found by the automatic checks.';
  return {
    assessed: true,
    status,
    statusLabel: STATUS[status].label,
    tone: STATUS[status].tone,
    headline,
    items,
    attention,
    disclaimer: QUALITY_DISCLAIMER
  };
}

/**
 * Compact header chip: only when something needs review.
 * @param {object|null|undefined} quality
 * @returns {{ label: string, tone: string, title: string }|null}
 */
export function describeQualityChip(quality) {
  const d = describeExtractionQuality(quality);
  if (!d.assessed || !d.attention) return null;
  return {
    label: `Extraction check · ${d.attention}`,
    tone: d.tone,
    title: `${d.statusLabel}: ${d.headline}. Automatic signal, not a confirmed error. See Overview.`
  };
}
