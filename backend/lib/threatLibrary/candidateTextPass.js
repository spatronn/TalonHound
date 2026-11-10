/**
 * Free-text passes over every block not read as a typed table: URLs first, then
 * the other observable shapes. A value inside a URL span belongs to that URL.
 */

import { isValidIpAddress } from '../publicIp.js';
import { STRONG_IOC_ZONES } from './documentZones.js';
import { hostnameFromUrl, pathBasenameFromUrl } from './candidateTyping.js';
import { findTruncatedDigests } from './tableSemantics.js';
import { ipv4VersionContext } from './ipv4VersionContext.js';
import { lineContainingObservable } from './indicatorScope.js';
import { RESOLVED_TYPES, trimUrlBoundary, validateUrlCandidate } from './observableTypeResolver.js';
import { hexRunIsHostnameLabelFragment, hexRunIsIdentifierSuffix, ipv4MatchIsStandalone } from './sourceOccurrence.js';
import { findIpv6Tokens } from './ipv6Tokens.js';
import { recoverDefangedLinkDomain, versionColumnTokens, IPV4_RE, IPV4_PORT_RE, IPV6_LOOPBACK_RE, URL_RE, HOST_PATH_RE, IPV4_HOST_PATH_HEAD_RE, IP_HOST_PATH_RE, trimShellContinuation, NETWORK_ENDPOINT_RE, DOMAIN_RE, IDN_DOMAIN_RE, DEFANGED_AT_BEFORE_RE, SPOOFED_SENDER_RE, isTruncatedHostTail, CVE_RE, ATTACK_RE, OCCURRENCE_FORMS, sourceSpelling, standaloneLineSpelling, portFromUrl, insideAnySpan, hitOffsets, HASH_PATTERNS, candidateKey } from './candidateHelpers.js';

/**
 * "0x" + exactly an MD5 run (tl-candidates-v62). "0x" + 40 / 64 hex is an EVM
 * address / transaction hash, never a SHA-1 / SHA-256.
 */
const HEX_LITERAL_DIGEST_SCAN_RE = /(?<![0-9a-z_])0x([0-9a-f]{32})(?![0-9a-z_])/gi;

/**
 * The block's own hyperlink text when it is a strict tail of a scheme-less
 * host/path match that markup glued onto a preceding word: the anchor is the
 * publisher's resource, the glued head is a different element's text.
 * @param {object} block
 * @param {string} raw
 * @returns {string|null}
 */
function anchorBoundedResource(block, raw) {
  const links = Array.isArray(block?.links) ? block.links : [];
  for (const link of links) {
    const lt = String(link?.text || '').trim();
    if (!lt || lt.length >= raw.length || !lt.includes('/') || !raw.endsWith(lt)) continue;
    // Glued: the head ends in a word character directly against the anchor.
    if (!/[A-Za-z0-9]$/.test(raw.slice(0, raw.length - lt.length))) continue;
    return lt;
  }
  return null;
}

/**
 * @param {object[]} blocks zone-annotated blocks
 * @param {ReturnType<import('./candidateAccumulator.js').createCandidateAccumulator>} acc
 * @param {{ typeDiag: object, tableHandled: Set, networkEndpoints: Array, scanText: Function, isObservableRow: Function, noteRejectedToken: Function }} ctx
 */
export function readDocumentText(blocks, acc, ctx) {
  const { add, rememberPort, countReason, deferTruncatedDigest, urlHostIndex, urlPathBasenames, knownUrlHosts } = acc;
  const { typeDiag, tableHandled, networkEndpoints, scanText, isObservableRow, noteRejectedToken } = ctx;
  // Pass 1: URLs — one candidate per URL; host/port/basename are parsed metadata only.
  /** @type {Map<string, Array<[number, number]>>} block id → URL spans */
  const urlSpansByBlock = new Map();
  for (const block of blocks) {
    if (tableHandled.has(block.id)) continue;
    const text = scanText(block);
    if (!text.trim()) continue;
    const spans = [];
    for (const m of text.matchAll(URL_RE)) {
      // Code interpolation ends the literal URL: `…/read?domain=${encodeURIComponent(d)}`
      // is the publisher URL "…/read?domain=" followed by a template expression.
      const literal = m[0].split('${')[0];
      const url = trimShellContinuation(trimUrlBoundary(literal));
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
    const hostPathMatches = [...text.matchAll(HOST_PATH_RE), ...text.matchAll(IP_HOST_PATH_RE)].sort((a, b) => a.index - b.index);
    for (const m of hostPathMatches) {
      let start = m.index;
      let raw = trimShellContinuation(trimUrlBoundary(m[0]));
      // Adjacent inline markup glued a label onto the anchor
      // ("<span>CVE-2026-1234</span><a>www.vendor.example/advisory</a>"):
      // the structured link text bounds the resource (tl-candidates-v62).
      const anchored = anchorBoundedResource(block, raw);
      if (anchored) {
        start += raw.length - anchored.length;
        raw = anchored;
      }
      if (!raw || insideAnySpan(spans, start, start + raw.length)) continue;
      // The glued head belongs to the span too: it is not a host of its own.
      const spanStart = anchored ? m.index : start;
      const v = validateUrlCandidate(raw);
      const ipHost = v.host_kind === 'ip';
      if (!v.ok || v.reason !== 'scheme_less_url_with_dns_host' || (ipHost && !IPV4_HOST_PATH_HEAD_RE.test(raw))) {
        countReason(typeDiag.scheme_less_resources.rejected, v.reason || 'invalid');
        continue;
      }
      const path = raw.slice(raw.indexOf('/'));
      if (path.length < 2) continue;
      spans.push([spanStart, start + raw.length]);
      const base = pathBasenameFromUrl(`http://${raw}`);
      if (v.host) knownUrlHosts.add(v.host);
      if (base && base.includes('.')) urlPathBasenames.add(base.toLowerCase());
      const isRow = isObservableRow(block);
      const entry = add(raw, 'url', block, {
        form: isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.URL,
        originalValue: sourceSpelling(block.text, raw),
        typing: { typing_reason: ipHost ? 'scheme_less_url_with_ip_host' : 'scheme_less_url_with_dns_host' }
      });
      typeDiag.scheme_less_resources.count += 1;
      if (entry) {
        entry.parsed.scheme = null;
        entry.parsed.scheme_less = true;
        entry.parsed.path = path;
        if (v.host && !entry.parsed.host) {
          entry.parsed.host = v.host;
          entry.parsed.host_kind = ipHost ? 'ip' : 'domain';
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
    const text = scanText(block);
    if (!text.trim()) continue;
    const urlSpans = urlSpansByBlock.get(block.id) || [];
    const isRow = isObservableRow(block);
    const standaloneForm = isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.STANDALONE;
    /** @type {Array<[number, number]>} */
    const consumed = [];
    const versionTokens = versionColumnTokens(block);
    // Prose version reading applies outside publisher IOC sections and rows,
    // where a bare value is the publisher's assertion and stays authoritative.
    const proseVersions = !isRow && !STRONG_IOC_ZONES.has(block.zone || '');

    // Non-HTTP transport endpoints ("tcp://host:443"): the host, read as a
    // declared network host with its port; the endpoint spelling is provenance.
    for (const m of text.matchAll(NETWORK_ENDPOINT_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      const host = m[2].toLowerCase();
      const isIp = isValidIpAddress(host);
      const port = m[3] && Number(m[3]) >= 1 && Number(m[3]) <= 65535 ? Number(m[3]) : null;
      const added = add(host, isIp ? 'ip' : 'domain', block, {
        form: isIp && port != null ? OCCURRENCE_FORMS.IP_PORT : standaloneForm,
        port,
        declaredType: isIp ? null : 'domain',
        typing: { typing_reason: 'network_endpoint_scheme' }
      });
      if (added) {
        networkEndpoints.push([isIp ? 'ip' : 'domain', host, m[0]]);
        consumed.push([start, end]);
      }
    }

    // IPv6 first: its spans keep an IPv4-mapped tail (`::ffff:192.0.2.1`)
    // from also reading as a separate IPv4 address.
    const ipv6Tokens = findIpv6Tokens(text).filter((t) => !insideAnySpan(urlSpans, t.start, t.end));
    const ipv6Spans = ipv6Tokens.map((t) => [t.start, t.end]);

    // IP:port endpoints (direct C2 endpoint assertions)
    for (const m of text.matchAll(IPV4_PORT_RE)) {
      const start = m.index;
      const ipEnd = start + m[1].length;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(ipv6Spans, start, end)) continue;
      if (!ipv4MatchIsStandalone(text, start, ipEnd)) continue;
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
      const raw = String(m[0]);
      const slash = raw.indexOf('/');
      const ipEnd = start + (slash >= 0 ? slash : raw.length);
      const end = start + raw.length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end) || insideAnySpan(ipv6Spans, start, end)) continue;
      if (!ipv4MatchIsStandalone(text, start, ipEnd)) continue;
      if (slash >= 0) add(raw, 'cidr', block, { form: standaloneForm });
      else if (versionTokens?.inVersion.has(raw) && !versionTokens.elsewhere.has(raw)) {
        // A release number in a software-version column ("Versions Affected":
        // 2.3.20.2) is version metadata, not an address. The same string in any
        // other cell of the table keeps the IPv4 reading.
        add(raw, RESOLVED_TYPES.TECHNICAL_ARTIFACT, block, {
          form: standaloneForm,
          originalValue: raw,
          typing: { typing_reason: 'version_column', artifact_kind: 'metadata' }
        });
      } else {
        const version = proseVersions ? ipv4VersionContext(text, start, end, { code: block.type === 'code' }) : null;
        if (version) {
          // A release number in prose ("Apache Struts 2.3.24.1 is vulnerable") is
          // version metadata; the same value under a network cue elsewhere keeps
          // its own IPv4 occurrence and identity.
          add(raw, RESOLVED_TYPES.TECHNICAL_ARTIFACT, block, {
            form: standaloneForm,
            originalValue: raw,
            typing: { typing_reason: 'version_context', artifact_kind: 'metadata' }
          });
        } else add(raw, 'ip', block, { form: standaloneForm });
      }
    }
    for (const t of ipv6Tokens) {
      // A prefix length glued to the address ("2607:99c0::/32") makes it an
      // IPv6 network block, never the bare network address (tl-candidates-v41).
      const prefix = /^\/(\d{1,3})(?![\d./\w])/.exec(text.slice(t.end));
      if (!ipv4MatchIsStandalone(text, t.start, t.end)) continue;
      if (prefix && Number(prefix[1]) <= 128) {
        add(`${t.value}/${prefix[1]}`, 'cidr', block, { form: standaloneForm });
        continue;
      }
      add(t.value, 'ipv6', block, { form: standaloneForm });
    }
    for (const m of text.matchAll(IPV6_LOOPBACK_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end)) continue;
      add(m[0], 'ipv6', block, { form: standaloneForm });
    }
    // A hex run inside a URL / scheme-less resource span is that URL's path,
    // query or fragment component, not an independent file-hash occurrence.
    // Containment is per occurrence: a standalone spelling of the same value
    // in this block (or elsewhere) still creates the hash, and its evidence
    // window is anchored on that spelling, not on the URL copy.
    // A digest the publisher cut short with an ellipsis ("SHA256: e76f54b7…")
    // is a prefix of the full digest stated elsewhere in the report, never a
    // shorter digest of its own: link it to that digest when it is unique,
    // otherwise read the run as before (tl-candidates-v54).
    const truncatedDigestSpans = [];
    for (const trunc of findTruncatedDigests(text)) {
      const truncEnd = trunc.index + trunc.spelling.length;
      if (insideAnySpan(urlSpans, trunc.index, truncEnd)) continue;
      truncatedDigestSpans.push([trunc.index, truncEnd]);
      const line = lineContainingObservable(text, trunc.spelling);
      const lookalikeType = trunc.prefix.length === 32 ? 'md5' : trunc.prefix.length === 40 ? 'sha1' : null;
      deferTruncatedDigest(
        trunc,
        block,
        { form: standaloneForm, rowText: line, evidenceRowText: line },
        lookalikeType ? () => add(trunc.prefix, lookalikeType, block, { form: standaloneForm }) : null
      );
    }
    for (const [re, type] of HASH_PATTERNS) {
      for (const m of text.matchAll(re)) {
        if (insideAnySpan(urlSpans, m.index, m.index + m[0].length)) continue;
        if (insideAnySpan(truncatedDigestSpans, m.index, m.index + m[0].length)) continue;
        // `pub-<hex>.r2.dev`: the run is part of a hostname label, not a hash.
        if (hexRunIsHostnameLabelFragment(text, m.index, m.index + m[0].length)) {
          noteRejectedToken(m[0], type, block, 'hex_in_hostname_label');
          continue;
        }
        // `anonymous-<hex>`: the generated suffix of an account name (v55).
        if (hexRunIsIdentifierSuffix(text, m.index, m.index + m[0].length)) {
          noteRejectedToken(m[0], type, block, 'hex_identifier_suffix');
          continue;
        }
        const focusOrdinal = hitOffsets(text.slice(0, m.index), m[0]).length;
        add(m[0], type, block, { form: standaloneForm, focusOrdinal });
      }
    }
    // An MD5 written as a hex literal ("0xFD91…") is that digest when the
    // literal opens its own line or list row (an inventory entry, optionally
    // followed by its description). Inside prose or code a 0x run is a
    // constant / key, never read as a digest (tl-candidates-v62).
    if (block.type !== 'code') {
      for (const m of text.matchAll(HEX_LITERAL_DIGEST_SCAN_RE)) {
        const lineStart = text.lastIndexOf('\n', m.index) + 1;
        if (!/^\s*(?:[-*•·▪]\s*)?$/.test(text.slice(lineStart, m.index))) continue;
        add(m[1], 'md5', block, { form: standaloneForm, originalValue: m[0] });
      }
    }
    for (const m of text.matchAll(CVE_RE)) add(m[0], 'cve', block, { form: standaloneForm });
    for (const m of text.matchAll(ATTACK_RE)) {
      if (/^T(1\d{3}|10\d{2}|11\d{2}|12\d{2}|15\d{2}|16\d{2})/.test(m[0])) {
        add(m[0], 'attack_technique', block, { form: standaloneForm });
      }
    }
    for (const m of text.matchAll(DOMAIN_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end)) continue;
      // The local part of an email address ("decrypt.support@mail.example")
      // is a mailbox name whose dots only look like a hostname
      // (tl-candidates-v37): never a domain of its own.
      if (/^@[a-z0-9]/i.test(text.slice(end, end + 2))) continue;
      // Truncated publisher hostname: "online-driver.kro.k" (from "kro[.]k")
      // matches DOMAIN_RE as the prefix "...kro" because a 1-char final label
      // cannot be a TLD. Do not invent a shorter complete domain from that.
      if (/^\.[a-z0-9](?![a-z0-9-])/i.test(text.slice(end))) continue;
      // "log.events.vc0" (an appliance log file): the dotted token goes on
      // with a label carrying a digit, which no TLD has, so its prefix
      // "log.events" is not a hostname of its own (tl-candidates-v52).
      if (/^\.[a-z0-9-]*\d[a-z0-9-]*(?![a-z0-9.-])/i.test(text.slice(end))) continue;
      // Redacted / truncated publisher hostname: "<REDACTED>-my.sharepoint.com"
      // matches only its tail "my.sharepoint.com". A hostname label never
      // starts with "-", and a redaction placeholder glued with "." hides the
      // leading labels: the tail is a different (parent) host, never derive it.
      if (isTruncatedHostTail(text, start)) continue;
      // `user@host.example`: the host is the address's domain (same
      // no-over-derivation rule as a URL host). Email is not a candidate type,
      // so the domain stays a candidate but never a structural row assertion.
      // A defanged at-sign ("hello[@]boots[.]com") is the same address when the
      // publisher says the sender is spoofed / impersonated: the domain is the
      // impersonated brand's, not the actor's (tl-candidates-v40). Other
      // defanged addresses in an IOC list keep their row reading.
      const emailDomain = start > 0 && (
        text[start - 1] === '@' ||
        (DEFANGED_AT_BEFORE_RE.test(text.slice(Math.max(0, start - 5), start)) &&
          SPOOFED_SENDER_RE.test(text.slice(Math.max(0, start - 160), end + 160)))
      );
      // `host.example:443`: keep the port as parsed endpoint context of the
      // domain (the occurrence form stays standalone — a port alone asserts
      // nothing about a hostname the way an ip:port endpoint does).
      const portM = emailDomain ? null : /^:(\d{1,5})(?!\d)/.exec(text.slice(end));
      const port = portM && Number(portM[1]) > 0 && Number(portM[1]) <= 65535 ? Number(portM[1]) : null;
      // Prefer structured link text when flattened block text glued a
      // one-letter conjunction onto a defanged domain (tl-candidates-v42).
      const recovered = recoverDefangedLinkDomain(block, m[0]);
      const spelling = recovered || m[0];
      // Original spelling: identifier segmentation (Loader.Program.Main) is case-visible.
      add(spelling, 'domain', block, {
        form: emailDomain ? OCCURRENCE_FORMS.EMAIL_DOMAIN : standaloneForm,
        originalValue: spelling,
        // Only a token alone on its line (an indicator list / pack row): inside
        // prose or code the refanged reading decides, as before.
        typingSpelling: standaloneLineSpelling(block.text, spelling),
        ...(port != null ? { port } : {})
      });
    }
    // Internationalised hostnames ("adidaš[.]com" in a lookalike-domain list):
    // one candidate in IDNA A-label form, the Unicode spelling kept as the
    // original value (tl-candidates-v59). ASCII-only matches belong to DOMAIN_RE.
    for (const m of text.matchAll(IDN_DOMAIN_RE)) {
      if (!/[^\x00-\x7f]/.test(m[0])) continue;
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end)) continue;
      if (/^@[\p{L}\p{N}]/u.test(text.slice(end, end + 2))) continue;
      const emailDomain = start > 0 && text[start - 1] === '@';
      add(m[0], 'domain', block, {
        form: emailDomain ? OCCURRENCE_FORMS.EMAIL_DOMAIN : standaloneForm,
        originalValue: m[0],
        typingSpelling: standaloneLineSpelling(block.text, m[0])
      });
    }
  }
}
