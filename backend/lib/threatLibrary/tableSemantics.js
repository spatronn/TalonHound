/**
 * Generic IOC table interpreter (format-, vendor- and language-independent).
 *
 * A canonical table block carries `table.headers` / `table.rows` (cell text in
 * DOM / reading order). This module decides whether the table is an explicit
 * indicator table and, if so, turns every row into typed source assertions:
 *
 *   declared type cell  →  expected observable type (hint, never authority)
 *   indicator cell      →  refang → validate → normalized identity (string)
 *   description cell    →  retained verbatim as provenance / evidence
 *
 * Column intent comes from normalized header labels when they are recognisable
 * (English / Turkish / German / Spanish / Portuguese / French / Russian / CJK
 * hints) and otherwise from the cells themselves: a column whose cells parse
 * as observables is the indicator column whatever its header says, and a
 * column whose cells are observable-type labels is the type column. Nothing
 * here matches a vendor, a URL or a specific indicator value.
 */

import { isIPv6 } from 'node:net';
import { normalizeCandidateValue } from './candidateValue.js';
import { refangObservable } from './defang.js';
import { resolveDottedTokenType } from './candidateTyping.js';
import { FILE_EXT_HINT, NON_NETWORK_RESOLVED_TYPES, trimUrlBoundary } from './observableTypeResolver.js';

/**
 * The absolute http(s) URL embedded after other text in one whitespace-free
 * token (a call argument or quoted string in a command cell), boundary-trimmed.
 * @param {string} token refanged cell token
 * @returns {string|null}
 */
function embeddedAbsoluteUrl(token) {
  const t = String(token || '');
  const at = t.search(/https?:\/\//i);
  if (at <= 0) return null;
  const url = trimUrlBoundary(t.slice(at).replace(/["'`].*$/, ''));
  return /^https?:\/\/[^/\s]+/i.test(url) ? url : null;
}

/**
 * v3: dense headerless observable grids (e.g. a narrative table of public
 * third-party endpoints) are no longer self-proving IOC tables. Explicitness
 * requires a type column or a header-labelled indicator column; publisher IOC
 * headings still assert rows by section inheritance without that structure.
 * v4: inline type labels in a multi-value cell ("MD5: … SHA-256: …") are
 * labels, not rejected values, so a labelled Hashes column is the indicator
 * column; a dotted value in a file-name column is a file name.
 * v5: a column labelled as a software version ("Versions Affected", "Build
 * Number") is never an indicator column, whatever its values look like.
 * v6: Filename|MD5 (file-name + hash) component inventories outside an
 * authoritative IOC / C2 / sample heading are not self-proving IOC tables —
 * they stay non-explicit so MODE A membership requires the publisher's curated
 * appendix (or a real sample/IOC heading).
 * v7: outside headed IOC / C2 / sample scope, a table self-proves only when it
 * declares a type column or sits under an authoritative IOC caption — not
 * merely because headers look like Domain / IP / MD5. Infrastructure-lookup
 * tables (First seen / ASN / registrar) and file-hash inventories never
 * self-prove from body analysis context alone.
 * v8: a mixed indicator cell whose leading value is a file path / file name
 * is decomposed: the file identity stays a non-network value and every
 * hash / network value of the remainder is a value of the cell (cell
 * companions); a remainder that is prose is reported, never silently dropped.
 * Bracketed tokens and bare type labels ("(SHA-256") no longer reject a
 * cell's hash. Certificate / fuzzy-hash attribute headers (thumbprint, serial,
 * signer, issuer, imphash, ssdeep, TLSH) name attribute columns, never
 * indicator columns.
 * v9: a reference column ("Source", "Reference", "Download", "Homepage",
 * "Project", "Repository" over URL cells) names where a row's subject is
 * published and is never an indicator column; an explicit endpoint (ip:port,
 * URL) in the unparsed remainder of a mixed indicator cell is a value of the
 * cell; a cell holding one URL wrapped onto two lines is one value.
 * v10: a bare IPv6 cell is an IP value (trailing `::` is not punctuation); a
 * defanged cell spelling reaches the dotted-token resolver; a resolution
 * column ("Resolved IP", "A record") is an attribute of the row's own
 * indicator, never an indicator column.
 * v11: filename-column consistency demotes only ambiguous file/TLD collisions
 * (`back.pl`, `tool.py`) or rows with explicit file evidence — never a clear
 * publisher-asserted domain (`evil[.]net` / “Domain contacted…”) merely because
 * sibling Item-column cells are filenames.
 */
export const TABLE_SEMANTICS_VERSION = 'tl-table-v11';

export const COLUMN_INTENTS = Object.freeze({
  TYPE: 'type',
  INDICATOR: 'indicator',
  DESCRIPTION: 'description',
  OTHER: 'other'
});

/** Header label hints per intent (normalized: lowercase, punctuation stripped). */
const HEADER_HINTS = Object.freeze({
  type: [
    /^(?:ioc|indicator|observable|value|artifact|artefact)?\s*(?:type|types|typ|kind|category)$/,
    /^(?:ioc|gösterge|gosterge)?\s*(?:tür|tur|türü|turu|tip|tipi|kategori)$/,
    /^(?:tipo|art|typ|catégorie|categoria|categoría)$/,
    /^(?:类型|類型|种类|種類|種別|指标类型|тип|тип индикатора)$/
  ],
  indicator: [
    /^(?:indicator|indicators|ioc|iocs|observable|observables|value|values|artifact|artifacts|artefact|artefacts)$/,
    /^(?:indicator|ioc)\s*(?:value|values)$/,
    /^(?:hash|hashes|file\s*hash|file\s*hashes|sha\s*-?\s*256|sha\s*-?\s*1|md5|sha256|sha1)$/,
    /^(?:ip|ips|ipv4|ipv6|ip\s*address|ip\s*addresses|ip\s*addr|address|addresses|c2|c2\s*server|c2\s*servers|server|servers|endpoint|endpoints)$/,
    /^(?:domain|domains|hostname|hostnames|fqdn|fqdns|host|hosts|url|urls|uri|link|links)$/,
    /^(?:gösterge|gostergeler|göstergeler|gosterge|değer|deger|değerler|degerler|ip\s*adresi|alan\s*adı|alan\s*adi|bağlantı|baglanti|karma|özet|ozet)$/,
    /^(?:indicador|indicadores|valor|valores|indikator|indikatoren|wert|werte|indicateur|indicateurs|valeur|valeurs|dominio|domínio|domaine|adresse\s*ip|dirección\s*ip)$/,
    /^(?:指标|指標|值|数值|哈希|散列|域名|网址|链接|ip地址|индикатор|индикаторы|значение|хеш|домен|адрес)$/
  ],
  description: [
    /^(?:description|descriptions|desc|context|note|notes|comment|comments|detail|details|remark|remarks|purpose|role|usage|meaning|malware|family|malware\s*family|threat|campaign|filename|file\s*name|tag|tags|label)$/,
    /^(?:açıklama|aciklama|not|notlar|yorum|açıklamalar|amaç|rol|kullanım|kullanim|dosya\s*adı|dosya\s*adi)$/,
    /^(?:descripción|descripcion|descrição|descricao|beschreibung|kommentar|anmerkung|commentaire|notas|observaciones|observações)$/,
    /^(?:描述|说明|備考|备注|注释|用途|说明信息|описание|комментарий|примечание|назначение)$/
  ]
});

/**
 * Observable type labels found in a "Type" column (or column header).
 * Order matters: sha256 before sha1, ipv6 before ip.
 */
const DECLARED_TYPE_HINTS = Object.freeze([
  { type: 'sha256', re: /sha[\s_-]?256/ },
  { type: 'sha1', re: /sha[\s_-]?1(?![0-9])/ },
  { type: 'md5', re: /\bmd5\b/ },
  { type: 'hash', re: /(?:^|\b)(?:hash|hashes|file\s*hash|karma|özet|ozet|哈希|散列|хеш|хэш)(?:\b|$)/ },
  { type: 'ipv6', re: /\bipv6\b/ },
  { type: 'ip', re: /(?:^|\b)(?:ip|ipv4|ip\s*address(?:es)?|ip\s*addr|ip\s*adresi|ip\s*adresleri|ip地址|ip\s*адрес|dirección\s*ip|adresse\s*ip|endereço\s*ip)(?:\b|$)/ },
  { type: 'domain', re: /(?:^|\b)(?:domain|domains|hostname|hostnames|fqdn|alan\s*adı|alan\s*adi|域名|домен|dominio|domínio|domaine)(?:\b|$)/ },
  { type: 'url', re: /(?:^|\b)(?:url|urls|uri|link|links|bağlantı|baglanti|网址|链接|ссылка|enlace|lien)(?:\b|$)/ },
  { type: 'email', re: /(?:^|\b)(?:e-?mail|e-?posta|邮箱|电子邮件|почта|correo)(?:\b|$)/ },
  { type: 'cve', re: /\bcve\b/ },
  { type: 'attack_technique', re: /(?:technique|att&ck|attack\s*id|mitre)/ }
]);

const ENDPOINT_LABEL_RE = /(?:port|endpoint|socket|:\s*port|&\s*port|ve\s*port|端口|порт|puerto|porta)/;

/** Table headings that describe victims / targets / fixed versions rather than adversary infrastructure. */
const NEGATIVE_TABLE_CONTEXT_RE =
  /\b(?:victim|victims|target|targets|targeted|affected|impacted|patched|fixed|remediat|mitigat|hunting|scanned|customer|customers|internal|kurban|hedef|etkilenen|受害|目标|受影响|修复)\b/i;

const HASH_DECLARED_TYPES = new Set(['md5', 'sha1', 'sha256', 'hash']);

/** Header labels that name a file / component column (not an IOC value column). */
const FILE_NAME_HEADER_RE =
  /^(?:file(?:\s*name)?s?|filenames?|path|filepath|file\s*path|sample(?:\s*name)?|module|component|artifact|artefact|dropped\s*file|dosya(?:\s*ad[ıi])?|dateiname|archivo|fichier|文件名|文件)$/;

/**
 * Column headers that name an ATTRIBUTE of another column's observable rather
 * than an observable of their own: the code-signing certificate of a sample
 * (thumbprint / serial / signer / issuer) or a structural / fuzzy
 * hash of it (imphash, ssdeep, TLSH). A SHA-1-shaped thumbprint is the
 * certificate's identity, not a malware sample's: such a column is never an
 * indicator column, whatever its values parse as. Its cells stay on the row as
 * labelled provenance (`cells`, `attribute_kind`).
 */
const ATTRIBUTE_COLUMN_HEADER_RE =
  /(?:^|\b)(?:certificate|certificates|cert|certs|code[\s-]*signing|thumbprint|thumbprints|serial(?:\s*(?:number|no))?|signer|signers|signing\s*(?:identity|subject|issuer)|issuer|issued\s*(?:by|to)|imphash|ssdeep|tlsh|sertifika|parmak\s*izi|zertifikat|certificado|сертификат|отпечаток|证书|指纹)(?:\b|$)/i;

/**
 * Column headers that name what the row's own indicator RESOLVED to ("Resolved
 * IP", "Resolves to", "A record", "DNS resolution"): a passive-DNS answer for
 * that domain — often shared CDN addresses — not an address the publisher
 * attributes to the actor. Publishers list actor IPs in the row's own
 * indicator column (tl-table-v11).
 */
const RESOLUTION_COLUMN_HEADER_RE =
  /^(?:resolved\s*(?:ips?|ip\s*address(?:es)?|address(?:es)?|to)|resolves?\s*to|resolution|ip\s*resolutions?|dns\s*(?:resolutions?|answers?|records?)|a\s*records?|aaaa\s*records?|passive\s*dns)$/i;

/**
 * Attribute kind of a column header, or null.
 * @param {string|null} header
 * @returns {'certificate'|'fuzzy_hash'|'resolution'|null}
 */
export function attributeColumnKind(header) {
  const norm = normalizeHeaderLabel(header || '');
  if (!norm || norm.length > 48) return null;
  if (RESOLUTION_COLUMN_HEADER_RE.test(norm)) return 'resolution';
  if (!ATTRIBUTE_COLUMN_HEADER_RE.test(norm)) return null;
  return /\b(?:imphash|ssdeep|tlsh)\b/.test(norm) ? 'fuzzy_hash' : 'certificate';
}

/**
 * Column headers that name where the row's subject is published — a tool's
 * project page, download location or reference article — rather than an
 * observable of the actor: "Source", "Reference", "Download", "Homepage",
 * "Project", "Repository".
 */
const REFERENCE_COLUMN_HEADER_RE =
  /^(?:sources?|references?|refs?|downloads?|download\s+(?:link|links|url|urls|page|location)|(?:tool\s+)?home\s*pages?|projects?|project\s+(?:page|url|site|link)s?|repository|repositories|repos?|websites?|web\s*sites?|more\s+info(?:rmation)?|documentation|further\s+reading|tool\s+(?:url|link|source)s?|kaynak|referans|quelle|fuente|fonte|来源|参考|источник)$/;

/**
 * A reference column: a reference header over cells whose observables are
 * URLs (resource locations). A "Source" column of IP addresses (connection
 * source) or hashes is not a reference column.
 * @param {string} header
 * @param {string[][]} rows
 * @param {number} col
 */
function isReferenceColumn(header, rows, col) {
  if (!REFERENCE_COLUMN_HEADER_RE.test(normalizeHeaderLabel(header))) return false;
  let urls = 0;
  let others = 0;
  for (const r of rows) {
    const cell = String(r[col] || '').trim();
    if (!cell) continue;
    const parsed = parseIndicatorCell(cell, null);
    for (const v of parsed.values) {
      if (v.is_ioc === false) continue;
      if (v.candidate_type === 'url') urls += 1;
      else others += 1;
    }
  }
  return urls > 0 && urls >= others * 2;
}

/** Heading / caption text that already curates samples or IOCs for this table. */
const AUTHORITATIVE_TABLE_HEADING_RE =
  /\b(?:iocs?|indicators?\s+of\s+compromise|compromise\s+indicators?|malicious\s+samples?|sample\s+hash(?:es)?|file\s+hash(?:es)?|md5|sha-?256|sha-?1|c2s?|c&c|command\s*(?:and|&)\s*control|operational\s+infrastructure)\b/i;

/**
 * @param {string} s
 */
export function normalizeHeaderLabel(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[\u2000-\u206f\u3000]/g, ' ')
    .replace(/[():：,.;/|"'`*#]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Header label → column intent (null when unrecognised).
 * @param {string} label
 */
export function headerIntent(label) {
  const norm = normalizeHeaderLabel(label);
  if (!norm || norm.length > 48) return null;
  for (const intent of ['type', 'indicator', 'description']) {
    for (const re of HEADER_HINTS[intent]) {
      if (re.test(norm)) return intent;
    }
  }
  return null;
}

/**
 * Parse a declared observable-type label ("SHA256", "IP Address & Port",
 * "IP 地址", "Alan Adı"). Returns null when the label is not a type label.
 * @param {string} label
 * @returns {{ label: string, type: string, endpoint: boolean }|null}
 */
export function parseDeclaredType(label) {
  const raw = String(label || '').trim();
  const norm = normalizeHeaderLabel(raw);
  if (!norm || norm.length > 48) return null;
  for (const hint of DECLARED_TYPE_HINTS) {
    if (hint.re.test(norm)) {
      return { label: raw, type: hint.type, endpoint: ENDPOINT_LABEL_RE.test(norm) };
    }
  }
  return null;
}

/**
 * Declared type → hint accepted by normalizeCandidateValue (null = syntax decides).
 * @param {{ type: string }|null} declared
 */
function hintForDeclared(declared) {
  if (!declared) return null;
  switch (declared.type) {
    case 'sha256':
    case 'sha1':
    case 'md5':
    case 'hash':
    case 'ip':
    case 'ipv6':
    case 'domain':
    case 'url':
    case 'cve':
    case 'attack_technique':
      return declared.type;
    default:
      return null;
  }
}

const IPV4_PORT_CELL_RE = /^((?:\d{1,3}\.){3}\d{1,3})[:：](\d{1,5})$/;
/** DNS identity shape: labels + alphabetic TLD (version strings like 7.4.8 never qualify). */
const DOMAIN_SHAPE_RE = /^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}\.?$/i;
const CELL_TOKEN_SPLIT_RE = /[\s,;，；|]+/;
const TRAILING_PUNCT_RE = /[,;:.，；。]+$/;

/**
 * Parse one token (already refanged) as an observable.
 * @param {string} token
 * @param {{ type: string, endpoint: boolean }|null} declared
 * @param {{ typeLabel?: string|null }} [ctx] raw row type cell / column label (source semantics)
 */
function parseToken(token, declared, ctx = {}) {
  let t = String(token || '').trim();
  // `2001:db8::` ends in colons that are part of the address, not punctuation.
  if (!isIPv6(t)) t = t.replace(TRAILING_PUNCT_RE, '');
  if (!t) return null;
  let port = null;
  const ep = t.match(IPV4_PORT_CELL_RE);
  if (ep) {
    const p = Number(ep[2]);
    if (Number.isFinite(p) && p >= 1 && p <= 65535) {
      port = p;
      t = ep[1];
    }
  }
  const hint = hintForDeclared(declared);
  let n = hint ? normalizeCandidateValue(t, hint) : normalizeCandidateValue(t, null);
  let mismatch = false;
  if (!n.ok && hint) {
    // Declared type is evidence, not authority: fall back to what the value actually is.
    const bySyntax = normalizeCandidateValue(t, null);
    if (bySyntax.ok) {
      n = bySyntax;
      mismatch = true;
    }
  } else if (n.ok && hint && n.candidateType !== hint && hint !== 'hash') {
    mismatch = true;
  }
  if (!n.ok) return { ok: false, raw: token, error: n.error || 'unrecognized', resolved_type: n.resolvedType || null };
  let typing = null;
  if (n.candidateType === 'domain') {
    if (!DOMAIN_SHAPE_RE.test(t)) return { ok: false, raw: token, error: 'invalid_domain' };
    // Central typing gate: the row's type label ("Mutex", "Domain", "Class") and
    // the value's own shape decide domain vs technical artifact. The cell text
    // keeps its original case so identifier segmentation is visible.
    // The publisher's own spelling (`EmbersAndBites[.]com`) when it is this
    // token: a defang marker is a network assertion the resolver must see.
    const spelled = ctx.sourceToken && refangObservable(ctx.sourceToken) === t ? ctx.sourceToken : t;
    typing = resolveDottedTokenType(spelled, {
      surroundingText: '',
      typeLabel: ctx.typeLabel || null,
      declaredType: declared ? declared.type : null,
      form: 'table_row'
    });
    if (typing.kind === 'skip') return { ok: false, raw: token, error: 'invalid_domain' };
    if (typing.kind !== 'domain') {
      n = {
        ...n,
        candidateType: typing.kind,
        normalizedValue: t,
        isIoc: false,
        resolvedType: typing.kind,
        typingReason: typing.reason
      };
    } else {
      n = { ...n, typingReason: typing.reason };
    }
  }
  return {
    ok: true,
    raw: token,
    refanged: t,
    candidate_type: n.candidateType,
    normalized_value: n.normalizedValue,
    is_ioc: n.isIoc !== false,
    likely_context_only: n.likelyContextOnly === true,
    port,
    declared_type_mismatch: mismatch || undefined,
    resolved_type: n.resolvedType || n.candidateType,
    typing_reason: n.typingReason || null,
    artifact_kind: typing?.artifact_kind || (NON_NETWORK_RESOLVED_TYPES.has(n.candidateType) ? n.candidateType : null),
    typing_signals: typing?.signals || undefined,
    parsed: n.parsed && typeof n.parsed === 'object' ? n.parsed : undefined
  };
}

/**
 * An absolute URL ending in "/" followed, after whitespace, by exactly one
 * file-name segment — and nothing else — is one URL whose last path segment
 * the publisher's layout wrapped onto the next line of the same cell / row
 * ("http://192.0.2.7:443/" + "4591187629.exe"). Only the whole text qualifies:
 * prose, a second URL or a segment without an extension never joins.
 */
const WRAPPED_URL_TAIL_RE =
  /^((?:h(?:tt|xx)ps?|ftps?)(?::|\[:\])\/\/[^\s/]+\/(?:[^\s]*\/)?)\s+([A-Za-z0-9][\w~%+-]*(?:\.[A-Za-z0-9]{1,10})+)$/i;

/**
 * @param {string} text one table cell or one indicator row
 * @returns {string|null} the joined URL, or null when the text is not a wrapped URL
 */
export function joinWrappedUrlTail(text) {
  const m = WRAPPED_URL_TAIL_RE.exec(String(text || '').replace(/\s+/g, ' ').trim());
  return m ? `${m[1]}${m[2]}` : null;
}

/**
 * Values asserted by one indicator cell. Whole-cell parse first (single value),
 * then token split for cells that list several indicators.
 * @param {string} cellText
 * @param {{ type: string, endpoint: boolean }|null} declared
 * @param {{ typeLabel?: string|null }} [ctx] row type cell / column label
 */
export function parseIndicatorCell(cellText, declared = null, ctx = {}) {
  const source = String(cellText || '').replace(/\s+/g, ' ').trim();
  // A URL the publisher's layout wrapped inside one cell ("http://h:443/" then
  // "payload.exe" on the next line): one value; `raw` keeps the cell as written.
  const refanged = refangObservable(joinWrappedUrlTail(source) || source);
  if (!refanged) return { values: [], rejected: [], reason: 'empty_indicator' };
  const whole = parseToken(refanged, declared, { ...ctx, sourceToken: source });
  // One value only when the parsed identity carries no whitespace: a cell that
  // lists several values ("H1 H2", "<br>"-separated) is split below, never
  // accepted as one spaced "hash".
  if (whole?.ok && !/\s/.test(String(whole.normalized_value || '')) && !(whole.candidate_type === 'domain' && /\s/.test(refanged))) {
    // A leading non-network value (path / file name) that consumed only part
    // of the cell: the rest may still hold the row's observables
    // ("C:\…\x.dll SHA256: <h>", "x.dll (SHA-256 <h>)"). Never accept the
    // partial reading silently.
    const mixed = whole.is_ioc === false ? decomposeMixedCell(refanged, whole, declared, ctx) : null;
    if (mixed) return mixed;
    // `raw` is the faithful source spelling (defanged form kept for provenance).
    return { values: [{ ...whole, raw: source }], rejected: [], reason: null };
  }
  const values = [];
  const rejected = [];
  const seen = new Set();
  const sourceTokens = source.split(CELL_TOKEN_SPLIT_RE).filter(Boolean);
  const refangedTokens = refanged.split(CELL_TOKEN_SPLIT_RE).filter(Boolean);
  const aligned = sourceTokens.length === refangedTokens.length;
  for (let i = 0; i < refangedTokens.length; i += 1) {
    const rawTok = refangedTokens[i];
    if (!rawTok || isInlineTypeLabelToken(rawTok)) continue;
    let tok = rawTok;
    let parsed = parseToken(tok, declared, aligned ? { ...ctx, sourceToken: sourceTokens[i] } : ctx);
    // "(SHA-256", "<hash>)": brackets around a value or a bare type label.
    if (!parsed?.ok) {
      const stripped = rawTok.replace(WRAPPING_PUNCT_RE, '');
      if (!stripped || SEPARATOR_TOKEN_RE.test(stripped) || isBareTypeLabelToken(stripped)) continue;
      if (stripped !== rawTok) {
        const retry = parseToken(stripped, declared, ctx);
        if (retry?.ok) {
          tok = stripped;
          parsed = retry;
        }
      }
      // A URL glued into code ("…DownloadString('https://h/x.ps1')"): only the
      // absolute URL span is the value — never the call around it.
      const embedded = parsed?.ok ? null : embeddedAbsoluteUrl(rawTok);
      if (embedded) {
        const retry = parseToken(embedded, declared, ctx);
        if (retry?.ok && retry.candidate_type === 'url') {
          tok = embedded;
          parsed = retry;
        }
      }
    }
    if (!parsed) continue;
    if (parsed.ok && aligned) parsed = { ...parsed, raw: tok === rawTok ? sourceTokens[i] : tok };
    if (parsed.ok) {
      const key = `${parsed.candidate_type}\0${parsed.normalized_value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      values.push(parsed);
    } else {
      rejected.push(parsed);
    }
  }
  // A file identity listed with its own hash(es) in one cell: link them.
  const fileIds = values.filter((v) => v.is_ioc === false && NON_NETWORK_RESOLVED_TYPES.has(v.candidate_type));
  const iocIds = values.filter((v) => v.is_ioc !== false);
  if (fileIds.length === 1 && iocIds.length && iocIds.every((v) => HASH_DECLARED_TYPES.has(v.candidate_type))) {
    const fileIdentity = `${fileIds[0].candidate_type}:${fileIds[0].normalized_value}`;
    const companions = iocIds.map((v) => `${v.candidate_type}:${v.normalized_value}`);
    for (const v of values) v.cell_companions = v === fileIds[0] ? companions : iocIds.includes(v) ? [fileIdentity] : v.cell_companions;
  }
  return { values, rejected, reason: values.length ? null : 'no_observable' };
}

/** Brackets / quotes wrapping a token inside a mixed cell ("(SHA-256", "<hash>)"). */
const WRAPPING_PUNCT_RE = /^[(\[{<"'“‘«]+|[)\]}>"'”’»,;.]+$/g;
/** Separator tokens between a file identity and its metadata ("-", "|", "=", "→"). */
const SEPARATOR_TOKEN_RE = /^[-–—|/=:→>]+$/;

/**
 * A type label written without a trailing colon inside a mixed cell
 * ("(SHA-256 <h>)", "MD5 <h>"): names the value after it, never a value.
 * @param {string} token wrapping punctuation already stripped
 */
function isBareTypeLabelToken(token) {
  const t = String(token || '').replace(/[:：]+$/, '');
  if (!t || parseToken(t, null)?.ok) return false;
  return Boolean(parseDeclaredType(t));
}

/**
 * Remove the first case-insensitive occurrence of `needle` from `text`.
 * @returns {string|null} remainder, or null when `needle` is not in `text`
 */
function withoutFirstOccurrence(text, needle) {
  const n = String(needle || '');
  if (!n) return null;
  const at = text.toLowerCase().indexOf(n.toLowerCase());
  if (at < 0) return null;
  return `${text.slice(0, at)} ${text.slice(at + n.length)}`.replace(/\s+/g, ' ').trim();
}

/**
 * Mixed indicator cell: a leading non-network value (file path / file name)
 * followed by the row's own observables — "C:\…\x.dll SHA256: <h>",
 * "x.dll (SHA-256 <h>)", "loader.exe - <md5>". The file identity stays
 * a non-network value (context); every IOC value in the remainder is its own
 * value of the cell. The remainder is recovered only when it is made of
 * observables, type labels and separators: a description that merely mentions
 * an observable ("loader.exe connects to evil.example") is not decomposed, but
 * an observable in it is reported (`residual_observables`) instead of being
 * dropped silently.
 * @param {string} refanged whole cell, refanged
 * @param {object} whole the leading non-network value parseToken produced
 * @returns {{ values: object[], rejected: object[], reason: null, decomposition: object }|null}
 *   null when the leading value accounts for the whole cell
 */
function decomposeMixedCell(refanged, whole, declared, ctx) {
  const head = whole.parsed?.normalized_path || whole.normalized_value || whole.refanged;
  const residual = withoutFirstOccurrence(refanged, head);
  if (residual == null || !/[\p{L}\p{N}]/u.test(residual)) return null;
  const idOf = (v) => `${v.candidate_type}:${v.normalized_value}`;
  // Cell sequence in source order: file identities and the IOC values after them.
  const sequence = [{ ...whole, raw: head }];
  const seen = new Set([`${whole.candidate_type}\0${whole.normalized_value}`]);
  let clean = true;
  const residualObservables = [];
  for (const rawTok of residual.split(CELL_TOKEN_SPLIT_RE).filter(Boolean)) {
    const tok = rawTok.replace(WRAPPING_PUNCT_RE, '');
    if (!tok || SEPARATOR_TOKEN_RE.test(tok) || isInlineTypeLabelToken(rawTok) || isBareTypeLabelToken(tok)) continue;
    const p = parseToken(tok, hashOnlyDeclared(declared), ctx);
    // A further complete file identity of a multi-pair cell ("a.dll (MD5 <h>)
    // <path>\b.dll (MD5 <h>)"): an absolute path or a bare file name. A path
    // fragment (the tail of an unquoted "Program Files" path) is not.
    const fileIdentity = p?.ok && p.is_ioc === false &&
      (p.candidate_type === 'file_path' || (p.candidate_type === 'technical_artifact' && !/[\\/]/.test(tok)));
    if (p?.ok && (p.is_ioc !== false || fileIdentity)) {
      const key = `${p.candidate_type}\0${p.normalized_value}`;
      if (!seen.has(key)) {
        seen.add(key);
        sequence.push({ ...p, raw: tok });
      }
      continue;
    }
    clean = false;
    const loose = parseToken(tok, null, ctx);
    if (loose?.ok && loose.is_ioc !== false) residualObservables.push(idOf(loose));
  }
  const iocValues = sequence.filter((v) => v.is_ioc !== false);
  if (!clean || !iocValues.length) {
    // Unparsed remainder: keep the leading value, report what was not read
    // (every observable of a prose remainder, parsed or not).
    residualObservables.unshift(...iocValues.map(idOf));
    // An explicit network endpoint in the remainder — "ip:port" or an absolute
    // URL, as in a command line the publisher put in the indicator column
    // ("conhost.exe client 192.0.2.5:443 …") — is a value of the cell
    // (tl-table-v9). A bare host merely named in prose is still only reported.
    const endpoints = [];
    for (const rawTok of residual.split(CELL_TOKEN_SPLIT_RE).filter(Boolean)) {
      const tok = rawTok.replace(WRAPPING_PUNCT_RE, '');
      const p = tok ? parseToken(tok, null, ctx) : null;
      if (!p?.ok || p.is_ioc === false) continue;
      if (!((p.candidate_type === 'ip' && p.port != null) || p.candidate_type === 'url')) continue;
      if (endpoints.some((e) => e.candidate_type === p.candidate_type && e.normalized_value === p.normalized_value)) continue;
      endpoints.push({ ...p, raw: tok, residual_endpoint: true });
    }
    return {
      values: [{ ...whole, raw: head, cell_residual: residual.slice(0, 160), residual_observables: residualObservables.length ? residualObservables : undefined }, ...endpoints],
      rejected: [],
      reason: null,
      decomposition: { mixed: true, recovered: 0, residual_unparsed: true, residual_observables: residualObservables }
    };
  }
  // Link each IOC value to the file identity written before it.
  const companions = new Map(sequence.map((v) => [v, []]));
  let file = null;
  for (const v of sequence) {
    if (v.is_ioc === false) {
      file = v;
      continue;
    }
    if (file) {
      companions.get(file).push(idOf(v));
      companions.get(v).push(idOf(file));
    }
  }
  return {
    values: sequence.map((v) => (companions.get(v).length ? { ...v, cell_companions: companions.get(v) } : v)),
    rejected: [],
    reason: null,
    decomposition: { mixed: true, recovered: iocValues.length, residual_unparsed: false }
  };
}

/** A declared hash type still guides a residual hash; any other declared type does not apply to it. */
function hashOnlyDeclared(declared) {
  return declared && HASH_DECLARED_TYPES.has(declared.type) ? declared : null;
}

/**
 * Inline observable-type label inside a labelled multi-value cell
 * ("MD5: <md5> SHA-256: <sha256>", "SHA1: …"): a colon-terminated type label
 * names the value after it — it is neither a value nor prose.
 * @param {string} token
 */
export function isInlineTypeLabelToken(token) {
  const t = String(token || '').trim();
  if (!/[:：]$/.test(t)) return false;
  return Boolean(parseDeclaredType(t.replace(/[:：]+$/, '')));
}

/**
 * Software-version column labels ("Version", "Versions Affected", "Affected
 * Versions", "Software / Product / Firmware Version", "Build Number"). Anchored:
 * a label must name a version and nothing else, so "IP Address", "Value" or
 * "Details" never qualify — an ambiguous heading suppresses nothing.
 */
const VERSION_COLUMN_PREFIX =
  /(?:affected|vulnerable|impacted|fixed|patched|first\s+fixed|minimum|maximum|min|max|current|latest|installed|running|software|product|firmware|os|kernel|agent|client|server|app|application|package|plugin|component|library|engine)/;
const VERSION_COLUMN_NOUN =
  /(?:version|versions|ver|build|builds|build\s+number|build\s+numbers|build\s+no|release|releases|revision|revisions|sürüm|sürümler|surum|versiyon|versión|versiones|versão|versões|versionen|версия|версии|版本|受影响版本)/;
const VERSION_COLUMN_SUFFIX = /(?:affected|vulnerable|impacted|fixed|patched|range|ranges|number|numbers|no|s)/;
const VERSION_COLUMN_RE = new RegExp(
  `^(?:${VERSION_COLUMN_PREFIX.source}\\s+)*${VERSION_COLUMN_NOUN.source}(?:\\s+${VERSION_COLUMN_SUFFIX.source})*$`
);

/**
 * True when a table header / header-like cell names a software-version column.
 * @param {string} label
 */
export function isVersionColumnLabel(label) {
  const norm = normalizeHeaderLabel(label);
  return Boolean(norm) && norm.length <= 48 && VERSION_COLUMN_RE.test(norm);
}

/**
 * Version columns of one table: from its header row (DOM `<th>` / typography),
 * or from a header-like first row (a version label, no observable). A table
 * with no header of its own inherits `carried` — the previous table's version
 * columns across a page break — when its width matches.
 * @param {{ headers?: string[]|null, rows?: string[][] }|null} table
 * @param {{ width: number, columns: number[] }|null} [carried]
 * @returns {{ columns: number[], width: number, header_row: boolean, own_header: boolean, inherited: boolean }}
 */
export function tableVersionColumns(table, carried = null) {
  const rows = Array.isArray(table?.rows) ? table.rows : [];
  const headers = Array.isArray(table?.headers) && table.headers.length ? table.headers : null;
  const width = Math.max(headers ? headers.length : 0, ...rows.map((r) => (Array.isArray(r) ? r.length : 0)), 0);
  const pick = (cells) =>
    cells.map((c, i) => (isVersionColumnLabel(c) ? i : -1)).filter((i) => i >= 0);
  if (headers) return { columns: pick(headers), width, header_row: false, own_header: true, inherited: false };
  const first = Array.isArray(rows[0]) ? rows[0].map((c) => String(c ?? '')) : [];
  const firstVersion = pick(first);
  if (firstVersion.length && !first.some((c) => cellIsObservable(c))) {
    return { columns: firstVersion, width, header_row: true, own_header: true, inherited: false };
  }
  if (carried && carried.columns?.length && carried.width === width) {
    return { columns: carried.columns.slice(), width, header_row: false, own_header: false, inherited: true };
  }
  return { columns: [], width, header_row: false, own_header: false, inherited: false };
}

/** Upper bound for a multi-value indicator cell (dozens of hashes in one <td>). */
const MULTI_VALUE_CELL_MAX_CHARS = 20000;
const MULTI_VALUE_CELL_MAX_TOKENS = 500;

/**
 * Observable reading of a cell for column scoring: the whole cell is one
 * observable value, or — the multi-value form publishers use for grouped
 * indicators ("H1<br>H2<br>H3", "a.example, b.example") — EVERY token is an
 * observable. The all-tokens rule mirrors parseIndicatorCell (which already
 * splits such cells) while keeping prose out: a description that merely
 * mentions one domain has non-observable words and never scores.
 * @param {string} cellText
 */
const SUBHEADER_EXTRA_LABEL_RE = /^(?:notes?|comments?|remarks?|context|other(?:\s+iocs?|\s+indicators?)?)$/;

/**
 * A mid-table row that only carries column labels — the header of the next
 * stacked sub-table. Returns per-indicator-column declarations
 * (Map index → { declared, label }) or null when the row is data.
 * @param {string[]} cells
 * @param {Array<{ index: number }>} indicatorCols
 */
function subHeaderRowDeclarations(cells, indicatorCols) {
  const nonEmpty = cells.map((c, idx) => ({ idx, text: String(c || '').trim() })).filter((c) => c.text);
  if (!nonEmpty.length) return null;
  for (const c of nonEmpty) {
    if (c.text.length > 48 || cellIsObservable(c.text)) return null;
    const norm = normalizeHeaderLabel(c.text);
    if (!headerIntent(c.text) && !parseDeclaredType(c.text) && !SUBHEADER_EXTRA_LABEL_RE.test(norm)) return null;
  }
  const out = new Map();
  let labelledIndicator = false;
  for (const col of indicatorCols) {
    const label = String(cells[col.index] || '').trim();
    if (!label) continue;
    const declared = parseDeclaredType(label);
    if (declared || headerIntent(label) === 'indicator' || SUBHEADER_EXTRA_LABEL_RE.test(normalizeHeaderLabel(label))) labelledIndicator = true;
    out.set(col.index, { declared: declared || null, label });
  }
  return labelledIndicator ? out : null;
}

function cellIsObservable(cellText) {
  const text = String(cellText || '').replace(/\s+/g, ' ').trim();
  const refanged = refangObservable(joinWrappedUrlTail(text) || text);
  if (!refanged) return null;
  if (refanged.length <= 512 && !/\s/.test(refanged)) {
    const parsed = parseToken(refanged, null);
    return parsed?.ok ? parsed : null;
  }
  if (refanged.length > MULTI_VALUE_CELL_MAX_CHARS) return null;
  const all = refanged.split(CELL_TOKEN_SPLIT_RE).filter(Boolean);
  if (all.length < 2 || all.length > MULTI_VALUE_CELL_MAX_TOKENS) return null;
  const tokens = all.filter((tok) => !isInlineTypeLabelToken(tok));
  if (!tokens.length) return null;
  const parsed = [];
  for (const tok of tokens) {
    const p = parseToken(tok, null);
    if (!p?.ok) return mixedCellObservable(refanged);
    parsed.push(p);
  }
  return { ...parsed[0], is_ioc: parsed.every((p) => p.is_ioc), multi_value: parsed.length };
}

/**
 * A mixed file-identity cell ("x.dll (SHA-256 <h>)") scores as an observable
 * cell when its remainder decomposes cleanly into IOC values (same rule as
 * parseIndicatorCell, so scoring and assertion agree).
 * @param {string} refanged
 */
function mixedCellObservable(refanged) {
  const whole = parseToken(refanged, null);
  if (!whole?.ok || whole.is_ioc !== false || /\s/.test(String(whole.normalized_value || ''))) return null;
  const mixed = decomposeMixedCell(refanged, whole, null, {});
  if (!mixed || mixed.decomposition.residual_unparsed) return null;
  const ioc = mixed.values.find((v) => v.is_ioc !== false);
  return ioc ? { ...ioc, multi_value: mixed.values.length } : null;
}

/**
 * Intent of a heading-like line such as "Type Indicator Description" — used by
 * the zone classifier when a PDF table header survives only as a heading.
 * @param {string} text
 */
export function looksLikeIocTableHeader(text) {
  const norm = normalizeHeaderLabel(text);
  if (!norm || norm.length > 80) return false;
  const words = norm.split(' ').filter(Boolean);
  if (words.length < 2 || words.length > 8) return false;
  const intents = new Set();
  const tokens = [];
  for (let i = 0; i < words.length; i += 1) {
    tokens.push(words[i]);
    if (i + 1 < words.length) tokens.push(`${words[i]} ${words[i + 1]}`);
  }
  let unmatched = 0;
  for (const w of words) if (!headerIntent(w)) unmatched += 1;
  for (const t of tokens) {
    const intent = headerIntent(t);
    if (intent) intents.add(intent);
  }
  const strong = intents.has('indicator') || intents.has('type');
  return strong && intents.size >= 2 && unmatched <= Math.max(1, Math.floor(words.length / 2));
}

/**
 * @param {string[][]} rows
 * @param {number} col
 */
function columnStats(rows, col) {
  let nonEmpty = 0;
  let observable = 0;
  let ioc = 0;
  let typeLabel = 0;
  let chars = 0;
  for (const r of rows) {
    const cell = String(r[col] || '').trim();
    if (!cell) continue;
    nonEmpty += 1;
    chars += cell.length;
    const parsed = cellIsObservable(cell);
    if (parsed) {
      observable += 1;
      if (parsed.is_ioc) ioc += 1;
    } else if (parseDeclaredType(cell)) typeLabel += 1;
  }
  return {
    non_empty: nonEmpty,
    observable_fraction: nonEmpty ? observable / nonEmpty : 0,
    ioc_fraction: nonEmpty ? ioc / nonEmpty : 0,
    type_label_fraction: nonEmpty ? typeLabel / nonEmpty : 0,
    avg_chars: nonEmpty ? chars / nonEmpty : 0
  };
}

const NETWORK_DECLARED_TYPES = new Set(['domain', 'url', 'ip', 'ipv6', 'email']);

/**
 * Last labels that are both common file extensions and delegated DNS suffixes
 * (or ccTLDs used as script extensions). Filename-column consistency may demote
 * these when a column is mostly files; clear gTLDs (`com`/`net`/`org`) are not
 * in this set and are not demoted by file majority alone.
 * `pl` (Perl / Poland) is the motivating case and is not in FILE_EXT_HINT.
 */
const FILENAME_DOMAIN_COLLISION_SUFFIXES = new Set([
  ...FILE_EXT_HINT,
  'pl'
]);

/** Row description that asserts network / domain / C2 semantics for the Item. */
const NETWORK_ROW_EVIDENCE_RE =
  /\b(?:domains?|hostnames?|fqdns?|c2|c&c|command[\s-]and[\s-]control|callbacks?|beacons?|contacted|communicat\w*|connect(?:s|ed|ing)?(?:\s+\w+){0,4}\s+to|hosted\s+on|dns|malicious\s+infrastructure|基础设施|域名|主机名?|домен|хост)\b/i;

/** Row description that asserts the Item is a file / sample name. */
const FILE_ROW_EVIDENCE_RE =
  /\b(?:file\s*names?|filenames?|dropped\s*files?|sample\s*names?|payload\s*files?|webshells?|executables?|binaries?|driver\s*files?|script\s*files?|dosya\s*ad[ıi]|dateiname|archivo|fichier|文件名)\b/i;

/**
 * IOC inventory column headers (Item / Indicator / IOC / Domain / …). Clear
 * domains in a file-majority column keep their domain reading here; Field /
 * Source / Purpose analysis columns do not.
 */
const IOC_ITEM_COLUMN_HEADER_RE =
  /^(?:item|items|indicator|indicators|ioc|iocs|observable|observables|value|values|domain|domains|hostname|hostnames|fqdn|fqdns|host|hosts|url|urls|uri|artifact|artifacts|artefact|artefacts|gösterge|gostergeler|göstergeler|değer|deger|değerler|degerler|indicador|indicadores|valor|valores|indikator|indikatoren|wert|werte|indicateur|indicateurs|valeur|valeurs|指标|指標|值|индикатор|индикаторы|значение)$/;

/**
 * True when a hostname-shaped value's last label is an ambiguous file/TLD
 * collision (`.pl`, `.py`, `.so`, …), not a clear network gTLD (`.com`/`.net`).
 * @param {string} value
 */
export function isFilenameDomainCollisionSuffix(value) {
  const labels = String(value || '')
    .toLowerCase()
    .replace(/\.$/, '')
    .split('.')
    .filter(Boolean);
  if (labels.length < 2) return false;
  return FILENAME_DOMAIN_COLLISION_SUFFIXES.has(labels[labels.length - 1]);
}

/**
 * @param {string|null|undefined} header
 */
function isIocItemColumnHeader(header) {
  const norm = normalizeHeaderLabel(header || '');
  return Boolean(norm) && IOC_ITEM_COLUMN_HEADER_RE.test(norm);
}

/**
 * Publisher defang residue on the source spelling (`evil[.]com`). Supporting
 * signal only — never sufficient alone against explicit file evidence.
 * @param {object} value
 */
function cellLooksDefanged(value) {
  const raw = String(value?.raw || '');
  if (!raw) return false;
  return /\[\.\]|\(\.\)|\{\.\}|\[ *\. *\]|\( *\. *\)/.test(raw);
}

/**
 * True when a column is a hash indicator column (MD5 / SHA header or declared).
 * @param {{ header?: string|null, intent?: string, declared_type?: { type: string }|null }} col
 */
function columnIsHashIndicator(col) {
  if (String(col?.intent || '') !== 'indicator') return false;
  if (col.declared_type && HASH_DECLARED_TYPES.has(col.declared_type.type)) return true;
  const declared = col.header ? parseDeclaredType(col.header) : null;
  if (declared && HASH_DECLARED_TYPES.has(declared.type)) return true;
  const norm = normalizeHeaderLabel(col.header || '');
  return /^(?:md5|sha\s*-?\s*1|sha\s*-?\s*256|sha\s*-?\s*512|hash|hashes|file\s*hash(?:es)?)$/.test(norm);
}

/**
 * True when a column is a file-name / component provenance column.
 * @param {{ header?: string|null, intent?: string }} col
 */
function columnIsFileNameColumn(col) {
  const norm = normalizeHeaderLabel(col?.header || '');
  if (!norm) return false;
  if (FILE_NAME_HEADER_RE.test(norm)) return true;
  return String(col?.intent || '') === 'description' && /(?:file|name|path|module|component|artifact|artefact|sample|dosya)/.test(norm);
}

/**
 * True when any indicator column carries network IOC types (IP / domain / URL).
 * @param {{ intent?: string, declared_type?: { type: string }|null, header?: string|null }[]} columns
 * @param {{ status: string, values: object[] }[]} rows
 */
function tableHasNetworkIndicatorColumn(columns, rows) {
  for (const col of columns) {
    if (String(col.intent || '') !== 'indicator') continue;
    const declared = col.declared_type || (col.header ? parseDeclaredType(col.header) : null);
    if (declared && NETWORK_DECLARED_TYPES.has(declared.type)) return true;
    const values = rows
      .filter((r) => r.status === 'valid')
      .flatMap((r) => r.values.filter((v) => v.column_index === col.index && v.is_ioc !== false));
    if (!values.length) continue;
    const network = values.filter((v) => NETWORK_DECLARED_TYPES.has(String(v.candidate_type || '')));
    if (network.length * 2 >= values.length) return true;
  }
  return false;
}

/**
 * Filename|MD5 (or File|SHA-256) component inventory: hash column + file-name
 * column, no type column, no network IOC column.
 * @param {{ intent?: string, header?: string|null, declared_type?: { type: string }|null }[]} columns
 * @param {{ status: string, values: object[] }[]} rows
 * @param {object|null} typeCol
 */
export function isFileHashInventoryTable(columns, rows, typeCol = null) {
  if (typeCol) return false;
  const cols = Array.isArray(columns) ? columns : [];
  if (!cols.some(columnIsHashIndicator)) return false;
  if (!cols.some(columnIsFileNameColumn)) return false;
  if (tableHasNetworkIndicatorColumn(cols, Array.isArray(rows) ? rows : [])) return false;
  return true;
}

/** Header labels that describe lookup / WHOIS / resolution attributes, not IOC assertions. */
const INFRASTRUCTURE_LOOKUP_HEADER_RE =
  /^(?:first\s*seen|last\s*seen|asn|as\s*number|org(?:anization)?|registrar|country|geo|location|owner|isp|network\s*name|whois|hosting|provider|size|filesize|file\s*size|bytes)$/i;

/**
 * Domain|IP|First seen|ASN (and similar) body tables: resolution / enrichment
 * attributes around observables, not a publisher IOC appendix by themselves.
 * @param {{ header?: string|null, intent?: string }[]} columns
 * @param {object|null} typeCol
 */
export function isInfrastructureLookupTable(columns, typeCol = null) {
  if (typeCol) return false;
  const cols = Array.isArray(columns) ? columns : [];
  const lookupCols = cols.filter((c) => INFRASTRUCTURE_LOOKUP_HEADER_RE.test(normalizeHeaderLabel(c.header || '')));
  if (!lookupCols.length) return false;
  const hasNetworkHeader = cols.some((c) => {
    const h = normalizeHeaderLabel(c.header || '');
    return /^(?:domain|host|hostname|url|ip|ipv4|ipv6|address|c2|indicator|observable|hash|md5|sha\s*-?\s*1|sha\s*-?\s*256)$/i.test(h);
  });
  return hasNetworkHeader;
}

/**
 * Publisher already curated this table via zone inheritance or an IOC/sample heading.
 * @param {object} block
 * @param {{ inAuthoritativeScope?: boolean, negativeZone?: boolean }} opts
 */
function tableInAuthoritativeScope(block, opts = {}) {
  if (opts.inAuthoritativeScope === true) return true;
  if (opts.negativeZone === true) return false;
  const zone = String(block?.zone || '');
  if (
    zone === 'explicit_ioc_section' ||
    zone === 'c2_section' ||
    zone === 'sample_table' ||
    zone === 'operational_infrastructure'
  ) {
    return true;
  }
  const heading = String(block?.section_heading || block?.table?.caption || '').trim();
  return Boolean(heading) && heading.length <= 80 && AUTHORITATIVE_TABLE_HEADING_RE.test(heading);
}

/**
 * Whether a domain reading in a file-majority column should be rewritten as a
 * file name. Column file majority is necessary but not sufficient:
 *   - Publisher network evidence (“Domain contacted…”, “C2”) always keeps the domain.
 *   - Ambiguous file/TLD collisions (`back.pl`) demote (defang alone does not save them).
 *   - Explicit file evidence (File Name header / “dropped file” description) demotes.
 *   - Clear domains otherwise keep only in IOC Item/Indicator-shaped columns or when
 *     the cell is defanged; Field/Source analysis tables still demote under file majority.
 * @param {object} value parsed indicator cell value (domain reading)
 * @param {{ description?: string|null }} row
 * @param {{ header?: string|null, declared_type?: { type: string }|null }} col
 */
function shouldDemoteDomainInFileColumn(value, row, col) {
  if (value.declared_type && NETWORK_DECLARED_TYPES.has(value.declared_type)) return false;
  if (value.typing_reason === 'declared_network_type') return false;
  const description = String(row?.description || '');
  if (NETWORK_ROW_EVIDENCE_RE.test(description)) return false;
  const collision = isFilenameDomainCollisionSuffix(value.normalized_value || value.refanged || '');
  const fileEvidence = FILE_ROW_EVIDENCE_RE.test(description) || columnIsFileNameColumn(col);
  if (fileEvidence) return true;
  if (collision) return true;
  if (cellLooksDefanged(value) || isIocItemColumnHeader(col.header)) return false;
  return true;
}

/**
 * One table column holds one kind of value. In a column whose values are file
 * names (`b374.php`, `error.jsp`, `x.exe`), a name whose extension also happens
 * to be a ccTLD / script suffix (`back.pl`, `tool.py`) is a file name too —
 * never a domain because its suffix is ambiguous. Clear domains (`evil.net`)
 * and rows whose description asserts network / C2 semantics keep the domain
 * reading even when sibling cells are filenames. Applies only to columns
 * without a declared network type, with at least two unambiguous file names
 * that outnumber the domain readings two to one. Mutates the parsed row
 * values in place.
 * @param {{ status: string, description?: string|null, values: object[] }[]} rows
 * @param {{ index: number, header?: string|null, declared_type?: { type: string }|null }[]} indicatorCols
 */
function applyFileNameColumnConsistency(rows, indicatorCols) {
  for (const col of indicatorCols) {
    if (col.declared_type && NETWORK_DECLARED_TYPES.has(col.declared_type.type)) continue;
    const entries = rows
      .filter((r) => r.status === 'valid')
      .flatMap((r) => r.values.filter((v) => v.column_index === col.index).map((v) => ({ value: v, row: r })));
    const files = entries.filter((e) => e.value.candidate_type === 'technical_artifact' && e.value.artifact_kind === 'file');
    const domains = entries.filter(
      (e) =>
        e.value.candidate_type === 'domain' &&
        e.value.typing_reason !== 'declared_network_type' &&
        !e.value.declared_type
    );
    if (!domains.length || files.length < 2 || files.length < 2 * domains.length) continue;
    for (const { value: v, row } of domains) {
      if (!shouldDemoteDomainInFileColumn(v, row, col)) continue;
      Object.assign(v, {
        candidate_type: 'technical_artifact',
        normalized_value: v.refanged,
        is_ioc: false,
        resolved_type: 'technical_artifact',
        typing_reason: 'file_name_column',
        artifact_kind: 'file'
      });
    }
  }
}

/**
 * Interpret a canonical table block.
 * @param {{ id?: string, table?: { headers?: string[]|null, rows?: string[][], caption?: string|null }, section_heading?: string|null, section?: string|null, zone?: string }} block
 * @param {{ negativeZone?: boolean, versionColumns?: number[], inAuthoritativeScope?: boolean }} [opts]
 *   versionColumns: software-version columns (see tableVersionColumns) — never indicator columns.
 *   inAuthoritativeScope: caller already classified the surrounding section as curated.
 */
export function interpretIocTable(block, opts = {}) {
  const table = block?.table || {};
  let headers = Array.isArray(table.headers) && table.headers.length ? table.headers.map((h) => String(h ?? '')) : null;
  let rows = (Array.isArray(table.rows) ? table.rows : []).map((r) => (Array.isArray(r) ? r.map((c) => String(c ?? '')) : []));
  const result = {
    version: TABLE_SEMANTICS_VERSION,
    table_id: block?.id || null,
    kind: 'not_ioc_table',
    reason: null,
    explicit: false,
    header_promoted: false,
    columns: [],
    rows: [],
    declared_type_column: null,
    indicator_columns: [],
    description_columns: [],
    stats: {
      rows_seen: 0,
      rows_valid: 0,
      rows_rejected: 0,
      values_asserted: 0,
      rejection_reasons: {}
    }
  };
  if (!rows.length) {
    result.reason = 'no_rows';
    return result;
  }

  const width = Math.max(headers ? headers.length : 0, ...rows.map((r) => r.length));
  if (width < 2) {
    result.reason = 'single_column';
    return result;
  }
  rows = rows.map((r) => {
    const out = r.slice(0, width);
    while (out.length < width) out.push('');
    return out;
  });

  // Header promotion: first row made of recognisable labels and no observables.
  if (!headers) {
    const first = rows[0];
    const intents = first.map((c) => headerIntent(c) || (isVersionColumnLabel(c) ? 'version' : null));
    const labelled = intents.filter(Boolean).length;
    const hasObservable = first.some((c) => cellIsObservable(c));
    if (!hasObservable && labelled >= 1 && (labelled >= 2 || rows.length >= 2)) {
      headers = first;
      rows = rows.slice(1);
      result.header_promoted = true;
    }
  }
  if (!rows.length) {
    result.reason = 'header_only';
    return result;
  }

  // Column intents: header hints first, then cell syntax. A software-version
  // column is never an indicator column: "2.3.20.2" under "Versions Affected"
  // is a release number however IPv4-shaped it is.
  const versionCols = new Set(Array.isArray(opts.versionColumns) ? opts.versionColumns : []);
  const columns = [];
  for (let c = 0; c < width; c += 1) {
    const header = headers ? String(headers[c] ?? '').trim() : '';
    const stats = columnStats(rows, c);
    if (versionCols.has(c) || (header && isVersionColumnLabel(header))) {
      columns.push({ index: c, header: header || null, intent: 'other', method: 'version_column', declared_type: null, ...stats });
      continue;
    }
    const attributeKind = header ? attributeColumnKind(header) : null;
    if (header && isReferenceColumn(header, rows, c)) {
      // Provenance of the row's subject (where a tool is published), never
      // an observable the publisher attributes to the actor (tl-table-v9).
      columns.push({ index: c, header, intent: 'other', method: 'reference_column', attribute_kind: 'reference', declared_type: null, ...stats });
      continue;
    }
    if (attributeKind) {
      // Never an indicator column, even when every cell parses (thumbprints).
      columns.push({ index: c, header, intent: 'other', method: 'attribute_column', attribute_kind: attributeKind, declared_type: null, ...stats });
      continue;
    }
    let intent = header ? headerIntent(header) : null;
    let method = intent ? 'header' : null;
    const declaredFromHeader = header ? parseDeclaredType(header) : null;
    if (stats.observable_fraction >= 0.5 && stats.non_empty >= 1) {
      if (intent !== 'indicator') method = intent ? 'content_override' : 'content';
      intent = 'indicator';
    } else if (!intent && stats.type_label_fraction >= 0.5 && stats.non_empty >= 1) {
      intent = 'type';
      method = 'content';
    } else if (intent === 'indicator' && stats.non_empty > 0 && stats.observable_fraction === 0) {
      // Header said "indicator" but nothing parses — keep as other (still logged).
      intent = 'other';
      method = 'header_unverified';
    }
    columns.push({
      index: c,
      header: header || null,
      intent: intent || 'other',
      method: method || 'unclassified',
      declared_type: declaredFromHeader && intent === 'indicator' ? declaredFromHeader : null,
      ...stats
    });
  }
  // Description: the widest non-indicator, non-type text column when unlabelled.
  if (!columns.some((c) => c.intent === 'description')) {
    const others = columns.filter((c) => c.intent === 'other' && c.method !== 'version_column' && c.method !== 'attribute_column' && c.non_empty > 0);
    others.sort((a, b) => b.avg_chars - a.avg_chars);
    if (others[0]) {
      others[0].intent = 'description';
      others[0].method = 'content';
    }
  }
  result.columns = columns;

  const indicatorCols = columns.filter((c) => c.intent === 'indicator');
  const typeCol = columns.find((c) => c.intent === 'type') || null;
  const descCols = columns.filter((c) => c.intent === 'description');
  if (!indicatorCols.length) {
    result.reason = 'no_indicator_column';
    return result;
  }

  // Row assertions
  const rejectionReasons = {};
  const reject = (row, reason) => {
    rejectionReasons[reason] = (rejectionReasons[reason] || 0) + 1;
    result.rows.push({ ...row, status: 'rejected', reason });
  };
  // Stacked sub-tables: a later row made only of column labels ("IP Address |
  // Notes", "Domain/URL | Notes" under an initial "SHA256 | Notes" header)
  // starts a new group whose labels declare the indicator columns' types.
  let segmentDeclared = null;
  for (let i = 0; i < rows.length; i += 1) {
    const cells = rows[i];
    result.stats.rows_seen += 1;
    const subheader = subHeaderRowDeclarations(cells, indicatorCols);
    if (subheader) {
      segmentDeclared = subheader;
      reject({ row_index: i, cells: cells.map((c) => String(c || '').trim()), values: [] }, 'subheader_row');
      continue;
    }
    const declaredRow = typeCol ? parseDeclaredType(cells[typeCol.index]) : null;
    const description = descCols.map((c) => String(cells[c.index] || '').trim()).filter(Boolean).join(' · ') || null;
    const row = {
      row_index: i,
      declared_type: declaredRow,
      type_cell: typeCol ? String(cells[typeCol.index] || '').trim() || null : null,
      description,
      // Every cell of the publisher's row, in column order: provenance only
      // (observation dates, columns no intent claimed), never assertions.
      cells: cells.map((c) => String(c || '').trim()),
      values: []
    };
    const rejected = [];
    for (const col of indicatorCols) {
      const cell = String(cells[col.index] || '');
      if (!cell.trim()) continue;
      const segment = segmentDeclared && segmentDeclared.has(col.index) ? segmentDeclared.get(col.index) : undefined;
      const declared = segment !== undefined ? segment.declared || declaredRow : col.declared_type || declaredRow;
      const typeLabel =
        (typeCol ? String(cells[typeCol.index] || '').trim() : '') || (segment !== undefined ? segment.label : col.header) || null;
      const parsed = parseIndicatorCell(cell, declared, { typeLabel });
      for (const v of parsed.values) {
        row.values.push({
          ...v,
          column_index: col.index,
          indicator_cell: cell.trim(),
          declared_type: declared ? declared.type : null,
          declared_endpoint: declared ? declared.endpoint : false
        });
      }
      rejected.push(...parsed.rejected);
      if (!parsed.values.length && parsed.reason) rejected.push({ raw: cell, error: parsed.reason });
    }
    if (!row.values.length) {
      const allEmpty = indicatorCols.every((c) => !String(cells[c.index] || '').trim());
      const unsupported = declaredRow && declaredRow.type === 'email';
      if (!cells.some((c) => c.trim())) reject(row, 'empty_row');
      else reject(row, allEmpty ? 'empty_indicator' : unsupported ? 'unsupported_type' : 'no_observable');
      continue;
    }
    result.stats.rows_valid += 1;
    result.stats.values_asserted += row.values.length;
    result.rows.push({ ...row, status: 'valid', reason: null, rejected_tokens: rejected.length ? rejected.slice(0, 8) : undefined });
  }
  result.stats.rows_rejected = result.stats.rows_seen - result.stats.rows_valid;
  result.stats.rejection_reasons = rejectionReasons;
  applyFileNameColumnConsistency(result.rows, indicatorCols);

  if (!result.stats.rows_valid) {
    result.reason = 'no_valid_rows';
    return result;
  }

  // A table of CVE ids / ATT&CK techniques is an identifier table: its rows are
  // never IOC assertions and the generic pass handles them as before. A table
  // whose values are host / code artifacts (mutex names, paths, config keys)
  // is an artifact table: rows keep their provenance but never assert IOCs.
  const iocValues = result.rows.some((r) => r.status === 'valid' && r.values.some((v) => v.is_ioc));
  if (!iocValues) {
    const artifactValues = result.rows.some(
      (r) => r.status === 'valid' && r.values.some((v) => NON_NETWORK_RESOLVED_TYPES.has(v.candidate_type))
    );
    result.kind = artifactValues ? 'artifact_table' : 'identifier_table';
    result.reason = artifactValues ? 'no_network_values' : 'no_ioc_values';
    return result;
  }

  // Explicitness: the table itself proves IOC semantics when it declares types
  // or labels its indicator column. A dense headerless grid of IPs/domains is
  // not enough — publishers often render narrative infrastructure (public
  // STUN pools, scanned hosts, example ranges) as multi-column IP tables that
  // must not open an authoritative IOC section by density alone. Rows under a
  // real IOC / C2 / Files heading still inherit assertion from the section.
  const iocValuesByColumn = new Map();
  for (const r of result.rows) {
    if (r.status !== 'valid') continue;
    for (const v of r.values) if (v.is_ioc) iocValuesByColumn.set(v.column_index, (iocValuesByColumn.get(v.column_index) || 0) + 1);
  }
  const iocCols = indicatorCols.filter(
    (c) => c.ioc_fraction >= 0.5 || ((c.method === 'header' || c.declared_type) && (iocValuesByColumn.get(c.index) || 0) > 0)
  );
  const headerLabelled = iocCols.some((c) => c.method === 'header' || c.method === 'content_override' || c.declared_type);
  const denseObservables = iocCols.some((c) => c.observable_fraction >= 0.8) && result.stats.rows_valid >= 2;
  const structural = iocCols.length > 0 && (Boolean(typeCol) || headerLabelled);
  const headingText = String(block?.section_heading || block?.table?.caption || '');
  const negativeContext = NEGATIVE_TABLE_CONTEXT_RE.test(headingText) || opts.negativeZone === true;
  const fileHashInventory = isFileHashInventoryTable(columns, result.rows, typeCol);
  const infrastructureLookup = isInfrastructureLookupTable(columns, typeCol);
  const inAuthoritativeScope = tableInAuthoritativeScope(block, opts);
  const authoritativeCaption = AUTHORITATIVE_TABLE_HEADING_RE.test(headingText);
  // Outside curated IOC / C2 / sample scope, column headers alone are not
  // enough: require a declared type column or an authoritative caption.
  // File-hash inventories and Domain|IP|ASN-style lookup tables never
  // self-prove from body analysis context.
  const blockedOutsideScope = fileHashInventory || infrastructureLookup || !(Boolean(typeCol) || authoritativeCaption);
  const selfProving = structural && (inAuthoritativeScope || !blockedOutsideScope);
  result.kind = 'ioc_table';
  result.explicit = selfProving && !negativeContext;
  result.dense_observables = denseObservables;
  result.file_hash_inventory = fileHashInventory;
  result.infrastructure_lookup = infrastructureLookup;
  result.reason = !structural
    ? denseObservables
      ? 'dense_without_type_or_header'
      : 'weak_structure'
    : negativeContext
      ? 'negative_context'
      : !inAuthoritativeScope && fileHashInventory
        ? 'file_hash_inventory_outside_ioc_scope'
        : !inAuthoritativeScope && infrastructureLookup
          ? 'infrastructure_lookup_outside_ioc_scope'
          : !inAuthoritativeScope && blockedOutsideScope
            ? 'header_labelled_outside_ioc_scope'
            : 'structural_ioc_table';
  result.declared_type_column = typeCol ? typeCol.index : null;
  result.indicator_columns = indicatorCols.map((c) => c.index);
  result.description_columns = descCols.map((c) => c.index);
  return result;
}
