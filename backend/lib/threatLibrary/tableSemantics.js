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

import { normalizeCandidateValue } from './candidateValue.js';
import { refangObservable } from './defang.js';
import { resolveDottedTokenType } from './candidateTyping.js';
import { NON_NETWORK_RESOLVED_TYPES } from './observableTypeResolver.js';

/**
 * v2: row type labels feed the observable-type resolver (a "Mutex" / "Path"
 * row never yields a domain / URL), relative paths and technical artifacts
 * are retained as non-IOC row values, tables made only of such artifacts are
 * `artifact_table` (row provenance kept, never explicit).
 */
export const TABLE_SEMANTICS_VERSION = 'tl-table-v2';

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
  let t = String(token || '').trim().replace(TRAILING_PUNCT_RE, '');
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
    typing = resolveDottedTokenType(t, {
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
 * Values asserted by one indicator cell. Whole-cell parse first (single value),
 * then token split for cells that list several indicators.
 * @param {string} cellText
 * @param {{ type: string, endpoint: boolean }|null} declared
 * @param {{ typeLabel?: string|null }} [ctx] row type cell / column label
 */
export function parseIndicatorCell(cellText, declared = null, ctx = {}) {
  const source = String(cellText || '').replace(/\s+/g, ' ').trim();
  const refanged = refangObservable(source);
  if (!refanged) return { values: [], rejected: [], reason: 'empty_indicator' };
  const whole = parseToken(refanged, declared, ctx);
  if (whole?.ok && !(whole.candidate_type === 'domain' && /\s/.test(refanged))) {
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
    const tok = refangedTokens[i];
    if (!tok) continue;
    let parsed = parseToken(tok, declared, ctx);
    if (!parsed) continue;
    if (parsed.ok && aligned) parsed = { ...parsed, raw: sourceTokens[i] };
    if (parsed.ok) {
      const key = `${parsed.candidate_type}\0${parsed.normalized_value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      values.push(parsed);
    } else {
      rejected.push(parsed);
    }
  }
  return { values, rejected, reason: values.length ? null : 'no_observable' };
}

/**
 * True when a whole cell is one observable value (used for column scoring).
 * @param {string} cellText
 */
function cellIsObservable(cellText) {
  const refanged = refangObservable(String(cellText || '').replace(/\s+/g, ' ').trim());
  if (!refanged || refanged.length > 512) return null;
  const parsed = parseToken(refanged, null);
  if (!parsed?.ok) return null;
  // Prose never parses as one value; a dotted phrase with spaces is not an identity.
  if (/\s/.test(refanged)) return null;
  return parsed;
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

/**
 * Interpret a canonical table block.
 * @param {{ id?: string, table?: { headers?: string[]|null, rows?: string[][], caption?: string|null }, section_heading?: string|null, section?: string|null, zone?: string }} block
 * @param {{ negativeZone?: boolean }} [opts]
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
    const intents = first.map((c) => headerIntent(c));
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

  // Column intents: header hints first, then cell syntax.
  const columns = [];
  for (let c = 0; c < width; c += 1) {
    const header = headers ? String(headers[c] ?? '').trim() : '';
    const stats = columnStats(rows, c);
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
    const others = columns.filter((c) => c.intent === 'other' && c.non_empty > 0);
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
  for (let i = 0; i < rows.length; i += 1) {
    const cells = rows[i];
    result.stats.rows_seen += 1;
    const declaredRow = typeCol ? parseDeclaredType(cells[typeCol.index]) : null;
    const description = descCols.map((c) => String(cells[c.index] || '').trim()).filter(Boolean).join(' · ') || null;
    const row = {
      row_index: i,
      declared_type: declaredRow,
      type_cell: typeCol ? String(cells[typeCol.index] || '').trim() || null : null,
      description,
      values: []
    };
    const rejected = [];
    for (const col of indicatorCols) {
      const cell = String(cells[col.index] || '');
      if (!cell.trim()) continue;
      const declared = col.declared_type || declaredRow;
      const typeLabel = (typeCol ? String(cells[typeCol.index] || '').trim() : '') || col.header || null;
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

  // Explicitness: the table itself proves IOC semantics when it declares types,
  // labels its indicator column, or is essentially a list of IOC observables.
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
  const structural = iocCols.length > 0 && (Boolean(typeCol) || headerLabelled || denseObservables);
  const headingText = String(block?.section_heading || block?.table?.caption || '');
  const negativeContext = NEGATIVE_TABLE_CONTEXT_RE.test(headingText) || opts.negativeZone === true;
  result.kind = 'ioc_table';
  result.explicit = structural && !negativeContext;
  result.reason = !structural ? 'weak_structure' : negativeContext ? 'negative_context' : 'structural_ioc_table';
  result.declared_type_column = typeCol ? typeCol.index : null;
  result.indicator_columns = indicatorCols.map((c) => c.index);
  result.description_columns = descCols.map((c) => c.index);
  return result;
}
