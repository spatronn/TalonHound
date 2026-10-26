/**
 * Structure-aware parsing of tabular / record IOC packs (tl-ioc-source-structured-v1).
 *
 * CSV and NDJSON packs carry their meaning in columns and fields: an `IOC`
 * column next to a `Link` column, an ECS `threat.indicator.url` next to a
 * `description` that repeats the value in braces. A free-text scan of such a
 * file promotes reference links and glues delimiters onto values. Here every
 * value comes from one field whose meaning is known:
 *
 *   CSV    RFC 4180 records (quoted fields, escaped quotes, embedded newlines).
 *          The header decides which columns hold indicators (`ioc`, `value`,
 *          `data`, or a type-named column such as `domain` / `sha256`), which
 *          column declares the row type (`type`), and everything else
 *          (`link`, `reference`, `description`, dates, tags) is metadata that
 *          is never scanned for observables. A row whose declared type is not
 *          a TalonHound IOC type (filename, port, user_agent, file_path) is
 *          skipped and counted.
 *   NDJSON one JSON record per line. Elastic Common Schema
 *          `threat.indicator` records are read field by field (file hashes,
 *          url, ip, domain by indicator type); description / reference /
 *          provider are never read. Other records go through the keyed
 *          indicator walker used for loose JSON.
 *
 * Values are whole fields (or whitespace-separated tokens of an indicator
 * field) normalized with the extractor's own `normalizeCandidateValue`, so a
 * value can never extend across a field boundary.
 */

import { normalizeCandidateValue } from '../candidateValue.js';
import { toLinkedSourceCandidate } from './linkedCandidate.js';

export const STRUCTURED_SOURCE_PARSER_VERSION = 'tl-ioc-source-structured-v2';

const IOC_TYPES = new Set(['ip', 'ipv6', 'cidr', 'domain', 'url', 'md5', 'sha1', 'sha256']);

/** Declared row / column type → normalization hint (null = not an IOC type). */
const DECLARED_TYPE_HINTS = new Map([
  ['domain', 'domain'], ['domains', 'domain'], ['domain-name', 'domain'], ['domain_name', 'domain'], ['hostname', 'domain'],
  ['host', 'domain'], ['fqdn', 'domain'],
  ['url', 'url'], ['urls', 'url'], ['uri', 'url'],
  // A host + path written without a scheme ("ip_path,192.0.2.7/api/x") is a
  // URL; read as an IP it would drop the publisher's path (structured-v2).
  ['ip_path', 'url'], ['ip-path', 'url'], ['ip:path', 'url'], ['host_path', 'url'], ['domain_path', 'url'], ['url_path', 'url'],
  ['ip', 'ip'], ['ips', 'ip'], ['ipv4', 'ip'], ['ipv6', 'ip'], ['ip-dst', 'ip'], ['ip-src', 'ip'], ['ip_address', 'ip'],
  ['ip address', 'ip'], ['ip addresses', 'ip'], ['ipv4-addr', 'ip'], ['ipv6-addr', 'ip'], ['ip_port', 'ip'], ['ip-port', 'ip'],
  ['ip:port', 'ip'], ['ip-dst|port', 'ip'],
  ['md5', 'hash'], ['sha1', 'hash'], ['sha-1', 'hash'], ['sha256', 'hash'], ['sha-256', 'hash'], ['hash', 'hash'],
  ['hashes', 'hash'], ['file hash', 'hash'], ['filehash', 'hash'], ['file_hash', 'hash']
]);

const TYPE_COLUMN_RE = /^(?:type|ioc[\s_-]*type|indicator[\s_-]*type|observable[\s_-]*type|kind|data[\s_-]*type)$/;
const VALUE_COLUMN_RE = /^(?:iocs?|indicators?|value|data|observables?|ioc[\s_-]*value|indicator[\s_-]*value|artifacts?)$/;

function headerKey(cell) {
  return String(cell || '').replace(/^﻿/, '').trim().toLowerCase();
}

function declaredHint(label) {
  const key = headerKey(label);
  return DECLARED_TYPE_HINTS.has(key) ? DECLARED_TYPE_HINTS.get(key) : null;
}

/**
 * RFC 4180 record parser (quoted fields, `""` escapes, CR/LF/CRLF, newlines
 * inside quotes). The delimiter is chosen from the first line.
 * @param {string} text
 * @returns {string[][]}
 */
export function parseCsvRecords(text) {
  const src = String(text || '').replace(/^﻿/, '');
  const firstLine = src.split(/\r?\n/, 1)[0] || '';
  const count = (ch) => (firstLine.match(new RegExp(`\\${ch}`, 'g')) || []).length;
  const delimiter = count('\t') > count(',') && count('\t') >= count(';') ? '\t' : count(';') > count(',') ? ';' : ',';
  const records = [];
  let field = '';
  let record = [];
  let quoted = false;
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i += 1;
        } else quoted = false;
      } else field += ch;
      continue;
    }
    if (ch === '"' && field.trim() === '') {
      quoted = true;
      field = '';
    } else if (ch === delimiter) {
      record.push(field);
      field = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && src[i + 1] === '\n') i += 1;
      record.push(field);
      if (record.some((f) => f.trim() !== '')) records.push(record);
      record = [];
      field = '';
    } else field += ch;
  }
  record.push(field);
  if (record.some((f) => f.trim() !== '')) records.push(record);
  return records.map((r) => r.map((f) => f.trim()));
}

/**
 * Normalize one field value under an optional declared hint. `ip` rows keep
 * only the address of an `address:port` endpoint.
 */
function normalizeField(value, hint) {
  let v = String(value || '').trim().replace(/^["'`]|["'`]$/g, '');
  if (!v) return null;
  if (hint === 'ip') {
    const ep = v.replace(/\[\.\]/g, '.').match(/^((?:\d{1,3}\.){3}\d{1,3})[:|](\d{1,5})$/);
    if (ep) v = ep[1];
  }
  let n = normalizeCandidateValue(v, hint === 'hash' ? null : hint);
  if (!n.ok && hint) n = normalizeCandidateValue(v, null);
  if (!n.ok || !IOC_TYPES.has(n.candidateType) || n.isIoc === false) return null;
  return n;
}

function candidateFromField(n, meta, provenance) {
  return toLinkedSourceCandidate(
    {
      candidate_type: n.candidateType,
      original_value: n.originalValue,
      normalized_value: n.normalizedValue,
      evidence_text: provenance.evidence_text,
      evidence: {
        ...(n.reservedAddress ? { reserved_address: true } : {}),
        ...(n.nonActionableLocal ? { non_actionable_local: true } : {}),
        structured_source: provenance.structured
      },
      occurrences: [
        {
          zone: 'linked_ioc_source',
          asserted: true,
          occurrence_kind: 'standalone_indicator_row',
          surrounding_text: provenance.evidence_text
        }
      ]
    },
    meta
  );
}

function finish(format, candidates, warnings, stats) {
  const byKey = new Map();
  for (const c of candidates) {
    const key = `${c.candidate_type}\0${c.normalized_value}`;
    if (!byKey.has(key)) byKey.set(key, c);
  }
  const unique = [...byKey.values()];
  const typeBreakdown = {};
  for (const c of unique) typeBreakdown[c.candidate_type] = (typeBreakdown[c.candidate_type] || 0) + 1;
  return {
    ok: true,
    format,
    candidates: unique,
    raw_count: candidates.length,
    unique_count: unique.length,
    type_breakdown: typeBreakdown,
    warnings,
    structured: { parser_version: STRUCTURED_SOURCE_PARSER_VERSION, ...stats }
  };
}

/**
 * @param {string} body
 * @param {{ sourcePublicId?: string|null, filePath?: string|null }} [meta]
 */
export function parseCsvIocSource(body, meta = {}) {
  const records = parseCsvRecords(body);
  const warnings = [];
  if (!records.length) return { ok: false, code: 'parse_failed', format: 'csv', message: 'Empty CSV', candidates: [], warnings };

  const header = records[0].map(headerKey);
  let typeCol = header.findIndex((h) => TYPE_COLUMN_RE.test(h));
  let valueCols = header
    .map((h, i) => ({ i, h }))
    .filter(({ h, i }) => i !== typeCol && (VALUE_COLUMN_RE.test(h) || declaredHint(h)))
    .map(({ i }) => i);
  let rows = records.slice(1);
  let headerless = false;
  if (!valueCols.length) {
    // No recognised header: every column whose fields are (almost) all IOCs
    // is an indicator column; the first record is data.
    headerless = true;
    typeCol = -1;
    rows = records;
    const width = Math.max(...records.map((r) => r.length));
    valueCols = [];
    for (let i = 0; i < width; i += 1) {
      const cells = records.map((r) => r[i]).filter(Boolean);
      const parsed = cells.filter((c) => normalizeField(c, null)).length;
      if (cells.length && parsed / cells.length >= 0.8) valueCols.push(i);
    }
    warnings.push('csv_header_not_recognized');
    if (!valueCols.length) {
      return { ok: false, code: 'unsupported_csv_schema', format: 'csv', message: 'No indicator column found', candidates: [], warnings };
    }
  }

  const out = [];
  const skippedTypes = {};
  let rejected = 0;
  rows.forEach((row, idx) => {
    const rowType = typeCol >= 0 ? headerKey(row[typeCol]) : null;
    let rowHint = null;
    if (rowType) {
      rowHint = declaredHint(rowType);
      if (!rowHint) {
        skippedTypes[rowType] = (skippedTypes[rowType] || 0) + 1;
        return;
      }
    }
    const rowText = row.filter(Boolean).join(' | ').slice(0, 300);
    for (const col of valueCols) {
      const hint = rowHint || (headerless ? null : declaredHint(header[col]));
      const cell = row[col];
      if (!cell) continue;
      // An indicator field may list several values; never words of prose.
      const tokens = /\s/.test(cell) ? cell.split(/\s+/).filter(Boolean) : [cell];
      for (const tok of tokens) {
        const n = normalizeField(tok, hint);
        if (!n) {
          rejected += 1;
          continue;
        }
        out.push(
          candidateFromField(n, meta, {
            evidence_text: rowText,
            structured: {
              format: 'csv',
              row_index: idx + (headerless ? 0 : 1),
              column_index: col,
              column_header: headerless ? null : records[0][col],
              row_type: rowType || null
            }
          })
        );
      }
    }
  });
  if (rejected) warnings.push('csv_values_rejected');
  return finish('csv', out, warnings, {
    headerless,
    value_columns: valueCols.map((i) => (headerless ? i : records[0][i])),
    type_column: typeCol >= 0 ? records[0][typeCol] : null,
    ignored_columns: headerless ? [] : records[0].filter((_, i) => i !== typeCol && !valueCols.includes(i)),
    skipped_row_types: skippedTypes,
    rejected_values: rejected
  });
}

/** ECS `threat.indicator` → [[value, hint, field]] (never description / reference). */
function ecsIndicatorValues(ind) {
  const out = [];
  const type = String(ind?.type || '').toLowerCase();
  const hashes = ind?.file?.hash && typeof ind.file.hash === 'object' ? ind.file.hash : {};
  for (const alg of ['md5', 'sha1', 'sha256']) {
    if (typeof hashes[alg] === 'string') out.push([hashes[alg], 'hash', `file.hash.${alg}`]);
  }
  const url = ind?.url;
  if (typeof url === 'string') out.push([url, 'url', 'url']);
  else if (url && typeof url === 'object') {
    const full = url.full || url.original;
    if (typeof full === 'string') out.push([full, 'url', url.full ? 'url.full' : 'url.original']);
    if (type === 'domain-name' && typeof url.domain === 'string') out.push([url.domain, 'domain', 'url.domain']);
  }
  if (typeof ind?.ip === 'string') out.push([ind.ip, 'ip', 'ip']);
  if (type === 'domain-name' && typeof ind?.domain === 'string') out.push([ind.domain, 'domain', 'domain']);
  return out;
}

/** Keyed loose-JSON values of one non-ECS record. */
function looseRecordValues(record) {
  const out = [];
  const walk = (node, depth) => {
    if (depth > 6 || node == null) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    if (typeof node !== 'object') return;
    for (const key of ['indicators', 'iocs', 'observables', 'data', 'items', 'values']) {
      if (key in node) walk(node[key], depth + 1);
    }
    for (const key of ['value', 'indicator', 'ioc', 'observable', 'hash', 'ip', 'domain', 'url', 'sha256', 'md5', 'sha1']) {
      const v = node[key];
      if (typeof v === 'string' || typeof v === 'number') out.push([String(v), declaredHint(key), key]);
    }
  };
  walk(record, 0);
  return out;
}

/**
 * @param {string} body
 * @param {{ sourcePublicId?: string|null, filePath?: string|null }} [meta]
 */
export function parseNdjsonIocSource(body, meta = {}) {
  const lines = String(body || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const warnings = [];
  const out = [];
  const unsupported = {};
  let parseErrors = 0;
  let ecsRecords = 0;
  lines.forEach((line, idx) => {
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      parseErrors += 1;
      return;
    }
    const ind = record?.threat?.indicator;
    let values;
    if (ind && typeof ind === 'object') {
      ecsRecords += 1;
      values = ecsIndicatorValues(ind);
      if (!values.length) {
        const t = String(ind.type || 'unknown').toLowerCase();
        unsupported[t] = (unsupported[t] || 0) + 1;
      }
    } else {
      values = looseRecordValues(record);
    }
    for (const [value, hint, field] of values) {
      const n = normalizeField(value, hint);
      if (!n) continue;
      out.push(
        candidateFromField(n, meta, {
          evidence_text: `${field}: ${value}`.slice(0, 300),
          structured: {
            format: 'ndjson',
            line_index: idx,
            field,
            ...(ind ? { ecs_indicator_type: ind.type || null } : {})
          }
        })
      );
    }
  });
  if (!out.length && parseErrors === lines.length) {
    return { ok: false, code: 'parse_failed', format: 'ndjson', message: 'No JSON records', candidates: [], warnings };
  }
  if (parseErrors) warnings.push('ndjson_unparsable_lines');
  return finish('ndjson', out, warnings, {
    records: lines.length,
    ecs_records: ecsRecords,
    unparsable_lines: parseErrors,
    unsupported_indicator_types: unsupported
  });
}
