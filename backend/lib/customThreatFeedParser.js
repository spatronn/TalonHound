import { normalizeObservable } from './observable-normalization.js';
import { mapFixedIocTypeToObservableType } from './customThreatFeedUtils.js';

function inferObservableType(value) {
  const v = String(value || '').trim();
  if (!v) return null;
  const isUrl = /^https?:\/\//i.test(v);
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v);
  if (isUrl || v.includes('/')) return 'url';
  if (isIpv4) return 'ip';
  if (/^[a-f0-9]{32,128}$/i.test(v)) return 'hash';
  return 'domain';
}

const CSV_IOC_HEADERS = new Set(['value', 'ioc', 'indicator']);
const CSV_META_HEADERS = new Set(['type', 'confidence', 'tags', 'threat_classification']);

const MAX_INVALID_SAMPLES = 20;

function splitCsvLine(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === ',' && !inQuotes) {
      out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function isCommentLine(line) {
  const t = String(line || '').trim();
  return !t || t.startsWith('#') || t.startsWith('//') || t.startsWith(';');
}

export function detectFormatFromContent(text, contentType = '', url = '') {
  const ct = String(contentType || '').toLowerCase();
  const path = String(url || '').toLowerCase();
  if (ct.includes('csv') || path.endsWith('.csv')) return 'csv';
  if (ct.includes('text/plain') || path.endsWith('.txt')) return 'txt';
  const sample = String(text || '').slice(0, 4096);
  const lines = sample.split(/\r?\n/).filter((l) => !isCommentLine(l)).slice(0, 5);
  if (!lines.length) return 'txt';
  const commaLines = lines.filter((l) => l.includes(',')).length;
  if (commaLines >= Math.ceil(lines.length / 2)) return 'csv';
  return 'txt';
}

function normalizeHashType(value) {
  const v = String(value || '').trim().toLowerCase();
  if (/^[a-f0-9]{32}$/.test(v)) return 'md5';
  if (/^[a-f0-9]{40}$/.test(v)) return 'sha1';
  if (/^[a-f0-9]{64}$/.test(v)) return 'sha256';
  return 'hash';
}

function resolveObservableType(value, csvType, iocTypeMode, fixedIocType) {
  if (iocTypeMode === 'fixed') {
    const mapped = mapFixedIocTypeToObservableType(fixedIocType);
    if (!mapped) return null;
    if (mapped === 'hash') return normalizeHashType(value);
    return mapped;
  }
  const fromCsv = String(csvType || '').trim().toLowerCase();
  if (fromCsv) {
    if (fromCsv === 'file_hash' || fromCsv === 'hash') return normalizeHashType(value);
    if (['domain', 'ip', 'url', 'ipv4', 'ipv6'].includes(fromCsv)) {
      return fromCsv === 'ipv4' ? 'ip' : fromCsv === 'ipv6' ? 'ip6' : fromCsv;
    }
  }
  const inferred = inferObservableType(value);
  if (!inferred) return null;
  if (inferred === 'hash') return normalizeHashType(value);
  return inferred;
}

function validateValueForType(value, observableType) {
  const v = String(value || '').trim();
  if (!v) return false;
  const t = String(observableType || '').toLowerCase();
  if (t === 'ip') return /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v);
  if (t === 'ip6') return v.includes(':');
  if (t === 'domain') return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(v) || /^[a-z0-9.-]+$/i.test(v);
  if (t === 'url') return /^https?:\/\//i.test(v) || v.includes('/');
  if (['hash', 'md5', 'sha1', 'sha256'].includes(t)) return /^[a-f0-9]{32,128}$/i.test(v);
  return true;
}

function normalizeParsedValue(value, observableType) {
  const t = String(observableType || '').toLowerCase();
  if (t === 'url') return normalizeObservable('url', value);
  if (t === 'domain') return String(value || '').trim().toLowerCase();
  if (['hash', 'md5', 'sha1', 'sha256'].includes(t)) return String(value || '').trim().toLowerCase();
  return String(value || '').trim();
}

function pushInvalid(invalidRows, raw, reason) {
  if (invalidRows.length >= MAX_INVALID_SAMPLES) return;
  invalidRows.push({ raw: String(raw || '').slice(0, 500), reason });
}

export function parseTxtFeedContent(text, options = {}) {
  const { iocTypeMode = 'auto', fixedIocType = null } = options;
  const valid = [];
  const invalidRows = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const line of lines) {
    if (isCommentLine(line)) continue;
    const raw = line.trim();
    if (!raw) continue;
    const observableType = resolveObservableType(raw, null, iocTypeMode, fixedIocType);
    if (!observableType) {
      pushInvalid(invalidRows, raw, 'Could not detect IOC type');
      continue;
    }
    if (iocTypeMode === 'fixed' && !validateValueForType(raw, observableType)) {
      pushInvalid(invalidRows, raw, `Value does not match fixed type ${fixedIocType}`);
      continue;
    }
    const observable = normalizeParsedValue(raw, observableType);
    if (!observable) {
      pushInvalid(invalidRows, raw, 'Empty value after normalization');
      continue;
    }
    valid.push({ observable, observableType, confidence: null, raw });
  }
  return { valid, invalidRows, totalRows: lines.filter((l) => !isCommentLine(l) && l.trim()).length };
}

function findHeaderIndex(headers, names) {
  const lower = headers.map((h) => String(h || '').trim().toLowerCase());
  for (const name of names) {
    const idx = lower.indexOf(name);
    if (idx >= 0) return idx;
  }
  return -1;
}

export function parseCsvFeedContent(text, options = {}) {
  const { iocTypeMode = 'auto', fixedIocType = null } = options;
  const valid = [];
  const invalidRows = [];
  const lines = String(text || '').split(/\r?\n/).filter((l) => !isCommentLine(l));
  if (!lines.length) return { valid, invalidRows, totalRows: 0 };

  const firstCols = splitCsvLine(lines[0]);
  const valueIdx = findHeaderIndex(firstCols, [...CSV_IOC_HEADERS]);
  const hasHeader = valueIdx >= 0;
  const typeIdx = hasHeader ? findHeaderIndex(firstCols, ['type']) : -1;
  const confIdx = hasHeader ? findHeaderIndex(firstCols, ['confidence']) : -1;
  const startLine = hasHeader ? 1 : 0;
  const defaultValueIdx = hasHeader ? valueIdx : 0;

  for (let i = startLine; i < lines.length; i += 1) {
    const cols = splitCsvLine(lines[i]);
    const raw = String(cols[defaultValueIdx] || '').trim();
    if (!raw) continue;
    const csvType = typeIdx >= 0 ? cols[typeIdx] : null;
    const observableType = resolveObservableType(raw, csvType, iocTypeMode, fixedIocType);
    if (!observableType) {
      pushInvalid(invalidRows, raw, 'Could not detect IOC type');
      continue;
    }
    if (iocTypeMode === 'fixed' && !validateValueForType(raw, observableType)) {
      pushInvalid(invalidRows, raw, `Value does not match fixed type ${fixedIocType}`);
      continue;
    }
    const observable = normalizeParsedValue(raw, observableType);
    if (!observable) {
      pushInvalid(invalidRows, raw, 'Empty value after normalization');
      continue;
    }
    let confidence = null;
    if (confIdx >= 0 && cols[confIdx]) {
      confidence = String(cols[confIdx]).trim().toLowerCase();
    }
    valid.push({ observable, observableType, confidence, raw });
  }

  const dataLines = lines.slice(startLine).filter((l) => splitCsvLine(l)[defaultValueIdx]?.trim());
  return { valid, invalidRows, totalRows: dataLines.length };
}

export function parseFeedContent(text, options = {}) {
  const format = options.format === 'auto'
    ? detectFormatFromContent(text, options.contentType, options.url)
    : options.format;
  const parseOpts = {
    iocTypeMode: options.iocTypeMode || 'auto',
    fixedIocType: options.fixedIocType || null
  };
  if (format === 'csv') return { ...parseCsvFeedContent(text, parseOpts), detectedFormat: 'csv' };
  return { ...parseTxtFeedContent(text, parseOpts), detectedFormat: 'txt' };
}

export function buildParseSample(valid, invalidRows, limit = 10) {
  return {
    valid_sample_count: valid.length,
    invalid_sample_count: invalidRows.length,
    sample_parsed_iocs: valid.slice(0, limit).map((r) => ({
      observable: r.observable,
      observable_type: r.observableType,
      confidence: r.confidence || null
    })),
    invalid_samples: invalidRows.slice(0, limit)
  };
}
