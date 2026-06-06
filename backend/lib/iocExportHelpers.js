export const IOC_EXPORT_MAX_LIMIT = 5000;
export const IOC_EXPORT_DEFAULT_LIMIT = 500;

const TYPE_ALIASES = new Map([
  ['ip', 'ip'],
  ['ip6', 'ip'],
  ['domain', 'domain'],
  ['url', 'url'],
  ['file_hash', 'file_hash'],
  ['hash', 'file_hash'],
  ['md5', 'file_hash'],
  ['sha1', 'file_hash'],
  ['sha256', 'file_hash']
]);

const STATUS_VALUES = new Set(['active', 'expired', 'suppressed']);
const CONFIDENCE_VALUES = new Set(['low', 'medium', 'high']);

export function parseIocExportQuery(query = {}) {
  const format = String(query.format || 'json').trim().toLowerCase();
  if (!['json', 'csv'].includes(format)) {
    return { ok: false, message: 'format must be json or csv' };
  }

  const page = Math.max(Number(query.page || 1), 1);
  const pageSize = Math.min(
    Math.max(Number(query.page_size || query.pageSize || query.limit || IOC_EXPORT_DEFAULT_LIMIT), 1),
    IOC_EXPORT_MAX_LIMIT
  );

  const typeRaw = String(query.type || '').trim().toLowerCase();
  let observableType = null;
  if (typeRaw) {
    observableType = TYPE_ALIASES.get(typeRaw) || typeRaw;
    if (!['ip', 'domain', 'url', 'file_hash'].includes(observableType)) {
      return { ok: false, message: 'type must be ip, domain, url, or file_hash' };
    }
  }

  const statusRaw = String(query.status || '').trim().toLowerCase();
  if (statusRaw && !STATUS_VALUES.has(statusRaw)) {
    return { ok: false, message: 'status must be active, expired, or suppressed' };
  }

  const confidenceRaw = String(query.confidence || '').trim().toLowerCase();
  if (confidenceRaw && !CONFIDENCE_VALUES.has(confidenceRaw)) {
    return { ok: false, message: 'confidence must be low, medium, or high' };
  }

  const sinceRaw = String(query.since || '').trim();
  let since = null;
  if (sinceRaw) {
    const d = new Date(sinceRaw);
    if (Number.isNaN(d.getTime())) return { ok: false, message: 'since must be a valid date' };
    since = d.toISOString();
  }

  const includeExpired = String(query.include_expired || 'false').toLowerCase() === 'true';
  const includeSuppressed = String(query.include_suppressed || 'false').toLowerCase() === 'true';

  return {
    ok: true,
    format,
    page,
    pageSize,
    offset: (page - 1) * pageSize,
    filters: {
      type: observableType,
      status: statusRaw || null,
      confidence: confidenceRaw || null,
      source: String(query.source || '').trim() || null,
      tag: String(query.tag || '').trim() || null,
      since,
      include_expired: includeExpired,
      include_suppressed: includeSuppressed,
      q: String(query.q || '').trim() || null
    }
  };
}

export function csvEscape(value) {
  const s = value == null ? '' : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}
