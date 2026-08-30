// Time-bounded, keyset-paginated Audit Logs query helpers.
//
// Audit history is large and append-only. Instead of OFFSET pagination over the
// whole table (deep pages + full COUNT(*) per request), the list endpoint is
// bounded to a time window and paged with a deterministic keyset cursor on
// (created_at DESC, id DESC).
//
// All timestamps are absolute TIMESTAMPTZ instants — this module never applies a
// timezone. Callers pass ISO strings; the System Timezone only affects display.

export const DEFAULT_AUDIT_LIMIT = 50;
export const MAX_AUDIT_LIMIT = 100;
// Safe default lower bound when no time range is supplied (Last 24 hours).
export const DEFAULT_AUDIT_RANGE_MS = 24 * 60 * 60 * 1000;

/** Bad client input (invalid dates, range, cursor). Maps to HTTP 400. */
export class AuditQueryError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuditQueryError';
  }
}

/** Clamp a requested page size to [1, MAX_AUDIT_LIMIT]; default 50. */
export function parseAuditLimit(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_AUDIT_LIMIT;
  return Math.min(MAX_AUDIT_LIMIT, Math.max(1, Math.floor(n)));
}

function parseInstant(value, label) {
  if (value == null || String(value).trim() === '') return null;
  const d = new Date(String(value).trim());
  if (Number.isNaN(d.getTime())) {
    throw new AuditQueryError(`Invalid "${label}" timestamp`);
  }
  return d;
}

/**
 * Resolve the effective time window for an audit query.
 *
 * Missing lower bound → Last 24 hours (anchored to `to` when present, else now).
 * This guarantees the endpoint can never fall back to an unbounded history scan
 * because a caller omitted the range.
 *
 * @param {{ from?: unknown, to?: unknown, now?: Date }} input
 * @returns {{ from: Date, to: Date|null }}
 * @throws {AuditQueryError} when a supplied timestamp is invalid or from >= to.
 */
export function resolveAuditTimeRange({ from, to, now } = {}) {
  const nowDate = now instanceof Date && !Number.isNaN(now.getTime()) ? now : new Date();
  const toDate = parseInstant(to, 'to');
  let fromDate = parseInstant(from, 'from');
  if (!fromDate) {
    const anchor = toDate || nowDate;
    fromDate = new Date(anchor.getTime() - DEFAULT_AUDIT_RANGE_MS);
  }
  if (toDate && fromDate.getTime() >= toDate.getTime()) {
    throw new AuditQueryError('"from" must be before "to"');
  }
  return { from: fromDate, to: toDate };
}

/**
 * Encode a keyset cursor from a row's ordering key. Opaque base64url of the
 * normalized (created_at, id) pair — never interpolated into SQL.
 * @param {{ created_at: Date|string, id: number|string }} row
 * @returns {string|null}
 */
export function encodeAuditCursor(row) {
  if (!row) return null;
  const createdAt = row.created_at instanceof Date
    ? row.created_at.toISOString()
    : String(row.created_at || '').trim();
  const id = row.id == null ? '' : String(row.id).trim();
  if (!createdAt || !id) return null;
  const json = JSON.stringify({ c: createdAt, i: id });
  return Buffer.from(json, 'utf8').toString('base64url');
}

/**
 * Decode + validate a keyset cursor. Returns null for an empty cursor (first
 * page). Produces a normalized ISO timestamp and numeric id string that are
 * only ever used as bound query parameters.
 * @param {unknown} raw
 * @returns {{ created_at: string, id: string }|null}
 * @throws {AuditQueryError} when the cursor is present but malformed.
 */
export function decodeAuditCursor(raw) {
  const s = raw == null ? '' : String(raw).trim();
  if (!s) return null;
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
  } catch {
    throw new AuditQueryError('Invalid pagination cursor');
  }
  const c = parsed?.c;
  const i = parsed?.i;
  const d = c ? new Date(String(c)) : null;
  if (!d || Number.isNaN(d.getTime())) {
    throw new AuditQueryError('Invalid pagination cursor');
  }
  if (i == null || !/^\d+$/.test(String(i))) {
    throw new AuditQueryError('Invalid pagination cursor');
  }
  return { created_at: d.toISOString(), id: String(i) };
}
