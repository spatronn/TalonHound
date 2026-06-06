import { BULK_TRIAGE_MAX_ITEMS } from './rbac.js';

export function parseBulkIds(raw) {
  if (!Array.isArray(raw)) return { ok: false, message: 'ids must be an array' };
  const ids = [];
  const seen = new Set();
  for (const item of raw) {
    const n = Number(item);
    if (!Number.isFinite(n) || n <= 0) continue;
    const key = String(Math.trunc(n));
    if (seen.has(key)) continue;
    seen.add(key);
    ids.push(Math.trunc(n));
  }
  if (!ids.length) return { ok: false, message: 'At least one valid id is required' };
  if (ids.length > BULK_TRIAGE_MAX_ITEMS) {
    return { ok: false, message: `Bulk limit exceeded (max ${BULK_TRIAGE_MAX_ITEMS})` };
  }
  return { ok: true, ids };
}

export function parseIncidentBulkIds(raw) {
  if (!Array.isArray(raw)) return { ok: false, message: 'ids must be an array' };
  const ids = [];
  const seen = new Set();
  for (const item of raw) {
    const s = String(item ?? '').trim();
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    ids.push(s);
  }
  if (!ids.length) return { ok: false, message: 'At least one valid id is required' };
  if (ids.length > BULK_TRIAGE_MAX_ITEMS) {
    return { ok: false, message: `Bulk limit exceeded (max ${BULK_TRIAGE_MAX_ITEMS})` };
  }
  return { ok: true, ids };
}

/** @returns {{ verdict: string, securityTest: boolean } | null} */
export function normalizeDetectionBulkVerdict(raw) {
  const v = String(raw ?? '').trim().toLowerCase().replace(/\s+/g, '_');
  if (v === 'security_test') return { verdict: 'fp', securityTest: true };
  if (['fp', 'tp', 'suspicious', 'in_progress'].includes(v)) {
    return { verdict: v, securityTest: false };
  }
  return null;
}

/** @returns {{ verdict: string, securityTest: boolean } | null} */
export function normalizeIncidentBulkVerdict(raw) {
  const v = String(raw ?? '').trim();
  const lower = v.toLowerCase().replace(/\s+/g, '_');
  if (lower === 'security_test') return { verdict: 'FP', securityTest: true };
  const allowed = new Set(['TP', 'FP', 'Suspicious', 'Unreviewed', 'In Progress']);
  if (allowed.has(v)) return { verdict: v, securityTest: false };
  return null;
}

export function emptyBulkResponse(total = 0) {
  return { total, succeeded: 0, failed: 0, results: [] };
}

export function pushBulkResult(results, id, ok, error = null) {
  results.push({ id, ok, ...(error ? { error } : {}) });
}
