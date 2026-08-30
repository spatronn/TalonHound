/**
 * @param {unknown} raw
 * @param {{ field?: string, minLength?: number, maxLength?: number }} [opts]
 */
export function parseRequiredReason(raw, opts = {}) {
  const field = opts.field || 'reason';
  const minLength = Math.max(Number(opts.minLength ?? 3), 1);
  const maxLength = Math.max(Number(opts.maxLength ?? 4000), minLength);
  const reason = String(raw ?? '').trim();
  if (!reason || reason.length < minLength) {
    return { ok: false, message: `${field} is required (min ${minLength} characters)` };
  }
  return { ok: true, reason: reason.slice(0, maxLength) };
}

/** Accept explicit reason; fall back to legacy note field during API transition. */
export function parseActionReason(body, opts = {}) {
  const raw = body?.reason ?? body?.note;
  return parseRequiredReason(raw, opts);
}
