/**
 * Explicit-table completeness diagnostics.
 *
 * Diagnostic only: this module never inserts, promotes, or re-validates
 * candidates. It records the IOC identities a valid explicit table asserted
 * *before* candidate `add()` can reject them, then compares that set to the
 * identities that actually materialized.
 */

export const DROPPED_ASSERTED_LIMIT = 40;
export const MISSING_IDENTITIES_LIMIT = 40;

export function explicitTableIdentityKey(type, value) {
  return `${String(type || '')}\0${String(value || '')}`;
}

export function formatExplicitTableIdentityKey(key) {
  return String(key || '').replace('\0', ':');
}

/**
 * @returns {{
 *   rememberAsserted: (type: string, value: string) => string,
 *   rememberDropped: (type: string, value: string, reason?: string) => void,
 *   finalize: (createdCandidates: object[]) => {
 *     candidates_created: number,
 *     explicit_identities: number,
 *     missing_identities: string[],
 *     dropped_asserted_identities: { type: string, value: string, reason: string }[],
 *     inconsistent: boolean
 *   }
 * }}
 */
export function createExplicitTableAssertionTracker() {
  /** @type {Map<string, { type: string, value: string }>} */
  const asserted = new Map();
  /** @type {Map<string, { type: string, value: string, reason: string }>} */
  const dropped = new Map();

  const rememberDropped = (type, value, reason) => {
    const key = explicitTableIdentityKey(type, value);
    if (dropped.has(key) || dropped.size >= DROPPED_ASSERTED_LIMIT) return;
    dropped.set(key, { type, value, reason: reason || 'rejected' });
  };

  return {
    rememberAsserted(type, value) {
      const key = explicitTableIdentityKey(type, value);
      if (!asserted.has(key)) asserted.set(key, { type, value });
      return key;
    },
    rememberDropped,
    finalize(createdCandidates) {
      const created = (createdCandidates || []).filter(
        (c) => Array.isArray(c.table_rows) && c.table_rows.some((r) => r.explicit)
      );
      const createdKeys = new Set(created.map((c) => explicitTableIdentityKey(c.candidate_type, c.normalized_value)));
      const missing = [];
      for (const [key, ident] of asserted) {
        if (createdKeys.has(key)) continue;
        missing.push(formatExplicitTableIdentityKey(key));
        if (!dropped.has(key)) rememberDropped(ident.type, ident.value, 'not_materialized');
      }
      return {
        candidates_created: created.length,
        explicit_identities: asserted.size,
        missing_identities: missing.slice(0, MISSING_IDENTITIES_LIMIT),
        dropped_asserted_identities: [...dropped.values()].slice(0, DROPPED_ASSERTED_LIMIT),
        inconsistent: missing.length > 0
      };
    }
  };
}
