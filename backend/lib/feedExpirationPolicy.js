/**
 * IOC-type-based expiration policy overrides.
 *
 * A feed has a single feed-level default expiration policy
 * (threat_feed_expiration_policies, observable_type = 'all'). On top of that,
 * an operator may configure per-IOC-type overrides in
 * integration_feed_expiration_type_policies. A type override with mode
 * 'no_expire' or 'fixed_ttl' takes precedence over the feed default; mode
 * 'inherit' (or no override at all) falls back to the feed default.
 */

/**
 * Normalized IOC type keys used for type overrides. These match the
 * customThreatFeedUtils FIXED_IOC_TYPES convention so the UI, custom feeds and
 * expiration overrides all agree on the same vocabulary.
 */
export const POLICY_IOC_TYPES = Object.freeze(['domain', 'ip', 'url', 'file_hash']);

export const TYPE_POLICY_MODES = Object.freeze(['inherit', 'no_expire', 'fixed_ttl']);

const HASH_OBSERVABLE_TYPES = new Set(['hash', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

/**
 * Map a concrete stored observable_type (e.g. 'md5', 'ipv6', 'domain') to the
 * normalized policy IOC type key used by type overrides. Returns null when the
 * type does not map to a known policy bucket.
 *
 * @param {string} observableType
 * @returns {'domain'|'ip'|'url'|'file_hash'|null}
 */
export function normalizeIocTypeForPolicy(observableType) {
  const t = String(observableType || '').trim().toLowerCase();
  if (!t) return null;
  if (t === 'domain' || t === 'url') return t;
  if (t === 'ip' || t === 'ip6' || t === 'ipv4' || t === 'ipv6') return 'ip';
  if (t === 'file_hash') return 'file_hash';
  if (HASH_OBSERVABLE_TYPES.has(t)) return 'file_hash';
  return null;
}

/**
 * Resolve the effective expiration policy for a specific IOC type,
 * given the feed-level default and an optional type-specific override.
 *
 * @param {{ enabled: boolean, mode: string, ttlDays: number|null }} feedPolicy
 * @param {{ mode: string, ttl_days: number|null }|null} typeOverride
 * @returns {{ enabled: boolean, ttlDays: number|null, source: 'type_override'|'feed_default' }}
 */
export function resolveExpirationPolicy(feedPolicy, typeOverride) {
  if (typeOverride && typeOverride.mode !== 'inherit') {
    if (typeOverride.mode === 'no_expire') {
      return { enabled: false, ttlDays: null, source: 'type_override' };
    }
    if (typeOverride.mode === 'fixed_ttl') {
      const ttl = typeOverride.ttl_days == null ? null : Number(typeOverride.ttl_days);
      // Migration constraint guarantees a positive ttl_days for fixed_ttl. If a
      // malformed override sneaks in (ttl null/invalid), fall back to the feed
      // default rather than producing a broken "expire but no date" policy.
      if (Number.isFinite(ttl) && ttl > 0) {
        return { enabled: true, ttlDays: ttl, source: 'type_override' };
      }
      return {
        enabled: feedPolicy?.enabled ?? false,
        ttlDays: feedPolicy?.ttlDays ?? null,
        source: 'feed_default'
      };
    }
  }
  // inherit or no override: use feed default
  return {
    enabled: feedPolicy?.enabled ?? false,
    ttlDays: feedPolicy?.ttlDays ?? null,
    source: 'feed_default'
  };
}

/**
 * Validate a list of IOC-type override entries from an API request body.
 * Each entry: { ioc_type, mode, ttl_days? }.
 *
 * @param {Array<object>|undefined|null} entries
 * @returns {{ ok: boolean, errors: string[], normalized: Array<{ioc_type:string,mode:string,ttl_days:number|null}> }}
 */
export function validateExpirationTypePolicies(entries) {
  const errors = [];
  const normalized = [];
  if (entries == null) return { ok: true, errors, normalized };
  if (!Array.isArray(entries)) {
    return { ok: false, errors: ['expiration_type_policies must be an array'], normalized };
  }

  const seen = new Set();
  for (const raw of entries) {
    const iocType = String(raw?.ioc_type || '').trim().toLowerCase();
    const mode = String(raw?.mode || '').trim();
    if (!POLICY_IOC_TYPES.includes(iocType)) {
      errors.push(`ioc_type must be one of: ${POLICY_IOC_TYPES.join(', ')}`);
      continue;
    }
    if (seen.has(iocType)) {
      errors.push(`duplicate ioc_type override: ${iocType}`);
      continue;
    }
    seen.add(iocType);
    if (!TYPE_POLICY_MODES.includes(mode)) {
      errors.push(`mode for ${iocType} must be one of: ${TYPE_POLICY_MODES.join(', ')}`);
      continue;
    }
    let ttlDays = raw?.ttl_days == null || raw?.ttl_days === '' ? null : Number(raw.ttl_days);
    if (mode === 'fixed_ttl') {
      if (!Number.isInteger(ttlDays) || ttlDays <= 0) {
        errors.push(`ttl_days for ${iocType} must be a positive integer when mode is fixed_ttl`);
        continue;
      }
    } else {
      ttlDays = null;
    }
    normalized.push({ ioc_type: iocType, mode, ttl_days: ttlDays });
  }

  return { ok: errors.length === 0, errors, normalized };
}
