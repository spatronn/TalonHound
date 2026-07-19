const DEFAULT_RELATION_LIMIT = 5;

function toNonNegativeFiniteNumber(value) {
  if (value == null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function relationIdentity(relation, lookupType) {
  const value = String(lookupType) === 'ip' ? relation?.domain : relation?.value;
  return String(value || '').trim().toLowerCase();
}

export function formatDnsmaniaCount(value) {
  const number = toNonNegativeFiniteNumber(value);
  return number == null ? '0' : number.toLocaleString('en-US');
}

export function getDnsmaniaPresentation({
  summary = {},
  relations = [],
  lookupType = 'ip',
  limit = DEFAULT_RELATION_LIMIT
} = {}) {
  const relationList = Array.isArray(relations) ? relations : [];
  const countField = String(lookupType) === 'ip'
    ? summary?.associated_domain_count
    : summary?.associated_ip_count;
  const compatibilityFallback = String(lookupType) === 'ip'
    ? summary?.associated_domain_count_fallback
    : summary?.associated_ip_count_fallback;
  const seenRelations = new Set();
  const distinctRelations = relationList.filter((relation) => {
    const identity = relationIdentity(relation, lookupType);
    if (!identity || seenRelations.has(identity)) return false;
    seenRelations.add(identity);
    return true;
  });
  const distinctPersistedCount = distinctRelations.length;
  const totalCount = toNonNegativeFiniteNumber(countField)
    ?? toNonNegativeFiniteNumber(compatibilityFallback)
    ?? distinctPersistedCount;
  const effectiveTotalCount = Math.max(totalCount, distinctPersistedCount);
  const safeLimit = Math.max(0, Math.min(Number(limit) || DEFAULT_RELATION_LIMIT, DEFAULT_RELATION_LIMIT));
  const shownRelations = distinctRelations.slice(0, safeLimit);
  const shownCount = shownRelations.length;

  return {
    totalCount: effectiveTotalCount,
    shownRelations,
    shownCount,
    showHint: effectiveTotalCount > shownCount,
    formattedTotal: formatDnsmaniaCount(effectiveTotalCount)
  };
}
