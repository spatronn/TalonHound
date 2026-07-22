// Whitelisted DSL fields and the operators each one accepts.
//
// This registry is the single source of truth for validation. The tokenizer/parser
// consult it; the query builder maps each (field, operator) pair to safe,
// parameterized SQL. Nothing outside this list is queryable.
//
// NOTE: `updated_at` is intentionally NOT a field. ioc_items has no truthful
// item-level updated_at column, so exposing it would require a fabricated mapping.
// It is excluded from the DSL, Advanced Search, Syntax Help, the API and export
// columns until a real column exists.
//
// NOTE: `last_seen` is intentionally NOT a field. ioc_items.last_seen_at is written by
// the importer with feed-heterogeneous semantics (source last_online for some feeds,
// observation-refresh for others) and the analyst presentation layer deliberately
// exposes no "last seen / last confirmed in source" value (see
// iocSourceTimestampPresentation.js). Exposing it would present an ambiguous
// analyst-facing timestamp, so it is excluded from v1.
//
// `first_seen` maps to the analyst "First seen in source" = MIN(first_seen_in_feed)
// across feed memberships (fallback to ioc_items.first_seen_at for membership-less
// IOCs) — identical to the export column semantics, so filter and export agree.
// `last_changed` maps to MAX(COALESCE(last_changed_in_source, first_seen_in_feed));
// last_seen_in_feed is never referenced. `created_at` is the unambiguous item creation
// time.

export const TEXT_OPERATORS = Object.freeze([
  'contains',
  'equals',
  'not_equals',
  'starts_with',
  'ends_with',
  'not_contains'
]);

export const LIST_OPERATORS = Object.freeze(['in', 'not_in']);

export const ENUM_OPERATORS = Object.freeze(['equals', 'not_equals', 'in', 'not_in']);

export const DATE_OPERATORS = Object.freeze(['before', 'after', 'between']);

// kind drives value parsing/normalization:
//   text  - quoted string values, ILIKE/equality semantics
//   enum  - constrained (or free) token values, equality/membership semantics
//   date  - date/datetime literals, before/after/between semantics
export const FIELD_REGISTRY = Object.freeze({
  ioc: { kind: 'text', operators: TEXT_OPERATORS },
  tag: { kind: 'text', operators: [...TEXT_OPERATORS, ...LIST_OPERATORS] },
  source: { kind: 'text', operators: [...TEXT_OPERATORS, ...LIST_OPERATORS] },
  threat_actor: { kind: 'text', operators: [...TEXT_OPERATORS, ...LIST_OPERATORS] },
  classification: { kind: 'enum', operators: ENUM_OPERATORS },
  type: {
    kind: 'enum',
    operators: ENUM_OPERATORS,
    allowedValues: ['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']
  },
  status: {
    kind: 'enum',
    operators: ENUM_OPERATORS,
    allowedValues: ['active', 'expired', 'disabled', 'suppressed']
  },
  confidence: {
    kind: 'enum',
    operators: ENUM_OPERATORS,
    allowedValues: ['low', 'medium', 'high']
  },
  first_seen: { kind: 'date', operators: DATE_OPERATORS },
  last_changed: { kind: 'date', operators: DATE_OPERATORS },
  created_at: { kind: 'date', operators: DATE_OPERATORS }
});

export const FIELD_NAMES = Object.freeze(Object.keys(FIELD_REGISTRY));

// A couple of user-friendly aliases normalized to canonical field names. Kept small
// and explicit; field names are otherwise matched case-insensitively.
const FIELD_ALIASES = Object.freeze({
  ioc_value: 'ioc',
  value: 'ioc',
  ioc_type: 'type',
  observable_type: 'type',
  threat_classification: 'classification',
  actor: 'threat_actor'
});

export function canonicalFieldName(raw) {
  const lower = String(raw || '').trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(FIELD_REGISTRY, lower)) return lower;
  if (Object.prototype.hasOwnProperty.call(FIELD_ALIASES, lower)) return FIELD_ALIASES[lower];
  return null;
}

export function getFieldSpec(canonicalName) {
  return FIELD_REGISTRY[canonicalName] || null;
}

export function operatorSupported(canonicalName, operator) {
  const spec = FIELD_REGISTRY[canonicalName];
  if (!spec) return false;
  return spec.operators.includes(operator);
}
