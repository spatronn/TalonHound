// Client-side metadata + DSL generation for IOC Advanced Search.
//
// The Advanced Search panel does NOT talk to a different backend format: it generates
// the SAME DSL text that a user could type by hand, which is then parsed/validated by
// the one backend engine. This module is the single source of the field/operator
// metadata and the condition -> DSL string generator (kept pure and unit-tested).
//
// Mirrors backend/lib/iocSearchDsl/fields.js. `updated_at` is intentionally absent.

export const TEXT_OPERATORS = ['contains', 'equals', 'not_equals', 'starts_with', 'ends_with', 'not_contains'];
export const LIST_OPERATORS = ['in', 'not_in'];
export const ENUM_OPERATORS = ['equals', 'not_equals', 'in', 'not_in'];
export const DATE_OPERATORS = ['before', 'after', 'between'];

export const SEARCH_FIELDS = [
  { name: 'ioc', label: 'IOC', kind: 'text', operators: TEXT_OPERATORS },
  { name: 'type', label: 'Type', kind: 'enum', operators: ENUM_OPERATORS, values: ['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh'] },
  { name: 'tag', label: 'Tag', kind: 'text', operators: [...TEXT_OPERATORS, ...LIST_OPERATORS] },
  { name: 'source', label: 'Source', kind: 'text', operators: [...TEXT_OPERATORS, ...LIST_OPERATORS] },
  { name: 'classification', label: 'Classification', kind: 'enum', operators: ENUM_OPERATORS },
  { name: 'threat_actor', label: 'Threat actor', kind: 'text', operators: [...TEXT_OPERATORS, ...LIST_OPERATORS] },
  { name: 'status', label: 'Status', kind: 'enum', operators: ENUM_OPERATORS, values: ['active', 'expired', 'disabled', 'suppressed'] },
  { name: 'confidence', label: 'Confidence', kind: 'enum', operators: ENUM_OPERATORS, values: ['low', 'medium', 'high'] },
  { name: 'first_seen', label: 'First seen in source', kind: 'date', operators: DATE_OPERATORS },
  { name: 'last_changed', label: 'Last changed in source', kind: 'date', operators: DATE_OPERATORS },
  { name: 'created_at', label: 'Created at', kind: 'date', operators: DATE_OPERATORS }
];

export const FIELD_BY_NAME = Object.fromEntries(SEARCH_FIELDS.map((f) => [f.name, f]));

export const FIELD_LABELS = Object.fromEntries(SEARCH_FIELDS.map((f) => [f.name, f.label]));

export const OPERATOR_LABELS = {
  contains: 'contains',
  equals: 'equals',
  not_equals: 'not equals',
  starts_with: 'starts with',
  ends_with: 'ends with',
  not_contains: 'not contains',
  in: 'in',
  not_in: 'not in',
  before: 'before',
  after: 'after',
  between: 'between'
};

// Export columns offered in the export modal (mirrors backend columns.js). No updated_at.
export const EXPORT_COLUMN_OPTIONS = [
  { key: 'ioc', label: 'IOC' },
  { key: 'ioc_type', label: 'IOC Type' },
  { key: 'status', label: 'Status' },
  { key: 'source', label: 'Source' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'tags', label: 'Tags' },
  { key: 'classifications', label: 'Classifications' },
  { key: 'threat_actor', label: 'Threat actor' },
  { key: 'first_seen_in_source', label: 'First seen in source' },
  { key: 'last_changed_in_source', label: 'Last changed in source' },
  { key: 'created_at', label: 'Created at' }
];

export const DEFAULT_EXPORT_COLUMNS = [
  'ioc', 'ioc_type', 'status', 'source', 'confidence', 'tags', 'classifications',
  'first_seen_in_source', 'last_changed_in_source'
];

export function defaultOperatorFor(fieldName) {
  const f = FIELD_BY_NAME[fieldName];
  if (!f) return 'equals';
  if (f.kind === 'date') return 'after';
  if (f.kind === 'text') return 'contains';
  return 'equals';
}

export function newCondition(fieldName = 'ioc') {
  return { field: fieldName, operator: defaultOperatorFor(fieldName), value: '', value2: '' };
}

function quoteValue(v) {
  return `"${String(v ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

// Split a comma-separated list value into trimmed, non-empty items.
function splitList(v) {
  return String(v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Render a single condition to a DSL fragment. Returns '' when the condition is
// incomplete (so the UI can skip it rather than emit invalid DSL).
export function conditionToDsl(cond) {
  if (!cond || !cond.field || !cond.operator) return '';
  const { field, operator } = cond;
  if (operator === 'in' || operator === 'not_in') {
    const items = splitList(cond.value);
    if (!items.length) return '';
    return `${field} ${operator} (${items.map(quoteValue).join(', ')})`;
  }
  if (operator === 'between') {
    if (!String(cond.value).trim() || !String(cond.value2).trim()) return '';
    return `${field} between ${quoteValue(cond.value)} AND ${quoteValue(cond.value2)}`;
  }
  if (!String(cond.value).trim()) return '';
  return `${field} ${operator} ${quoteValue(cond.value)}`;
}

// Build a full DSL query from the Advanced Search panel state.
//   match: 'all' -> AND, 'any' -> OR
// Single-level combination, so no parentheses are required.
export function buildDslFromConditions(match, conditions) {
  const parts = (conditions || []).map(conditionToDsl).filter(Boolean);
  if (!parts.length) return '';
  const joiner = match === 'any' ? ' OR ' : ' AND ';
  return parts.join(joiner);
}

// Human-readable chip label for an active condition returned by the search API.
export function chipLabel(cond) {
  const fieldLabel = FIELD_LABELS[cond.field] || cond.field;
  const opLabel = OPERATOR_LABELS[cond.operator] || cond.operator;
  let valuePart;
  if (cond.dates && cond.dates.length) {
    valuePart = cond.dates.join(' – ');
  } else if (cond.values && cond.values.length) {
    valuePart = cond.values.join(', ');
  } else {
    valuePart = '';
  }
  return `${fieldLabel} ${opLabel}: ${valuePart}`.trim();
}
