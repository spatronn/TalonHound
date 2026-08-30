// Deterministic, AST-based expensive-query classifier for IOC List search.
//
// Decides whether a validated DSL query can run on the interactive search path (fast,
// index-friendly, returned synchronously) or must be routed to an asynchronous Deep
// Search. It works ONLY from the normalized AST produced by parseSearchQuery — never from
// raw user strings — and mirrors the SQL the query builder actually emits against the
// indexes that exist on ioc_items (see migration 023: trigram GIN on observable and
// source_name; per-type btree; hash partial indexes).
//
// This is intentionally NOT a query optimizer and does not run EXPLAIN. It is a small,
// auditable rule set keyed on (field, operator) plus AND/OR/NOT structure. The interactive
// path keeps its statement timeout as the ultimate safety net for anything this
// under-classifies (see the timeout -> deep_search fallback in the search route).
//
// Returned reason codes (machine-readable, safe for UI/metrics — never leak SQL):
//   leading_wildcard      a `%value%` / `%value` search whose value is too short for the
//                         trigram index to serve (degrades to a scan)
//   negative_predicate    NOT ILIKE / not_equals / not_in on text — no index can serve it
//   broad_or              an OR group wider than the configured branch limit
//   source_scan           any `source` predicate — compiles to a correlated feed-membership
//                         EXISTS disjunction that cannot use the source_name index
//   no_selective_predicate  an expensive predicate with no selective indexed sibling to
//                           bound the scan

import { getClassifierConfig } from './config.js';

export const DEEP_SEARCH_REASONS = Object.freeze({
  LEADING_WILDCARD: 'leading_wildcard',
  NEGATIVE_PREDICATE: 'negative_predicate',
  BROAD_OR: 'broad_or',
  SOURCE_SCAN: 'source_scan',
  NO_SELECTIVE_PREDICATE: 'no_selective_predicate'
});

// Reason used when the interactive statement timeout fires and the same query is
// re-enqueued as a Deep Search (set by the route, not by this classifier).
export const TIMEOUT_FALLBACK_REASON = 'interactive_statement_timeout';

// Fields whose values are constrained enums / small dimension tables. Equality and
// membership on these are index-backed and (for identity/junction fields) selective.
const ENUM_FIELDS = new Set(['type', 'known_hash_type', 'status', 'confidence', 'classification']);
const DATE_FIELDS = new Set(['first_seen', 'last_changed', 'created_at']);
const HASH_FIELDS = new Set(['md5', 'sha1', 'sha256']);
const ATTR_FIELDS = new Set(['imphash', 'tlsh', 'ssdeep']);

function valueLength(node) {
  const v = node.values && node.values[0];
  return v == null ? 0 : String(v).trim().length;
}

// Classify a single leaf condition into { cost, selective, reason }.
//   cost 'cheap'    -> index-friendly enough for the interactive path
//   cost 'expensive'-> forces a scan; carries a reason
//   selective       -> bounds the result to a small set, so an AND sibling can rescue an
//                      otherwise-expensive predicate
function classifyCondition(node, cfg) {
  const { field, operator } = node;

  // Exact file-hash / non-identity-attribute identity: partial/unique index, one lookup.
  if (HASH_FIELDS.has(field) || ATTR_FIELDS.has(field)) {
    return { cost: 'cheap', selective: true };
  }

  // Enum / small-dimension fields. Index-backed; equality/membership on identity-ish ones
  // (classification via junction) is selective. Negated enum membership still evaluates
  // against a bounded domain, so it stays interactive.
  if (ENUM_FIELDS.has(field)) {
    const selective = (operator === 'equals' || operator === 'in') && field === 'classification';
    return { cost: 'cheap', selective };
  }

  // Date filters compile to indexed range comparisons (created_at) or bounded membership
  // subqueries (first_seen/last_changed). Not selective on their own but not scan-forcing.
  if (DATE_FIELDS.has(field)) {
    return { cost: 'cheap', selective: false };
  }

  // `source` always compiles to `source_name ILIKE … OR EXISTS(feed membership …) OR
  // EXISTS(manual source …)`. The correlated EXISTS disjunction cannot use the source_name
  // trigram index, so EVERY source predicate is a scan regardless of operator.
  if (field === 'source') {
    return { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.SOURCE_SCAN };
  }

  // Free-text fields backed by a trigram GIN index (ioc/observable) or a small junction
  // with an ILIKE (tag/threat_actor).
  const len = valueLength(node);
  switch (operator) {
    case 'equals':
      // Wildcard-free ILIKE -> trigram-served exact match. Selective.
      return { cost: 'cheap', selective: true };
    case 'in':
      return { cost: 'cheap', selective: true };
    case 'starts_with':
      // `value%` prefix — trigram-usable when the value carries a full 3-gram.
      return len >= cfg.trigramMinLength
        ? { cost: 'cheap', selective: false }
        : { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.LEADING_WILDCARD };
    case 'contains':
    case 'ends_with':
      // `%value%` / `%value` — trigram serves it only above the min trigram length.
      return len >= cfg.trigramMinLength
        ? { cost: 'cheap', selective: false }
        : { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.LEADING_WILDCARD };
    case 'not_contains':
    case 'not_equals':
    case 'not_in':
      // Negated text predicates: no index can serve a NOT ILIKE / <> match.
      return { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.NEGATIVE_PREDICATE };
    default:
      // Unknown operator reaching here means the registry changed without updating this
      // map — fail safe by routing to Deep Search rather than risking an interactive scan.
      return { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.NO_SELECTIVE_PREDICATE };
  }
}

// Recursively fold the AST into { cost, selective, reason }.
function classifyNode(node, cfg) {
  if (node.type === 'condition') {
    return classifyCondition(node, cfg);
  }

  if (node.type === 'not') {
    const child = classifyNode(node.child, cfg);
    // Negation destroys the usability of an equality/prefix index. Only a negated enum
    // (bounded domain) stays interactive. A NOT never yields a selective predicate.
    if (child.cost === 'expensive') return { ...child, selective: false };
    const isEnumOnly = node.child.type === 'condition' && ENUM_FIELDS.has(node.child.field);
    if (isEnumOnly) return { cost: 'cheap', selective: false };
    return { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.NEGATIVE_PREDICATE };
  }

  if (node.type === 'and') {
    const children = node.children.map((c) => classifyNode(c, cfg));
    // A selective indexed predicate bounds the whole conjunction to a small driving set,
    // so an otherwise-expensive sibling can be applied as a cheap post-filter.
    if (children.some((c) => c.selective)) {
      return { cost: 'cheap', selective: true };
    }
    const expensive = children.find((c) => c.cost === 'expensive');
    if (expensive) return { cost: 'expensive', selective: false, reason: expensive.reason };
    return { cost: 'cheap', selective: false };
  }

  if (node.type === 'or') {
    const children = node.children.map((c) => classifyNode(c, cfg));
    // OR forces every branch to be evaluated, so an expensive branch cannot be rescued by
    // a selective one and the whole group is at least as wide as its widest branch.
    const expensive = children.find((c) => c.cost === 'expensive');
    if (expensive) return { cost: 'expensive', selective: false, reason: expensive.reason };
    if (node.children.length > cfg.maxOrBranches) {
      return { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.BROAD_OR };
    }
    // A union of selective branches is still selective overall.
    const selective = children.length > 0 && children.every((c) => c.selective);
    return { cost: 'cheap', selective };
  }

  // Unknown node type — fail safe to Deep Search.
  return { cost: 'expensive', selective: false, reason: DEEP_SEARCH_REASONS.NO_SELECTIVE_PREDICATE };
}

/**
 * Classify a parsed DSL query.
 * @param {object} ast  AST from parseSearchQuery(...)
 * @param {{ config?: object }} [opts]
 * @returns {{ mode: 'interactive'|'deep_search', reason: string|null }}
 */
export function classifyQuery(ast, { config = getClassifierConfig() } = {}) {
  if (!ast || typeof ast !== 'object') {
    return { mode: 'interactive', reason: null };
  }
  const result = classifyNode(ast, config);
  if (result.cost === 'expensive') {
    return { mode: 'deep_search', reason: result.reason || DEEP_SEARCH_REASONS.NO_SELECTIVE_PREDICATE };
  }
  return { mode: 'interactive', reason: null };
}
