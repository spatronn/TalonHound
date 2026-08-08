// Public entrypoint for the IOC Search DSL.
//
//   parseSearchQuery(input)  -> { ast, normalizedQuery, conditions }  (throws DslError)
//   buildWhereClause(ast)    -> { sql, params }
//
// The same parse + build pair is used by the synchronous search API and, independently,
// by the export worker (which re-parses the stored query text and never trusts a
// client-supplied AST).

import { DslError } from './errors.js';
import { getSearchLimits } from './config.js';
import { tokenize } from './tokenizer.js';
import { parseTokens } from './parser.js';
import { buildWhereClause } from './queryBuilder.js';

export { DslError, isDslError } from './errors.js';
export { buildWhereClause } from './queryBuilder.js';
export {
  buildSearchPageSql,
  buildSearchProbeSql,
  buildFileArtifactSearchPageSql,
  buildLegacyFileArtifactSearchPageSql,
  buildCanonicalResultSelectSql,
  buildDeepSearchSpoolInsertSql,
  canonicalSearchPageFromRows
} from './searchPageSql.js';
export { FIELD_REGISTRY, FIELD_NAMES } from './fields.js';
export {
  getSearchLimits,
  getPreviewLimit,
  getQueryTimeoutMs,
  getSearchTimezone,
  getClassifierConfig
} from './config.js';
export {
  classifyQuery,
  DEEP_SEARCH_REASONS,
  TIMEOUT_FALLBACK_REASON
} from './classifyQuery.js';

// Node precedence for deciding when a child must be parenthesized during rendering.
const PREC = { or: 1, and: 2, not: 3, condition: 4 };

function quote(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function renderCondition(node) {
  const { field, operator } = node;
  if (operator === 'in' || operator === 'not_in') {
    return `${field} ${operator} (${node.values.map(quote).join(', ')})`;
  }
  if (operator === 'between') {
    return `${field} between ${quote(node.dates[0].display)} AND ${quote(node.dates[1].display)}`;
  }
  if (operator === 'before' || operator === 'after') {
    return `${field} ${operator} ${quote(node.dates[0].display)}`;
  }
  return `${field} ${operator} ${quote(node.values[0])}`;
}

function renderNode(node, parentPrec) {
  let text;
  let prec;
  if (node.type === 'condition') {
    return renderCondition(node);
  }
  if (node.type === 'not') {
    prec = PREC.not;
    text = `NOT ${renderNode(node.child, PREC.not)}`;
  } else if (node.type === 'and') {
    prec = PREC.and;
    text = node.children.map((c) => renderNode(c, PREC.and)).join(' AND ');
  } else if (node.type === 'or') {
    prec = PREC.or;
    text = node.children.map((c) => renderNode(c, PREC.or)).join(' OR ');
  } else {
    throw new Error(`Unknown AST node type: ${node.type}`);
  }
  return prec < parentPrec ? `(${text})` : text;
}

// Canonical, re-parseable text form of an AST. Field names are already canonical;
// precedence-preserving parentheses are added only where required.
export function renderNormalizedQuery(ast) {
  return renderNode(ast, 0);
}

// Flatten the AST into a list of leaf conditions for building removable UI chips.
// Logical structure is not represented in the flat list; the chips summarize the
// active predicates.
export function flattenConditions(node, acc = []) {
  if (!node) return acc;
  if (node.type === 'condition') {
    acc.push({
      field: node.field,
      operator: node.operator,
      values: node.values ? [...node.values] : undefined,
      dates: node.dates ? node.dates.map((d) => d.display) : undefined
    });
  } else if (node.type === 'not') {
    flattenConditions(node.child, acc);
  } else if (node.children) {
    node.children.forEach((c) => flattenConditions(c, acc));
  }
  return acc;
}

// Parse + validate a raw DSL query. Enforces the max query length before tokenizing so
// a pathological input cannot blow up the lexer. Throws DslError on any violation.
export function parseSearchQuery(input, { limits = getSearchLimits() } = {}) {
  const raw = String(input ?? '');
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new DslError('Invalid search syntax. Example: ioc contains "example.com"', {
      code: 'empty_query',
      position: 0
    });
  }
  if (raw.length > limits.maxQueryLength) {
    throw new DslError(
      `Query exceeds maximum length of ${limits.maxQueryLength} characters`,
      { code: 'max_length_exceeded', position: 0 }
    );
  }
  const tokens = tokenize(raw);
  const ast = parseTokens(tokens, limits);
  return {
    ast,
    normalizedQuery: renderNormalizedQuery(ast),
    conditions: flattenConditions(ast)
  };
}
