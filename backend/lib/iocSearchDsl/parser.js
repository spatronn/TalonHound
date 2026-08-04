import { tokenize, TokenType } from './tokenizer.js';
import { DslError } from './errors.js';
import { getSearchLimits } from './config.js';
import {
  canonicalFieldName,
  getFieldSpec,
  operatorSupported
} from './fields.js';
import { assertUsableTextValue, parseDateLiteral, assertHashValue } from './normalize.js';

const LOGICAL_KEYWORDS = new Set(['and', 'or', 'not']);

// Recursive-descent parser producing a normalized, validated AST.
//
// Precedence (lowest to highest): OR, AND, NOT, parentheses/condition.
// The AST is the canonical representation that is both compiled to SQL and persisted
// with an export job, so all field-name canonicalization, operator whitelisting and
// value validation happen here — never in the SQL builder.
class Parser {
  constructor(tokens, limits) {
    this.tokens = tokens;
    this.pos = 0;
    this.limits = limits;
    this.conditionCount = 0;
    this.depth = 0;
  }

  peek(offset = 0) {
    return this.tokens[Math.min(this.pos + offset, this.tokens.length - 1)];
  }

  next() {
    const tok = this.tokens[this.pos];
    if (this.pos < this.tokens.length - 1) this.pos += 1;
    return tok;
  }

  atEnd() {
    return this.peek().type === TokenType.EOF;
  }

  isKeyword(tok, word) {
    return tok.type === TokenType.IDENT && tok.value.toLowerCase() === word;
  }

  parse() {
    if (this.atEnd()) {
      throw new DslError('Empty query', { code: 'empty_query', position: 0 });
    }
    const node = this.parseOr();
    if (!this.atEnd()) {
      const tok = this.peek();
      throw new DslError(`Unexpected token: ${tok.value || tok.type}`, {
        code: 'unexpected_token',
        position: tok.position
      });
    }
    if (this.conditionCount === 0) {
      throw new DslError('Query has no conditions', { code: 'no_conditions', position: 0 });
    }
    return node;
  }

  parseOr() {
    let left = this.parseAnd();
    const children = [left];
    while (this.isKeyword(this.peek(), 'or')) {
      this.next();
      children.push(this.parseAnd());
    }
    if (children.length === 1) return left;
    return { type: 'or', children };
  }

  parseAnd() {
    let left = this.parseNot();
    const children = [left];
    while (this.isKeyword(this.peek(), 'and')) {
      this.next();
      children.push(this.parseNot());
    }
    if (children.length === 1) return left;
    return { type: 'and', children };
  }

  parseNot() {
    if (this.isKeyword(this.peek(), 'not')) {
      this.next();
      return { type: 'not', child: this.parseNot() };
    }
    return this.parsePrimary();
  }

  parsePrimary() {
    const tok = this.peek();
    if (tok.type === TokenType.LPAREN) {
      this.depth += 1;
      if (this.depth > this.limits.maxParenthesesDepth) {
        throw new DslError(
          `Query exceeds maximum parenthesis depth of ${this.limits.maxParenthesesDepth}`,
          { code: 'max_depth_exceeded', position: tok.position }
        );
      }
      this.next(); // consume '('
      const inner = this.parseOr();
      const close = this.peek();
      if (close.type !== TokenType.RPAREN) {
        throw new DslError('Missing closing parenthesis', {
          code: 'unclosed_parenthesis',
          position: close.position
        });
      }
      this.next(); // consume ')'
      this.depth -= 1;
      return inner;
    }
    if (tok.type === TokenType.RPAREN) {
      throw new DslError('Unexpected closing parenthesis', {
        code: 'unexpected_token',
        position: tok.position
      });
    }
    return this.parseCondition();
  }

  parseCondition() {
    const fieldTok = this.peek();
    if (fieldTok.type !== TokenType.IDENT || LOGICAL_KEYWORDS.has(fieldTok.value.toLowerCase())) {
      throw new DslError(`Expected a field name but found: ${fieldTok.value || fieldTok.type}`, {
        code: 'expected_field',
        position: fieldTok.position
      });
    }
    const canonical = canonicalFieldName(fieldTok.value);
    if (!canonical) {
      throw new DslError(`Unknown field: ${fieldTok.value}`, {
        code: 'unknown_field',
        position: fieldTok.position,
        field: fieldTok.value
      });
    }
    this.next();

    const opTok = this.peek();
    if (opTok.type !== TokenType.IDENT) {
      throw new DslError(`Expected an operator after field "${canonical}"`, {
        code: 'expected_operator',
        position: opTok.position,
        field: canonical
      });
    }
    const operator = opTok.value.toLowerCase();
    const spec = getFieldSpec(canonical);
    if (!spec.operators.includes(operator)) {
      throw new DslError(
        `Operator "${operator}" is not supported for field "${canonical}"`,
        { code: 'unsupported_operator', position: opTok.position, field: canonical }
      );
    }
    this.next();

    this.conditionCount += 1;
    if (this.conditionCount > this.limits.maxConditions) {
      throw new DslError(
        `Query exceeds maximum of ${this.limits.maxConditions} conditions`,
        { code: 'max_conditions_exceeded', position: opTok.position }
      );
    }

    if (operator === 'in' || operator === 'not_in') {
      return this.parseListCondition(canonical, spec, operator, opTok.position);
    }
    if (operator === 'between') {
      return this.parseBetweenCondition(canonical, operator, opTok.position);
    }
    if (operator === 'before' || operator === 'after') {
      return this.parseDateCondition(canonical, operator);
    }
    return this.parseScalarCondition(canonical, spec, operator);
  }

  expectString(field, operator) {
    const tok = this.peek();
    if (tok.type !== TokenType.STRING) {
      throw new DslError(`Expected a quoted value after "${field} ${operator}"`, {
        code: 'expected_value',
        position: tok.position,
        field
      });
    }
    this.next();
    return tok;
  }

  parseScalarCondition(field, spec, operator) {
    const tok = this.expectString(field, operator);
    // Hash-kind fields validate + normalize to an exact lowercase hash. The registry
    // only allows `equals` for them, so no fuzzy operator ever reaches here.
    if (spec.kind === 'hash') {
      const value = assertHashValue(tok.value, {
        field,
        hashType: spec.hashType,
        operator,
        position: tok.position
      });
      return { type: 'condition', field, kind: 'hash', operator, values: [value] };
    }
    const value = assertUsableTextValue(tok.value, { field, operator, position: tok.position });
    this.assertEnumValue(field, spec, value, tok.position);
    return { type: 'condition', field, kind: spec.kind, operator, values: [value] };
  }

  parseListCondition(field, spec, operator, position) {
    const open = this.peek();
    if (open.type !== TokenType.LPAREN) {
      throw new DslError(`Expected "(" after "${field} ${operator}"`, {
        code: 'expected_list',
        position: open.position,
        field
      });
    }
    this.next();
    const values = [];
    if (this.peek().type === TokenType.RPAREN) {
      throw new DslError(`Empty list for "${field} ${operator}"`, {
        code: 'empty_list',
        position: this.peek().position,
        field
      });
    }
    for (;;) {
      const tok = this.peek();
      if (tok.type !== TokenType.STRING) {
        throw new DslError(`Expected a quoted value in "${field} ${operator} (...)"`, {
          code: 'expected_value',
          position: tok.position,
          field
        });
      }
      this.next();
      const value = assertUsableTextValue(tok.value, { field, operator, position: tok.position });
      this.assertEnumValue(field, spec, value, tok.position);
      values.push(value);
      if (values.length > this.limits.maxInItems) {
        throw new DslError(
          `List for "${field}" exceeds maximum of ${this.limits.maxInItems} items`,
          { code: 'max_in_items_exceeded', position: tok.position, field }
        );
      }
      const sep = this.peek();
      if (sep.type === TokenType.COMMA) {
        this.next();
        continue;
      }
      if (sep.type === TokenType.RPAREN) {
        this.next();
        break;
      }
      throw new DslError(`Expected "," or ")" in list for "${field}"`, {
        code: 'expected_list_separator',
        position: sep.position,
        field
      });
    }
    return { type: 'condition', field, kind: spec.kind, operator, values };
  }

  parseDateCondition(field, operator) {
    const tok = this.expectString(field, operator);
    const parsed = parseDateLiteral(tok.value, { field, operator, position: tok.position });
    return { type: 'condition', field, kind: 'date', operator, dates: [parsed] };
  }

  parseBetweenCondition(field, operator, position) {
    const fromTok = this.expectString(field, operator);
    const fromDate = parseDateLiteral(fromTok.value, { field, operator, position: fromTok.position });
    const andTok = this.peek();
    if (!this.isKeyword(andTok, 'and')) {
      throw new DslError(`Expected "AND" between the two values of "${field} between"`, {
        code: 'expected_between_and',
        position: andTok.position,
        field
      });
    }
    this.next();
    const toTok = this.expectString(field, operator);
    const toDate = parseDateLiteral(toTok.value, { field, operator, position: toTok.position });
    return { type: 'condition', field, kind: 'date', operator, dates: [fromDate, toDate] };
  }

  assertEnumValue(field, spec, value, position) {
    if (spec.kind !== 'enum' || !spec.allowedValues) return;
    const lower = value.toLowerCase();
    if (!spec.allowedValues.includes(lower)) {
      throw new DslError(
        `Invalid value "${value}" for field "${field}". Allowed: ${spec.allowedValues.join(', ')}`,
        { code: 'invalid_enum_value', position, field }
      );
    }
  }
}

export function parseTokens(tokens, limits = getSearchLimits()) {
  return new Parser(tokens, limits).parse();
}

export function parseDsl(input, limits = getSearchLimits()) {
  const tokens = tokenize(input);
  return parseTokens(tokens, limits);
}
