import { DslError } from './errors.js';

// Token kinds produced by the lexer. Keywords (AND/OR/NOT) and operator words
// (contains/equals/in/...) are all lexed as IDENT and disambiguated by the parser.
export const TokenType = Object.freeze({
  IDENT: 'ident',
  STRING: 'string',
  LPAREN: 'lparen',
  RPAREN: 'rparen',
  COMMA: 'comma',
  EOF: 'eof'
});

const IDENT_START = /[A-Za-z_]/;
const IDENT_CHAR = /[A-Za-z0-9_]/;

// A hand-written scanner (no regex chains) so quoting, escaping and positions are
// handled deterministically. Returns an array of tokens terminated by an EOF token.
export function tokenize(input) {
  const src = String(input);
  const tokens = [];
  let i = 0;
  const n = src.length;

  while (i < n) {
    const ch = src[i];

    // Whitespace
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      i += 1;
      continue;
    }

    if (ch === '(') {
      tokens.push({ type: TokenType.LPAREN, value: '(', position: i });
      i += 1;
      continue;
    }
    if (ch === ')') {
      tokens.push({ type: TokenType.RPAREN, value: ')', position: i });
      i += 1;
      continue;
    }
    if (ch === ',') {
      tokens.push({ type: TokenType.COMMA, value: ',', position: i });
      i += 1;
      continue;
    }

    // Double-quoted string with backslash escapes for \" and \\.
    if (ch === '"') {
      const start = i;
      i += 1;
      let value = '';
      let closed = false;
      while (i < n) {
        const c = src[i];
        if (c === '\\') {
          const next = src[i + 1];
          if (next === '"' || next === '\\') {
            value += next;
            i += 2;
            continue;
          }
          // Unknown escape: keep the backslash literally.
          value += c;
          i += 1;
          continue;
        }
        if (c === '"') {
          closed = true;
          i += 1;
          break;
        }
        value += c;
        i += 1;
      }
      if (!closed) {
        throw new DslError('Unclosed quoted value', { code: 'unclosed_quote', position: start });
      }
      tokens.push({ type: TokenType.STRING, value, position: start });
      continue;
    }

    // Bare identifier (field name / operator word / logical keyword).
    if (IDENT_START.test(ch)) {
      const start = i;
      let value = '';
      while (i < n && IDENT_CHAR.test(src[i])) {
        value += src[i];
        i += 1;
      }
      tokens.push({ type: TokenType.IDENT, value, position: start });
      continue;
    }

    throw new DslError(`Unexpected character: ${JSON.stringify(ch)}`, {
      code: 'unexpected_character',
      position: i
    });
  }

  tokens.push({ type: TokenType.EOF, value: '', position: n });
  return tokens;
}
