import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateSetupCode,
  normalizeSetupCode,
  hashSetupCode,
  verifySetupCode,
  isSha256Hex,
  SETUP_CODE_POLICY
} from './setupCode.js';

test('generateSetupCode produces grouped code from the unambiguous alphabet', () => {
  for (let i = 0; i < 50; i += 1) {
    const code = generateSetupCode();
    assert.match(code, /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    const bare = code.replace(/-/g, '');
    assert.equal(bare.length, SETUP_CODE_POLICY.length);
    for (const ch of bare) {
      assert.ok(SETUP_CODE_POLICY.alphabet.includes(ch), `unexpected char ${ch}`);
    }
    // No ambiguous characters.
    assert.ok(!/[ILOU01]/.test(bare));
  }
});

test('generateSetupCode is effectively unique', () => {
  const seen = new Set();
  for (let i = 0; i < 500; i += 1) seen.add(generateSetupCode());
  assert.equal(seen.size, 500);
});

test('normalizeSetupCode uppercases and strips separators/whitespace', () => {
  assert.equal(normalizeSetupCode('abcd-efgh'), 'ABCDEFGH');
  assert.equal(normalizeSetupCode('  ab cd-ef.gh '), 'ABCDEFGH');
  assert.equal(normalizeSetupCode(''), '');
  assert.equal(normalizeSetupCode(null), '');
  assert.equal(normalizeSetupCode(undefined), '');
});

test('hashSetupCode is deformatting-insensitive and deterministic', () => {
  const code = generateSetupCode();
  const h1 = hashSetupCode(code);
  const h2 = hashSetupCode(code.toLowerCase());
  const h3 = hashSetupCode(code.replace(/-/g, ' ').toLowerCase());
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.equal(h1, h2);
  assert.equal(h1, h3);
  assert.equal(hashSetupCode(''), '');
});

test('verifySetupCode accepts the matching code in any formatting, rejects others', () => {
  const code = generateSetupCode();
  const hash = hashSetupCode(code);
  assert.equal(verifySetupCode(code, hash), true);
  assert.equal(verifySetupCode(code.toLowerCase(), hash), true);
  assert.equal(verifySetupCode(`${code}`.replace(/-/g, ''), hash), true);
  assert.equal(verifySetupCode('WRON-GCOD-EWRO-NGXX', hash), false);
  assert.equal(verifySetupCode('', hash), false);
  assert.equal(verifySetupCode(code, ''), false);
  assert.equal(verifySetupCode(code, 'not-a-hash'), false);
  assert.equal(verifySetupCode(code, null), false);
});

test('isSha256Hex validates 64-hex only', () => {
  assert.equal(isSha256Hex('a'.repeat(64)), true);
  assert.equal(isSha256Hex('A'.repeat(64)), true);
  assert.equal(isSha256Hex('a'.repeat(63)), false);
  assert.equal(isSha256Hex('g'.repeat(64)), false);
  assert.equal(isSha256Hex(''), false);
});
