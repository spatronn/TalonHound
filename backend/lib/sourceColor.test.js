import test from 'node:test';
import assert from 'node:assert/strict';
import { validateHexColor, isValidHexColor, DEFAULT_SOURCE_COLOR } from './sourceColor.js';

test('validateHexColor accepts a well-formed hex and lowercases it', () => {
  assert.deepEqual(validateHexColor('#7C3AED'), { ok: true, value: '#7c3aed' });
  assert.deepEqual(validateHexColor('  #16a34a  '), { ok: true, value: '#16a34a' });
});

test('validateHexColor treats null/undefined/empty as clear -> null', () => {
  assert.deepEqual(validateHexColor(null), { ok: true, value: null });
  assert.deepEqual(validateHexColor(undefined), { ok: true, value: null });
  assert.deepEqual(validateHexColor(''), { ok: true, value: null });
  assert.deepEqual(validateHexColor('   '), { ok: true, value: null });
});

test('validateHexColor rejects invalid hex values', () => {
  assert.equal(validateHexColor('red').ok, false);
  assert.equal(validateHexColor('#12345').ok, false);
  assert.equal(validateHexColor('#1234567').ok, false);
  assert.equal(validateHexColor('7c3aed').ok, false);
  assert.equal(validateHexColor('#zzzzzz').ok, false);
  assert.equal(validateHexColor('rgb(0,0,0)').ok, false);
});

test('isValidHexColor validates format only', () => {
  assert.equal(isValidHexColor('#abcdef'), true);
  assert.equal(isValidHexColor('#ABCDEF'), true);
  assert.equal(isValidHexColor('#abc'), false);
  assert.equal(isValidHexColor(123), false);
  assert.equal(isValidHexColor(null), false);
});

test('DEFAULT_SOURCE_COLOR is itself a valid hex', () => {
  assert.equal(isValidHexColor(DEFAULT_SOURCE_COLOR), true);
});
