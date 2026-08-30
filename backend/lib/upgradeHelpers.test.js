/**
 * Non-destructive tests for upgrade CLI version/argument safety helpers.
 * Mirrors the SemVer gate used by scripts/upgrade.sh.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { isValidSemVer, compareSemVer, isNewerVersion } from './releaseSemver.js';

function normalizeVersionArg(raw) {
  let value = String(raw || '').trim();
  if (value.startsWith('v')) value = value.slice(1);
  if (!isValidSemVer(value)) return null;
  // Reject characters that could break shell interpolation even if SemVer-valid (none today),
  // and reject path-like / injection attempts rejected before SemVer parse in the shell gate.
  if (/[^\w.+-]/.test(value)) return null;
  return value;
}

function assertUpgradeAllowed(current, target) {
  const cmp = compareSemVer(target, current);
  if (cmp == null) return { ok: false, reason: 'invalid' };
  if (cmp < 0) return { ok: false, reason: 'downgrade' };
  if (cmp === 0) return { ok: false, reason: 'same' };
  return { ok: true };
}

test('upgrade version parsing accepts exact SemVer and strips leading v', () => {
  assert.equal(normalizeVersionArg('0.1.0-beta.3'), '0.1.0-beta.3');
  assert.equal(normalizeVersionArg('v0.1.0-beta.3'), '0.1.0-beta.3');
  assert.equal(normalizeVersionArg('0.1.0-beta.3; rm -rf /'), null);
  assert.equal(normalizeVersionArg('../main'), null);
  assert.equal(normalizeVersionArg('latest'), null);
  assert.equal(normalizeVersionArg('main'), null);
});

test('upgrade rejects downgrades and same version; allows newer', () => {
  assert.deepEqual(assertUpgradeAllowed('0.1.0-beta.2', '0.1.0-beta.1'), { ok: false, reason: 'downgrade' });
  assert.deepEqual(assertUpgradeAllowed('0.1.0-beta.2', '0.1.0-beta.2'), { ok: false, reason: 'same' });
  assert.deepEqual(assertUpgradeAllowed('0.1.0-beta.1', '0.1.0-beta.10'), { ok: true });
  assert.equal(isNewerVersion('0.1.0', '0.1.0-beta.9'), true);
});
