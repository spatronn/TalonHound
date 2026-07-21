import test from 'node:test';
import assert from 'node:assert/strict';
import {
  hasExplicitRunMode,
  resolveManualIntegrationRunMode
} from './integrationManualRun.js';

test('hasExplicitRunMode treats null/undefined/blank as absent', () => {
  assert.equal(hasExplicitRunMode(null), false);
  assert.equal(hasExplicitRunMode(undefined), false);
  assert.equal(hasExplicitRunMode(''), false);
  assert.equal(hasExplicitRunMode('   '), false);
  assert.equal(hasExplicitRunMode('incremental'), true);
});

test('non-USOM accepts missing/null/blank run_mode', () => {
  for (const raw of [undefined, null, '', '  ']) {
    const result = resolveManualIntegrationRunMode('urlhaus', raw);
    assert.equal(result.ok, true);
    assert.equal(result.runMode, null);
  }
});

test('non-USOM rejects explicit run_mode', () => {
  const result = resolveManualIntegrationRunMode('urlhaus', 'incremental');
  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.match(result.message, /usom-trcert/i);
});

test('USOM accepts valid modes and defaults blank to incremental', () => {
  assert.equal(resolveManualIntegrationRunMode('usom-trcert', undefined).runMode, 'incremental');
  assert.equal(resolveManualIntegrationRunMode('usom-trcert', null).runMode, 'incremental');
  assert.equal(resolveManualIntegrationRunMode('usom-trcert', '').runMode, 'incremental');
  assert.equal(
    resolveManualIntegrationRunMode('usom-trcert', 'full_reconciliation').runMode,
    'full_reconciliation'
  );
});

test('USOM rejects invalid run_mode', () => {
  const result = resolveManualIntegrationRunMode('usom-trcert', 'full');
  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.match(result.message, /Invalid run_mode/i);
});
