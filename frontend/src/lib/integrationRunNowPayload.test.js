import test from 'node:test';
import assert from 'node:assert/strict';
import { buildIntegrationRunNowPayload } from './integrationRunNowPayload.js';

test('USOM payload includes run_mode', () => {
  assert.deepEqual(
    buildIntegrationRunNowPayload('usom-trcert', 'incremental'),
    { run_mode: 'incremental' }
  );
  assert.deepEqual(
    buildIntegrationRunNowPayload('usom-trcert', 'full_reconciliation'),
    { run_mode: 'full_reconciliation' }
  );
});

test('non-USOM payload omits run_mode even when a mode arg is passed', () => {
  assert.deepEqual(buildIntegrationRunNowPayload('urlhaus', 'incremental'), {});
  assert.deepEqual(buildIntegrationRunNowPayload('threatfox', 'full_reconciliation'), {});
  assert.deepEqual(buildIntegrationRunNowPayload('emergingthreats-blockrules', 'incremental'), {});
});

test('switching from USOM to another feed does not leak run_mode into payload', () => {
  const usomBody = buildIntegrationRunNowPayload('usom-trcert', 'full_reconciliation');
  assert.equal(usomBody.run_mode, 'full_reconciliation');
  const otherBody = buildIntegrationRunNowPayload('urlhaus', 'full_reconciliation');
  assert.equal(Object.prototype.hasOwnProperty.call(otherBody, 'run_mode'), false);
});
