import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidMitreAttackId,
  resolveBundledMitreMappings,
  resolveMitreAttackRecord,
  invalidateMitreReferenceCache
} from './mitreReference.js';

test('isValidMitreAttackId accepts tactic, technique, and sub-technique ids', () => {
  assert.equal(isValidMitreAttackId('TA0011'), true);
  assert.equal(isValidMitreAttackId('T1566'), true);
  assert.equal(isValidMitreAttackId('T1583.001'), true);
  assert.equal(isValidMitreAttackId('INVALID'), false);
});

test('resolveBundledMitreMappings resolves bundled ids against reference snapshot', async () => {
  invalidateMitreReferenceCache();
  const { loadMitreReference } = await import('./mitreReference.js');
  const reference = await loadMitreReference();
  const resolved = resolveBundledMitreMappings([{ id: 'T1566' }, { id: 'TA0011' }], reference);
  assert.equal(resolved.length, 2);
  assert.equal(resolved[0].attack_id, 'T1566');
  assert.equal(resolved[0].attack_type, 'technique');
  assert.match(resolved[0].attack_url, /^https:\/\/attack\.mitre\.org\//);
});

test('resolveBundledMitreMappings rejects duplicate ids', async () => {
  invalidateMitreReferenceCache();
  const { loadMitreReference } = await import('./mitreReference.js');
  const reference = await loadMitreReference();
  assert.throws(
    () => resolveBundledMitreMappings([{ id: 'T1566' }, { id: 'T1566' }], reference),
    /Duplicate MITRE ATT&CK mapping/
  );
});

test('resolveMitreAttackRecord rejects unknown bundled ids', async () => {
  invalidateMitreReferenceCache();
  const { loadMitreReference } = await import('./mitreReference.js');
  const reference = await loadMitreReference();
  assert.throws(
    () => resolveMitreAttackRecord(reference, 'T9999'),
    /not found in bundled reference/
  );
});
