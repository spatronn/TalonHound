import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildThreatClassificationReconcilePlan,
  descriptionIsEmpty,
  findExistingClassificationMatch,
  buildExistingClassificationIndex
} from './reconciliation.js';
import { resolveBundledMitreMappings } from './mitreReference.js';
import { loadMitreReference, invalidateMitreReferenceCache } from './mitreReference.js';

const BUNDLED_UNKNOWN = {
  id: '4ee39c50-9e95-4c2e-bfba-c177a4c771e7',
  slug: 'unknown',
  name: 'Unknown',
  description: 'Default when classification is unset or unrecognized.',
  sort_order: 0,
  active: true,
  mitre_attack: [],
  resolved_mitre: []
};

const BUNDLED_PHISHING = {
  id: '8d6b91c4-86ad-4247-a986-9afe98fb1b43',
  slug: 'phishing',
  name: 'Phishing',
  description: 'Phishing description',
  sort_order: 10,
  active: true,
  mitre_attack: [{ id: 'T1566' }],
  resolved_mitre: []
};

test('descriptionIsEmpty treats null and blank as empty', () => {
  assert.equal(descriptionIsEmpty(null), true);
  assert.equal(descriptionIsEmpty(''), true);
  assert.equal(descriptionIsEmpty('  '), true);
  assert.equal(descriptionIsEmpty('value'), false);
});

test('findExistingClassificationMatch prefers stable bundled id', () => {
  const index = buildExistingClassificationIndex([
    { id: BUNDLED_PHISHING.id, slug: 'phishing', system_default: true }
  ]);
  const match = findExistingClassificationMatch(BUNDLED_PHISHING, index);
  assert.equal(match.id, BUNDLED_PHISHING.id);
});

test('reconcile plan fills empty descriptions and syncs built-in MITRE mappings', async () => {
  invalidateMitreReferenceCache();
  const reference = await loadMitreReference();
  BUNDLED_PHISHING.resolved_mitre = resolveBundledMitreMappings(BUNDLED_PHISHING.mitre_attack, reference);

  const existing = [
    { id: BUNDLED_UNKNOWN.id, slug: 'unknown', description: 'Default when classification is unset or unrecognized.', system_default: true, active: true, sort_order: 0 },
    { id: BUNDLED_PHISHING.id, slug: 'phishing', description: null, system_default: true, active: true, sort_order: 10 },
    { id: '11111111-1111-4111-8111-111111111111', slug: 'custom_local', description: 'Local custom', system_default: false, active: true, sort_order: 200 }
  ];

  const plan = buildThreatClassificationReconcilePlan([BUNDLED_UNKNOWN, BUNDLED_PHISHING], existing);
  assert.equal(plan.inserts.length, 0);
  assert.equal(plan.descriptionUpdates.length, 1);
  assert.equal(plan.descriptionUpdates[0].slug, 'phishing');
  assert.equal(plan.mitreSyncs.length, 2);
  assert.equal(plan.preservedCustom, 1);
  assert.equal(plan.skippedUnknown, true);
});

test('reconcile plan inserts missing bundled built-ins', () => {
  const plan = buildThreatClassificationReconcilePlan([BUNDLED_PHISHING], []);
  assert.equal(plan.inserts.length, 1);
  assert.equal(plan.inserts[0].slug, 'phishing');
});
