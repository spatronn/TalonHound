import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CANDIDATE_MATCH,
  CatalogLinkError,
  classifyCatalogCandidate,
  compactEntityKey,
  labelIdentity,
  linkSourceLabelToCatalog,
  summarizeLabelAssertions,
  validateCreateInput
} from './attributionCatalogLinking.js';

const FAMILY = (over = {}) => ({
  id: '11111111-1111-4111-8111-111111111111',
  name: 'PureRAT',
  slug: 'purerat',
  aliases: [],
  active: true,
  reference_sources: null,
  ...over
});

test('compactEntityKey ignores case, spaces and punctuation only', () => {
  assert.equal(compactEntityKey('Pure RAT'), 'purerat');
  assert.equal(compactEntityKey('pure-rat'), 'purerat');
  assert.equal(compactEntityKey('APT 28'), 'apt28');
  assert.equal(compactEntityKey('  '), null);
  // Distinct names keep distinct keys (no stemming / fuzzy).
  assert.notEqual(compactEntityKey('PureRAT'), compactEntityKey('PureCrypter'));
  assert.notEqual(compactEntityKey('APT28'), compactEntityKey('APT29'));
});

test('classify: exact canonical name, case- and whitespace-insensitive', () => {
  for (const label of ['PureRAT', 'purerat', '  PURERAT ']) {
    const r = classifyCatalogCandidate(FAMILY(), labelIdentity('malware_family', label));
    assert.equal(r.match, CANDIDATE_MATCH.NAME, label);
  }
});

test('classify: alias match names the alias (Fancy Bear → APT28)', () => {
  const actor = { id: 'a', name: 'APT28', slug: 'apt28', aliases: ['Fancy Bear', 'Sofacy'], active: true };
  const r = classifyCatalogCandidate(actor, labelIdentity('threat_actor', 'fancy bear'));
  assert.deepEqual(r, { match: CANDIDATE_MATCH.ALIAS, match_detail: 'Fancy Bear' });
});

test('classify: slug match', () => {
  const r = classifyCatalogCandidate(FAMILY({ name: 'Pure RAT Loader', slug: 'pure-rat' }), labelIdentity('malware_family', 'Pure RAT'));
  assert.equal(r.match, CANDIDATE_MATCH.SLUG);
});

test('classify: similar spelling is a suggestion, never an exact match', () => {
  const r = classifyCatalogCandidate(FAMILY({ name: 'Pure RAT', slug: 'pure-rat-x' }), labelIdentity('malware_family', 'PureRAT'));
  assert.equal(r.match, CANDIDATE_MATCH.SIMILAR);
  const viaAlias = classifyCatalogCandidate(FAMILY({ name: 'Other', slug: 'other', aliases: ['Pure-RAT'] }), labelIdentity('malware_family', 'PureRAT'));
  assert.deepEqual(viaAlias, { match: CANDIDATE_MATCH.SIMILAR, match_detail: 'Pure-RAT' });
});

test('classify: unrelated catalog row returned by search stays "search"', () => {
  const r = classifyCatalogCandidate(FAMILY({ name: 'PureCrypter', slug: 'purecrypter' }), labelIdentity('malware_family', 'PureRAT'));
  assert.equal(r.match, CANDIDATE_MATCH.SEARCH);
});

test('classify: OTX "<name> - S1234" labels use the ATT&CK id; conflicting ids are never exact', () => {
  const emotet = FAMILY({ name: 'Emotet', slug: 'emotet', reference_sources: { 'mitre-attack': { external_id: 'S0367' } } });
  assert.equal(classifyCatalogCandidate(emotet, labelIdentity('malware_family', 'Emotet - S0367')).match, CANDIDATE_MATCH.NAME);
  const geodo = FAMILY({ name: 'Geodo X', slug: 'geodo-x', reference_sources: { 'mitre-attack': { external_id: 'S0367' } } });
  assert.deepEqual(classifyCatalogCandidate(geodo, labelIdentity('malware_family', 'Emotet - S0367')), { match: CANDIDATE_MATCH.ATTACK_ID, match_detail: 'S0367' });
  const pinnedElsewhere = FAMILY({ name: 'Emotet', slug: 'emotet', reference_sources: { 'mitre-attack': { external_id: 'S9999' } } });
  const r = classifyCatalogCandidate(pinnedElsewhere, labelIdentity('malware_family', 'Emotet - S0367'));
  assert.equal(r.match, CANDIDATE_MATCH.SIMILAR);
  assert.match(r.match_detail, /different ATT&CK id S9999/);
  // Threat actors never parse ATT&CK suffixes.
  assert.equal(labelIdentity('threat_actor', 'Emotet - S0367').attackId, null);
});

test('validateCreateInput: trims, dedupes aliases, keeps analyst text only', () => {
  const r = validateCreateInput('malware_family', { name: '  Pure   RAT ', aliases: 'PureRAT, purerat ,Pure RAT, ', description: '' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { name: 'Pure RAT', slug: 'pure-rat', aliases: ['PureRAT'], description: null });
});

test('validateCreateInput: rejects empty, unsluggable, reserved and oversized input', () => {
  assert.equal(validateCreateInput('malware_family', { name: ' ' }).ok, false);
  assert.equal(validateCreateInput('malware_family', { name: '---' }).ok, false);
  assert.equal(validateCreateInput('threat_actor', { name: 'Unknown' }).ok, false);
  assert.equal(validateCreateInput('threat_actor', { name: 'x'.repeat(101) }).ok, false);
  assert.equal(validateCreateInput('malware_family', { name: 'x'.repeat(128) }).ok, true);
  assert.equal(validateCreateInput('malware_family', { name: 'ok', description: 'd'.repeat(4001) }).ok, false);
  assert.equal(validateCreateInput('campaign', { name: 'ok' }).ok, false);
});

test('summarizeLabelAssertions: unlinked vs linked vs none', () => {
  const row = (over) => ({ entity_id: null, visible: true, ...over });
  assert.equal(summarizeLabelAssertions([row({}), row({ entity_id: 'x' })]).state, 'unlinked');
  const linked = summarizeLabelAssertions([row({ entity_id: 'x' }), row({ entity_id: null, visible: false })]);
  assert.equal(linked.state, 'linked');
  assert.deepEqual(linked.linkedIds, ['x']);
  // Withdrawn / suppressed only: nothing the analyst can see on Overview.
  assert.equal(summarizeLabelAssertions([row({ visible: false })]).state, 'none');
  assert.equal(summarizeLabelAssertions([]).state, 'none');
});

function poolThatMustNotConnect() {
  return { connect: async () => { throw new Error('must not reach the database'); }, query: async () => { throw new Error('no'); } };
}

async function rejectsCode(promise, status, code) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof CatalogLinkError, err?.message);
    assert.equal(err.status, status);
    assert.equal(err.code, code);
    return true;
  });
}

test('linkSourceLabelToCatalog validates IOC, kind, label, mode and entity id before any DB work', async () => {
  const pool = poolThatMustNotConnect();
  const base = { iocId: 5, observableType: 'domain', entityKind: 'malware_family', sourceLabel: 'PureRAT', mode: 'link', entityId: '11111111-1111-4111-8111-111111111111' };
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, iocId: 'x' }), 400, 'INVALID_IOC');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, iocId: -1 }), 400, 'INVALID_IOC');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, observableType: '' }), 400, 'INVALID_IOC');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, entityKind: 'campaign' }), 400, 'INVALID_ENTITY_KIND');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, sourceLabel: '  ' }), 400, 'INVALID_SOURCE_LABEL');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, mode: 'merge' }), 400, 'INVALID_MODE');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, entityId: "1' OR 1=1" }), 400, 'INVALID_ENTITY_ID');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, mode: 'create', create: { name: 'PureRAT' }, canCreate: false }), 403, 'CATALOG_CREATE_FORBIDDEN');
  await rejectsCode(linkSourceLabelToCatalog(pool, { ...base, mode: 'create', create: { name: '' }, canCreate: true }), 400, 'INVALID_CREATE_INPUT');
});
