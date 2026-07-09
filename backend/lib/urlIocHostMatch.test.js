import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isRootUrlIoc,
  rootUrlCandidatesFromDomain,
  lookupTuplesForObs,
  matchObsToLookup,
  MATCH_SCOPE_HOST_ROOT_URL,
} from './urlIocHostMatch.js';

// -- isRootUrlIoc -------------------------------------------------------------

test('isRootUrlIoc: root URL with trailing slash', () => {
  assert.equal(isRootUrlIoc('https://ultimatebodyrecovery.com/'), true);
  assert.equal(isRootUrlIoc('http://ultimatebodyrecovery.com/'), true);
});

test('isRootUrlIoc: root URL without trailing slash normalizes to root', () => {
  assert.equal(isRootUrlIoc('https://ultimatebodyrecovery.com'), true);
  assert.equal(isRootUrlIoc('http://ultimatebodyrecovery.com'), true);
});

test('isRootUrlIoc: URL with non-root path returns false', () => {
  assert.equal(isRootUrlIoc('https://example.com/malware.exe'), false);
  assert.equal(isRootUrlIoc('https://example.com/login'), false);
  assert.equal(isRootUrlIoc('http://example.com/a/b/c'), false);
});

test('isRootUrlIoc: URL with query string returns false', () => {
  assert.equal(isRootUrlIoc('https://example.com/login?x=1'), false);
  assert.equal(isRootUrlIoc('https://example.com/?ref=abc'), false);
});

test('isRootUrlIoc: empty or invalid input returns false', () => {
  assert.equal(isRootUrlIoc(''), false);
  assert.equal(isRootUrlIoc(null), false);
  assert.equal(isRootUrlIoc('not-a-url'), false);
  assert.equal(isRootUrlIoc('ultimatebodyrecovery.com'), false);
});

// -- rootUrlCandidatesFromDomain ----------------------------------------------

test('rootUrlCandidatesFromDomain: returns https and http root forms', () => {
  const result = rootUrlCandidatesFromDomain('ultimatebodyrecovery.com');
  assert.deepEqual(result, [
    'https://ultimatebodyrecovery.com/',
    'http://ultimatebodyrecovery.com/'
  ]);
});

test('rootUrlCandidatesFromDomain: lowercases domain', () => {
  const result = rootUrlCandidatesFromDomain('Example.COM');
  assert.deepEqual(result, ['https://example.com/', 'http://example.com/']);
});

test('rootUrlCandidatesFromDomain: empty input returns empty array', () => {
  assert.deepEqual(rootUrlCandidatesFromDomain(''), []);
  assert.deepEqual(rootUrlCandidatesFromDomain(null), []);
});

// -- lookupTuplesForObs -------------------------------------------------------

test('lookupTuplesForObs: domain generates domain, url-bare, and root URL tuples', () => {
  const result = lookupTuplesForObs({ type: 'domain', value: 'ultimatebodyrecovery.com' });
  assert.ok(result.some(([v, t]) => v === 'ultimatebodyrecovery.com' && t === 'domain'));
  assert.ok(result.some(([v, t]) => v === 'ultimatebodyrecovery.com' && t === 'url'));
  assert.ok(result.some(([v, t]) => v === 'https://ultimatebodyrecovery.com/' && t === 'url'));
  assert.ok(result.some(([v, t]) => v === 'http://ultimatebodyrecovery.com/' && t === 'url'));
});

test('lookupTuplesForObs: url type returns single normalized url tuple', () => {
  const result = lookupTuplesForObs({ type: 'url', value: 'https://example.com/malware.exe' });
  assert.deepEqual(result, [['https://example.com/malware.exe', 'url']]);
});

test('lookupTuplesForObs: ipv4 returns ip tuple', () => {
  assert.deepEqual(lookupTuplesForObs({ type: 'ipv4', value: '1.2.3.4' }), [['1.2.3.4', 'ip']]);
});

test('lookupTuplesForObs: empty value returns empty array', () => {
  assert.deepEqual(lookupTuplesForObs({ type: 'domain', value: '' }), []);
});

// -- matchObsToLookup ---------------------------------------------------------

function makeMap(entries) {
  return new Map(entries.map(([k, v]) => [k, v]));
}

function makeHit(overrides = {}) {
  return { observable_type: 'domain', confidence: 90, source_name: 'test', updated_at: '2026-01-01', ...overrides };
}

test('domain observable matches root https URL IOC with _matchScope=host_root_url', () => {
  const map = makeMap([
    ['url\thttps://ultimatebodyrecovery.com/', makeHit({ observable_type: 'url', confidence: 90 })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'ultimatebodyrecovery.com' }, map);
  assert.ok(hit, 'should match');
  assert.equal(hit._matchScope, 'host_root_url');
});

test('domain observable matches root http URL IOC with _matchScope=host_root_url', () => {
  const map = makeMap([
    ['url\thttp://ultimatebodyrecovery.com/', makeHit({ observable_type: 'url' })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'ultimatebodyrecovery.com' }, map);
  assert.ok(hit, 'should match');
  assert.equal(hit._matchScope, 'host_root_url');
});

test('domain observable does NOT match path-containing URL IOC', () => {
  const map = makeMap([
    ['url\thttps://example.com/malware.exe', makeHit({ observable_type: 'url' })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'example.com' }, map);
  assert.equal(hit, null, 'must not match path URL via domain observable');
});

test('domain observable does NOT match query-containing URL IOC', () => {
  const map = makeMap([
    ['url\thttps://example.com/login?x=1', makeHit({ observable_type: 'url' })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'example.com' }, map);
  assert.equal(hit, null, 'must not match query URL via domain observable');
});

test('domain observable matches domain IOC with no _matchScope annotation', () => {
  const map = makeMap([['domain\tevil.com', makeHit({ observable_type: 'domain' })]]);
  const hit = matchObsToLookup({ type: 'domain', value: 'evil.com' }, map);
  assert.ok(hit, 'should match');
  assert.equal(hit._matchScope, undefined);
});

test('domain IOC wins over root-URL hit when domain hit is newer (no _matchScope)', () => {
  const domainHit = makeHit({ observable_type: 'domain', confidence: 90, updated_at: '2026-06-01' });
  const urlHit    = makeHit({ observable_type: 'url',    confidence: 90, updated_at: '2026-01-01' });
  const map = makeMap([
    ['domain\tevil.com',                domainHit],
    ['url\thttps://evil.com/', urlHit]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'evil.com' }, map);
  assert.ok(hit);
  assert.equal(hit._matchScope, undefined, 'domain IOC won, not annotated as host_root_url');
});

test('full URL observable matches path-containing URL IOC exactly', () => {
  const urlHit = makeHit({ observable_type: 'url' });
  const map = makeMap([['url\thttps://example.com/malware.exe', urlHit]]);
  const hit = matchObsToLookup({ type: 'url', value: 'https://example.com/malware.exe' }, map);
  assert.ok(hit, 'exact URL match must work');
  assert.equal(hit._matchScope, undefined);
});

test('regression: domain IOC still matches domain observable after fix', () => {
  const map = makeMap([['domain\tevil.com', makeHit({ observable_type: 'domain', confidence: 90 })]]);
  const hit = matchObsToLookup({ type: 'domain', value: 'evil.com' }, map);
  assert.ok(hit, 'domain IOC must still match domain observable');
});

test('ipv4 lookup unaffected by domain URL fix', () => {
  const map = makeMap([['ip\t1.2.3.4', makeHit({ observable_type: 'ip' })]]);
  assert.ok(matchObsToLookup({ type: 'ipv4', value: '1.2.3.4' }, map));
});

test('no match returns null', () => {
  const map = makeMap([]);
  assert.equal(matchObsToLookup({ type: 'domain', value: 'clean.com' }, map), null);
  assert.equal(matchObsToLookup({ type: 'url', value: 'https://clean.com/' }, map), null);
});

test('trailing-slash normalize: domain observable finds IOC stored with trailing slash', () => {
  const map = makeMap([
    ['url\thttps://ultimatebodyrecovery.com/', makeHit({ observable_type: 'url' })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'ultimatebodyrecovery.com' }, map);
  assert.ok(hit, 'should match via root URL candidates');
  assert.equal(hit._matchScope, 'host_root_url');
});

test('domain:443 port strip: domain observable without port matches root URL IOC', () => {
  const map = makeMap([
    ['url\thttps://ultimatebodyrecovery.com/', makeHit({ observable_type: 'url' })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'ultimatebodyrecovery.com' }, map);
  assert.ok(hit, 'port-stripped domain observable must match root URL IOC');
  assert.equal(hit._matchScope, 'host_root_url');
});

// -- IOC identity preservation when host_root_url match ---------------------------

test('host_root_url match: hit.observable carries full URL IOC value', () => {
  const urlValue = 'https://ultimatebodyrecovery.com/';
  const map = makeMap([
    [`url\t${urlValue}`, makeHit({ observable: urlValue, observable_type: 'url', confidence: 90 })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'ultimatebodyrecovery.com' }, map);
  assert.ok(hit, 'should match');
  assert.equal(hit._matchScope, 'host_root_url');
  // The caller (rowToMatchEvents) must use hit.observable for matched_ioc when _matchScope=host_root_url
  assert.equal(hit.observable, urlValue, 'hit.observable must be the full URL IOC value');
  assert.equal(hit.observable_type, 'url', 'hit.observable_type must be url, not domain');
});

test('host_root_url match: hit.observable_type is url not domain', () => {
  const map = makeMap([
    ['url\thttps://ultimatebodyrecovery.com/', makeHit({ observable: 'https://ultimatebodyrecovery.com/', observable_type: 'url' })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'ultimatebodyrecovery.com' }, map);
  assert.equal(hit.observable_type, 'url', 'ioc_type in match event must be url');
});

test('direct domain IOC match: hit.observable_type is domain', () => {
  const map = makeMap([
    ['domain\tevil.com', makeHit({ observable: 'evil.com', observable_type: 'domain' })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'evil.com' }, map);
  assert.ok(hit);
  assert.equal(hit._matchScope, undefined);
  assert.equal(hit.observable_type, 'domain', 'domain IOC preserves domain type');
});

// -- MATCH_SCOPE_HOST_ROOT_URL constant ------------------------------------------

test('MATCH_SCOPE_HOST_ROOT_URL constant equals the string stored in match events', () => {
  assert.equal(MATCH_SCOPE_HOST_ROOT_URL, 'host_root_url',
    'constant must equal the DB-stored value used in match_context.match_scope');
});

// -- Dedup key regression: host_root_url match must carry URL IOC identity --------

test('dedup regression: matched_ioc is URL form (not domain) for host_root_url match', () => {
  const iocUrl = 'https://ultimatebodyrecovery.com/';
  const map = makeMap([
    [`url\t${iocUrl}`, makeHit({ observable: iocUrl, observable_type: 'url', confidence: 90 })]
  ]);
  const hit = matchObsToLookup({ type: 'domain', value: 'ultimatebodyrecovery.com' }, map);
  assert.ok(hit, 'must match');
  assert.equal(hit._matchScope, MATCH_SCOPE_HOST_ROOT_URL);
  // Caller (rowToMatchEvents) derives matched_ioc from hit.observable when _matchScope=host_root_url.
  // This value becomes part of the dedup_key → must be the URL IOC, not the observed domain.
  assert.equal(hit.observable, iocUrl, 'dedup key must use URL IOC identity, not observed domain');
  assert.equal(hit.observable_type, 'url');
});
