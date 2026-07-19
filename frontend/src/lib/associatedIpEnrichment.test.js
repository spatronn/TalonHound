import test from 'node:test';
import assert from 'node:assert/strict';
import {
  compactAssociatedIpViewModel,
  indexAssociatedIpResults,
  isAssociatedIpEnrichmentCandidate
} from './associatedIpEnrichment.js';

test('indexes cached bulk results by canonical IP', () => {
  const indexed = indexAssociatedIpResults([
    { requested_ip: '8.8.8.8', normalized_ip: '8.8.8.8', state: 'cached' },
    { requested_ip: '2606:4700:4700::1111', state: 'not_found' }
  ]);
  assert.equal(indexed['8.8.8.8'].state, 'cached');
  assert.equal(indexed['2606:4700:4700::1111'].state, 'not_found');
});

test('compact view model exposes only verified ownership and location fields', () => {
  const view = compactAssociatedIpViewModel({
    state: 'cached',
    data: {
      enriched: true,
      provider_status: 'success',
      normalized_ip: '23.238.36.235',
      as_name: 'HostPapa',
      asn: 'AS36352',
      as_domain: 'colocrossing.com',
      country: 'United States',
      country_code: 'US',
      continent: 'North America',
      continent_code: 'NA',
      last_enriched_at: '2026-07-19T13:45:25.000Z'
    }
  });

  assert.deepEqual(Object.keys(view), [
    'state', 'hasData', 'ip', 'asName', 'asn', 'asDomain',
    'location', 'provider', 'lastChecked', 'error'
  ]);
  assert.equal(view.location, 'United States · North America');
  assert.equal(view.provider, 'IPinfo Lite');
  assert.equal(JSON.stringify(view).includes('country_code'), false);
  assert.equal(JSON.stringify(view).includes('Clean'), false);
  assert.equal(JSON.stringify(view).includes('CDN'), false);
});

test('loading, empty, error, cached and enriched states remain distinct', () => {
  assert.equal(compactAssociatedIpViewModel(null, '1.1.1.1').state, 'not_found');
  assert.equal(compactAssociatedIpViewModel({ state: 'provider_error' }).state, 'provider_error');
  assert.equal(compactAssociatedIpViewModel({ state: 'cached', data: { provider_status: 'success' } }).hasData, true);
  assert.equal(compactAssociatedIpViewModel({ state: 'enriched', data: { enriched: true } }).hasData, true);
  assert.equal(isAssociatedIpEnrichmentCandidate({ state: 'not_found' }), true);
  assert.equal(isAssociatedIpEnrichmentCandidate({ state: 'cached' }), false);
});
