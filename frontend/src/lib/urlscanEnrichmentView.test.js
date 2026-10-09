import test from 'node:test';
import assert from 'node:assert/strict';
import { computeProviderCoverage, providerStateLabel } from './intelligenceSummary.js';
import { isProviderApplicable } from './iocProviderApplicability.js';
import { PROVIDER_META, PROVIDER_ORDER } from '../components/enrichmentProviders/providerMeta.js';

test('urlscan provider meta and order are registered', () => {
  assert.equal(PROVIDER_META.urlscan.name, 'urlscan.io');
  assert.ok(PROVIDER_ORDER.includes('urlscan'));
  assert.match(PROVIDER_META.urlscan.longDescription, /never submits/i);
});

test('urlscan no_results coverage is not_found, never clean/available-as-safe', () => {
  const coverage = computeProviderCoverage(
    { urlscan: { status: 'no_results', assessment: 'no_results', found: false } },
    { iocType: 'url' }
  );
  const row = coverage.find((p) => p.key === 'urlscan');
  assert.ok(row);
  assert.equal(row.state, 'not_found');
  assert.equal(providerStateLabel(row.state), 'Not found');
  assert.doesNotMatch(providerStateLabel(row.state), /clean|safe|benign/i);
});

test('urlscan malicious evidence maps to available without implying IOC verdict', () => {
  const coverage = computeProviderCoverage(
    { urlscan: { status: 'success', assessment: 'malicious_evidence', hasResult: true } },
    { iocType: 'domain' }
  );
  const row = coverage.find((p) => p.key === 'urlscan');
  assert.equal(row.state, 'available');
});

test('urlscan rate_limited maps to error state', () => {
  const coverage = computeProviderCoverage(
    { urlscan: { status: 'rate_limited' } },
    { iocType: 'ip' }
  );
  assert.equal(coverage.find((p) => p.key === 'urlscan').state, 'error');
});

test('urlscan applicability matrix', () => {
  assert.equal(isProviderApplicable('urlscan', 'url'), true);
  assert.equal(isProviderApplicable('urlscan', 'domain'), true);
  assert.equal(isProviderApplicable('urlscan', 'ip'), true);
  assert.equal(isProviderApplicable('urlscan', 'sha256'), false);
  assert.equal(isProviderApplicable('urlscan', 'email'), false);
});
