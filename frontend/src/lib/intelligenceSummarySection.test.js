import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import * as intelligenceSummary from './intelligenceSummary.js';
import {
  computeAnalystRefsSummary,
  computeLayeredProviderCoverage
} from './intelligenceSummary.js';
import { getDerivedInfrastructureContext } from './iocProviderApplicability.js';

const intelligenceTabSrc = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '../intelligenceTab.jsx'),
  'utf8'
);

test('overall signal, reputation, and infrastructure summary helpers are removed', () => {
  assert.equal(typeof intelligenceSummary.computeOverallSignal, 'undefined');
  assert.equal(typeof intelligenceSummary.computeReputationSummary, 'undefined');
  assert.equal(typeof intelligenceSummary.signalToneStyle, 'undefined');
  assert.equal(typeof intelligenceSummary.computeInfrastructureSummary, 'undefined');
});

test('Intelligence Summary UI no longer renders Overall signal or Reputation cards', () => {
  assert.match(intelligenceTabSrc, /Intelligence Summary/);
  assert.match(intelligenceTabSrc, /Provider coverage/);
  assert.match(intelligenceTabSrc, /Analyst refs/);
  assert.doesNotMatch(intelligenceTabSrc, /Overall signal/);
  assert.doesNotMatch(intelligenceTabSrc, /computeOverallSignal/);
  assert.doesNotMatch(intelligenceTabSrc, /computeReputationSummary/);
  assert.doesNotMatch(intelligenceTabSrc, /signalToneStyle/);
  assert.doesNotMatch(intelligenceTabSrc, /Malicious signal/);
  assert.doesNotMatch(intelligenceTabSrc, /Clean \/ No reports/);
  assert.doesNotMatch(intelligenceTabSrc, /No reputation data/);
  // Reputation card title (not incidental "reputation" copy elsewhere in the file)
  assert.doesNotMatch(intelligenceTabSrc, />Reputation</);
  assert.doesNotMatch(intelligenceTabSrc, /['"]Reputation['"]/);
});

test('Intelligence Summary layout prefers wide coverage + narrow refs without leftover grid spans', () => {
  assert.match(intelligenceTabSrc, /summaryCoverageCardStyle/);
  assert.match(intelligenceTabSrc, /summaryRefsCardStyle/);
  assert.match(intelligenceTabSrc, /flex:\s*['"]2 1 280px['"]/);
  assert.match(intelligenceTabSrc, /flex:\s*['"]1 1 140px['"]/);
  assert.match(intelligenceTabSrc, /flexWrap:\s*['"]wrap['"]/);
  assert.doesNotMatch(intelligenceTabSrc, /gridColumn:\s*hasDerivedCoverage/);
});

test('Provider coverage + Analyst refs helpers still produce summary content', () => {
  const iocValue = 'http://203.0.113.10/path';
  const derivedContext = getDerivedInfrastructureContext(iocValue, 'url', { rdapEligible: false });
  const layered = computeLayeredProviderCoverage({
    directSnapshots: {
      virustotal: { status: 'success' }
    },
    derivedSnapshots: {
      ipinfo: { status: 'success' },
      abuseipdb: { status: 'success', score: 10 },
      spamhaus_drop: { status: 'not_listed' }
    },
    iocType: 'url',
    derivedContext
  });

  assert.ok(layered.derived?.length);
  assert.equal(layered.derivedHost, '203.0.113.10');
  assert.equal(layered.direct.find((p) => p.key === 'virustotal')?.state, 'available');
  assert.equal(layered.derived.find((p) => p.key === 'ipinfo')?.state, 'available');
  assert.equal(layered.derived.find((p) => p.key === 'abuseipdb')?.state, 'available');
  assert.equal(layered.derived.find((p) => p.key === 'spamhaus_drop')?.state, 'available');
  assert.equal(
    computeAnalystRefsSummary({ total_count: 2, supports_malicious_count: 1 }),
    '2 refs / 1 supports malicious'
  );
});

test('URL hostname that is a bare IP still yields derived coverage context', () => {
  const derivedContext = getDerivedInfrastructureContext('https://198.51.100.7/login', 'url');
  assert.ok(derivedContext);
  assert.equal(derivedContext.host, '198.51.100.7');
  assert.equal(derivedContext.hostKind, 'ip');
  assert.deepEqual(derivedContext.providers, ['ipinfo', 'abuseipdb', 'spamhaus_drop']);
});

test('domain IOC without derived IP keeps direct-only coverage layout', () => {
  const derivedContext = getDerivedInfrastructureContext('example.com', 'domain', { rdapEligible: true });
  assert.equal(derivedContext, null);

  const layered = computeLayeredProviderCoverage({
    directSnapshots: {
      virustotal: { status: 'success' }
    },
    derivedSnapshots: {},
    iocType: 'domain',
    rdapEligible: true,
    derivedContext: null
  });

  assert.ok(layered.direct.length);
  assert.equal(layered.derived, null);
  assert.equal(layered.derivedHost, null);
});
