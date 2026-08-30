import test from 'node:test';
import assert from 'node:assert/strict';
import {
  abuseScoreRiskLabel,
  abuseScoreRiskLabelDisplay,
  normalizeAbuseIpdbResponse,
  abuseIpdbHttpError
} from './abuseipdbEnrichment.js';

test('abuseScoreRiskLabel mapping', () => {
  assert.equal(abuseScoreRiskLabel(0), 'clean');
  assert.equal(abuseScoreRiskLabel(24), 'low');
  assert.equal(abuseScoreRiskLabel(25), 'suspicious');
  assert.equal(abuseScoreRiskLabel(74), 'suspicious');
  assert.equal(abuseScoreRiskLabel(75), 'high');
  assert.equal(abuseScoreRiskLabel(100), 'high');
  assert.equal(abuseScoreRiskLabelDisplay('clean'), 'Clean / No reports');
});

test('normalizeAbuseIpdbResponse extracts curated fields', () => {
  const raw = {
    data: {
      ipAddress: '1.2.3.4',
      isPublic: true,
      ipVersion: 4,
      abuseConfidenceScore: 42,
      countryCode: 'US',
      usageType: 'Hosting',
      isp: 'Example ISP',
      domain: 'example.com',
      hostnames: ['a.example.com'],
      totalReports: 5,
      numDistinctUsers: 2,
      lastReportedAt: '2024-01-01T00:00:00Z'
    }
  };
  const out = normalizeAbuseIpdbResponse(raw, { ip: '1.2.3.4', maxAgeInDays: 90, verbose: false });
  assert.equal(out.ipAddress, '1.2.3.4');
  assert.equal(out.abuseConfidenceScore, 42);
  assert.equal(out.risk_label, 'suspicious');
  assert.equal(out.countryCode, 'US');
  assert.equal(out.totalReports, 5);
  assert.equal(out.provider_status, 'success');
  assert.equal(out.recent_reports_summary, null);
});

test('normalizeAbuseIpdbResponse includes verbose report summary', () => {
  const raw = {
    data: {
      ipAddress: '1.2.3.4',
      abuseConfidenceScore: 10,
      reports: [{ reportedAt: '2024-01-01', comment: 'bad', categories: [18] }]
    }
  };
  const out = normalizeAbuseIpdbResponse(raw, { ip: '1.2.3.4', maxAgeInDays: 30, verbose: true });
  assert.ok(Array.isArray(out.recent_reports_summary));
  assert.equal(out.recent_reports_summary.length, 1);
});

test('abuseIpdbHttpError normalizes auth, rate limit, and 5xx', () => {
  assert.equal(abuseIpdbHttpError(401).code, 'auth');
  assert.equal(abuseIpdbHttpError(403).provider_status, 'auth_error');
  assert.equal(abuseIpdbHttpError(429).code, 'rate_limit');
  assert.equal(abuseIpdbHttpError(503).provider_status, 'provider_error');
});
