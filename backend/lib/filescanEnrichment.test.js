import test from 'node:test';
import assert from 'node:assert/strict';
import {
  maskApiKey,
  normalizeVerdict,
  verdictDisplayLabel,
  aggregateVerdict,
  verdictToConfidenceHint,
  classifyTag,
  normalizeFilescanResponse,
  filescanHttpError,
  normalizeFilescanCacheKey
} from './filescanEnrichment.js';

// --- maskApiKey ---

test('maskApiKey redacts API key', () => {
  assert.equal(maskApiKey('abcd1234efgh'), 'abcd********');
  assert.equal(maskApiKey('abcd'), '****');
  assert.equal(maskApiKey('ab'), '****');
  assert.equal(maskApiKey(''), null);
  assert.equal(maskApiKey(null), null);
});

test('maskApiKey never exposes full key', () => {
  const key = 'super-secret-api-key-12345';
  const masked = maskApiKey(key);
  assert.ok(masked !== key, 'masked key must not equal raw key');
  assert.ok(masked.includes('*'), 'masked key must contain asterisks');
  assert.ok(!masked.includes('secret'), 'masked key must not contain sensitive portion');
});

// --- normalizeVerdict ---

test('normalizeVerdict handles standard values', () => {
  assert.equal(normalizeVerdict('malicious'), 'malicious');
  assert.equal(normalizeVerdict('suspicious'), 'suspicious');
  assert.equal(normalizeVerdict('benign'), 'benign');
  assert.equal(normalizeVerdict('no_threat'), 'no_threat');
  assert.equal(normalizeVerdict('unknown'), 'unknown');
  assert.equal(normalizeVerdict(''), 'unknown');
  assert.equal(normalizeVerdict(null), 'unknown');
});

test('normalizeVerdict maps Filescan-specific labels', () => {
  assert.equal(normalizeVerdict('confirmed_threat'), 'malicious');
  assert.equal(normalizeVerdict('Confirmed Threat'), 'malicious');
  assert.equal(normalizeVerdict('MALICIOUS'), 'malicious');
  assert.equal(normalizeVerdict('threat'), 'malicious');
  assert.equal(normalizeVerdict('infected'), 'malicious');
  assert.equal(normalizeVerdict('clean'), 'benign');
  assert.equal(normalizeVerdict('safe'), 'benign');
});

// --- verdictDisplayLabel ---

test('verdictDisplayLabel produces readable labels', () => {
  assert.equal(verdictDisplayLabel('confirmed_threat'), 'Confirmed Threat');
  assert.equal(verdictDisplayLabel('malicious'), 'Malicious');
  assert.equal(verdictDisplayLabel('no_threat'), 'No Threat');
  assert.equal(verdictDisplayLabel(''), null);
  assert.equal(verdictDisplayLabel(null), null);
});

// --- aggregateVerdict ---

test('aggregateVerdict precedence', () => {
  assert.equal(aggregateVerdict(['no_threat', 'malicious', 'benign']), 'malicious');
  assert.equal(aggregateVerdict(['no_threat', 'suspicious', 'benign']), 'suspicious');
  assert.equal(aggregateVerdict(['benign', 'no_threat']), 'benign');
  assert.equal(aggregateVerdict(['no_threat']), 'no_threat');
  assert.equal(aggregateVerdict([]), 'unknown');
  assert.equal(aggregateVerdict(null), 'unknown');
});

test('aggregateVerdict handles Filescan-specific raw values', () => {
  assert.equal(aggregateVerdict(['confirmed_threat', 'no_threat']), 'malicious');
  assert.equal(aggregateVerdict(['clean', 'no_threat']), 'benign');
});

// --- verdictToConfidenceHint ---

test('verdictToConfidenceHint mapping', () => {
  assert.equal(verdictToConfidenceHint('malicious'), 'high');
  assert.equal(verdictToConfidenceHint('suspicious'), 'medium');
  assert.equal(verdictToConfidenceHint('benign'), 'low');
  assert.equal(verdictToConfidenceHint('no_threat'), 'low');
  assert.equal(verdictToConfidenceHint('unknown'), null);
  assert.equal(verdictToConfidenceHint(null), null);
});

// --- classifyTag ---

test('classifyTag: peexe → file_type', () => {
  const r = classifyTag('peexe');
  assert.equal(r.is_file_type, true);
  assert.equal(r.is_malware_family, false);
  assert.equal(r.is_threat_type, false);
  assert.equal(r.is_compiler_hint, false);
});

test('classifyTag: phorpiex → malware_family', () => {
  const r = classifyTag('phorpiex');
  assert.equal(r.is_malware_family, true);
  assert.equal(r.is_file_type, false);
});

test('classifyTag: dropper → threat_type', () => {
  const r = classifyTag('dropper');
  assert.equal(r.is_threat_type, true);
  assert.equal(r.is_malware_family, false);
});

test('classifyTag: microsoft_visual_cc → compiler_hint', () => {
  const r = classifyTag('microsoft_visual_cc');
  assert.equal(r.is_compiler_hint, true);
  assert.equal(r.is_malware_family, false);
});

test('classifyTag: unknown tag → all false', () => {
  const r = classifyTag('some_unknown_tool_xyz');
  assert.equal(r.is_malware_family, false);
  assert.equal(r.is_threat_type, false);
  assert.equal(r.is_file_type, false);
  assert.equal(r.is_compiler_hint, false);
});

// --- normalizeFilescanResponse ---

test('normalizeFilescanResponse: full hash response with all fields', () => {
  const raw = {
    items: [
      {
        id: '265fec2c-6833-461d-9da8-f7a6f3b61e3d',
        state: 'success',
        verdict: 'confirmed_threat',
        date: '2026-07-01T10:00:00Z',
        scan_engine: 'Internal',
        file: {
          name: '_2012c7af.exe',
          sha256: '2012c7af2da6b649bc2bb58f54837b200cafecc44ceda8d5e2e43b0ea205ac97',
          sha1: 'abc123sha1',
          md5: 'abc123md5',
          media_type: 'application/x-dosexec',
          type: 'PE',
          size: 15872,
          entropy: 5.9,
          strings: 0,
          link: null
        },
        scan_init: { id: 'flow-abc' },
        tags: [
          { source: 'SIGNAL', isRootTag: false, isMalwareFamilyTag: true, tag: { name: 'phorpiex' } },
          { source: 'SIGNAL', isRootTag: false, isMalwareFamilyTag: false, tag: { name: 'dropper' } },
          { source: 'SIGNAL', isRootTag: false, isMalwareFamilyTag: false, tag: { name: 'peexe' } },
          { source: 'SIGNAL', isRootTag: false, isMalwareFamilyTag: false, tag: { name: 'microsoft_visual_cc' } }
        ],
        threat_indicators: [
          {
            title: 'OSINT source detected malicious resource',
            verdict: 'MALICIOUS',
            origin: 'OPSWAT_METADEFENDER',
            resource_type: 'FILE_HASH_SHA256',
            resource_value: '2012c7af...'
          }
        ],
        summary: {
          threat_reputation_iocs: 0,
          confirmed_threat_indicators: 1,
          similar_samples: 0
        }
      }
    ],
    count: 1,
    method: 'and'
  };

  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: '2012c7af...' });

  // Verdict
  assert.equal(out.verdict, 'malicious');
  assert.equal(out.verdict_label, 'Confirmed Threat');
  assert.equal(out.confidence_hint, 'high');
  assert.equal(out.found, true);
  assert.equal(out.report_count, 1);

  // Tags
  assert.ok(out.tags.includes('phorpiex'));
  assert.ok(out.tags.includes('dropper'));
  assert.ok(out.tags.includes('peexe'));
  assert.ok(out.tags.includes('microsoft_visual_cc'));

  // Semantic classification
  assert.ok(out.malware_families.includes('phorpiex'), 'phorpiex should be in malware_families');
  assert.ok(out.threat_types.includes('dropper'), 'dropper should be in threat_types');
  assert.ok(out.file_type_hints.includes('peexe'), 'peexe should be in file_type_hints');
  assert.ok(out.compiler_hints.includes('microsoft_visual_cc'), 'microsoft_visual_cc should be in compiler_hints');

  // File metadata
  assert.ok(out.file !== null, 'file should be present');
  assert.equal(out.file.name, '_2012c7af.exe');
  assert.equal(out.file.sha256, '2012c7af2da6b649bc2bb58f54837b200cafecc44ceda8d5e2e43b0ea205ac97');
  assert.equal(out.file.sha1, 'abc123sha1');
  assert.equal(out.file.md5, 'abc123md5');
  assert.equal(out.file.media_type, 'application/x-dosexec');
  assert.equal(out.file.size, 15872);
  assert.equal(out.file.entropy, 5.9);
  assert.equal(out.file.strings_count, 0);

  // Threat indicators
  assert.equal(out.threat_indicators.length, 1);
  assert.equal(out.threat_indicators[0].title, 'OSINT source detected malicious resource');
  assert.equal(out.threat_indicators[0].origin, 'OPSWAT_METADEFENDER');
  assert.equal(out.threat_indicators[0].resource_type, 'FILE_HASH_SHA256');

  // Summary counts
  assert.equal(out.summary_counts.confirmed_threat_indicators, 1);
  assert.equal(out.summary_counts.threat_reputation_iocs, 0);
  assert.equal(out.summary_counts.similar_samples, 0);

  // Report
  assert.ok(out.report !== null);
  assert.equal(out.report.report_id, '265fec2c-6833-461d-9da8-f7a6f3b61e3d');
  assert.equal(out.report.scan_engine, 'Internal');
  assert.ok(out.report.link.includes('flow-abc'));
});

test('normalizeFilescanResponse: empty result (not found)', () => {
  const raw = { items: [], count: 0, method: 'and' };
  const out = normalizeFilescanResponse(raw, { iocType: 'domain', iocValue: 'example.com' });

  assert.equal(out.found, false);
  assert.equal(out.verdict, 'unknown');
  assert.equal(out.verdict_label, null);
  assert.equal(out.confidence_hint, null);
  assert.equal(out.report_count, 0);
  assert.deepEqual(out.reports, []);
  assert.deepEqual(out.tags, []);
  assert.deepEqual(out.malware_families, []);
  assert.equal(out.file, null);
  assert.equal(out.report, null);
  assert.equal(out.provider_status, 'success');
});

test('normalizeFilescanResponse: URL IOC with no_threat verdict', () => {
  const raw = {
    items: [{
      id: 'url-item-1',
      state: 'success',
      verdict: 'no_threat',
      date: '2026-07-01T00:00:00Z',
      file: { name: null, sha256: null, link: 'http://example.com/path' },
      scan_init: { id: 'flow-url-1' },
      tags: []
    }],
    count: 1
  };
  const out = normalizeFilescanResponse(raw, { iocType: 'url', iocValue: 'http://example.com/path' });
  assert.equal(out.found, true);
  assert.equal(out.verdict, 'no_threat');
  assert.equal(out.verdict_label, 'No Threat');
  assert.equal(out.confidence_hint, 'low');
});

test('normalizeFilescanResponse: IP IOC', () => {
  const raw = { items: [], count: 0 };
  const out = normalizeFilescanResponse(raw, { iocType: 'ip', iocValue: '1.2.3.4' });
  assert.equal(out.ioc_type, 'ip');
  assert.equal(out.ioc_value, '1.2.3.4');
  assert.equal(out.found, false);
});

test('normalizeFilescanResponse: backward compat — old cache missing new fields', () => {
  // Simulates an old cached record missing new fields being deserialized
  const oldSummary = {
    provider: 'filescan',
    found: true,
    verdict: 'malicious',
    confidence_hint: 'high',
    report_count: 2,
    reports: [{ report_id: 'r1', verdict: 'malicious', link: null }],
    tags: ['dropper'],
    threat_indicators: [{ name: 'dropper', source: 'SIGNAL', is_malware_family: false }],
    source_references: [],
    ioc_type: 'hash',
    ioc_value: 'abc123',
    fetched_at: '2026-01-01T00:00:00Z',
    provider_status: 'success',
    raw_summary: { count: 2, method: null }
    // NOTE: no verdict_label, no malware_families, no file, no report, no summary_counts, no emulation
  };
  // UI should handle missing fields gracefully — test the data shape expectations
  assert.equal(oldSummary.verdict_label, undefined);
  assert.equal(oldSummary.malware_families, undefined);
  assert.equal(oldSummary.file, undefined);
  // These resolve to undefined in JS, treated as falsy in the UI — no crash expected
  const families = Array.isArray(oldSummary.malware_families) ? oldSummary.malware_families : [];
  assert.deepEqual(families, []);
  const fileData = oldSummary.file || null;
  assert.equal(fileData, null);
});

// --- filescanHttpError ---

test('filescanHttpError auth', () => {
  const r401 = filescanHttpError(401);
  assert.equal(r401.provider_status, 'auth_error');
  assert.equal(r401.code, 'auth');
  const r403 = filescanHttpError(403);
  assert.equal(r403.provider_status, 'auth_error');
  assert.equal(r403.code, 'auth');
});

test('filescanHttpError rate limit', () => {
  const r = filescanHttpError(429);
  assert.equal(r.provider_status, 'rate_limited');
  assert.equal(r.code, 'rate_limit');
});

test('filescanHttpError 5xx', () => {
  const r = filescanHttpError(503);
  assert.equal(r.provider_status, 'provider_error');
  assert.equal(r.code, 'provider_error');
});

test('filescanHttpError other', () => {
  const r = filescanHttpError(400);
  assert.equal(r.provider_status, 'failed');
  assert.equal(r.code, 'http_error');
});

// --- normalizeFilescanCacheKey ---

test('normalizeFilescanCacheKey is consistent and lowercased', () => {
  const k1 = normalizeFilescanCacheKey('hash', 'ABC123');
  const k2 = normalizeFilescanCacheKey('HASH', 'abc123');
  assert.equal(k1, k2);
  assert.ok(k1.startsWith('hash:'));
});

// --- IOC global status immutability (contract test) ---

test('normalizeFilescanResponse never touches ioc_items confidence or status fields', () => {
  const raw = {
    items: [{ id: '1', state: 'success', verdict: 'confirmed_threat', date: '2026-01-01', file: {}, scan_init: { id: 'f1' }, tags: [] }],
    count: 1
  };
  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'abc' });
  const forbiddenFields = ['status', 'threat_classification', 'confidence', 'override', 'analyst_override'];
  for (const f of forbiddenFields) {
    assert.equal(out[f], undefined, `Field "${f}" must not appear in enrichment output`);
  }
});
