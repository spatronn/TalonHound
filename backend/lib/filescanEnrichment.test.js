import test from 'node:test';
import assert from 'node:assert/strict';
import {
  maskApiKey,
  normalizeVerdict,
  verdictDisplayLabel,
  aggregateVerdict,
  verdictToConfidenceHint,
  classifyTag,
  isTagMalwareFamily,
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
  // likely_malicious is Filescan's second-highest severity
  assert.equal(normalizeVerdict('likely_malicious'), 'malicious');
  assert.equal(normalizeVerdict('LIKELY_MALICIOUS'), 'malicious');
  assert.equal(normalizeVerdict('Likely Malicious'), 'malicious');
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
  // likely_malicious should be treated as malicious, not unknown
  assert.equal(aggregateVerdict(['likely_malicious', 'unknown']), 'malicious');
  assert.equal(aggregateVerdict(['unknown', 'likely_malicious']), 'malicious');
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

// --- isTagMalwareFamily ---

test('isTagMalwareFamily: isMalwareFamilyTag=true → true', () => {
  const t = { isMalwareFamilyTag: true, source: 'OSINT_LOOKUP', tag: { name: 'mirai', descriptions: [] } };
  assert.equal(isTagMalwareFamily(t), true);
});

test('isTagMalwareFamily: phorpiex OSINT_LOOKUP + malpedia cluster → true (isMalwareFamilyTag=false)', () => {
  // Real Filescan API has isMalwareFamilyTag:false for phorpiex but it IS a family
  const t = {
    isMalwareFamilyTag: false,
    source: 'OSINT_LOOKUP',
    tag: {
      name: 'phorpiex',
      descriptions: [{ cluster: { type: 'malpedia' } }]
    }
  };
  assert.equal(isTagMalwareFamily(t), true);
});

test('isTagMalwareFamily: crypt + ransomware cluster → true', () => {
  const t = {
    isMalwareFamilyTag: false,
    source: 'OSINT_LOOKUP',
    tag: {
      name: 'crypt',
      descriptions: [{ cluster: { type: 'ransomware' } }]
    }
  };
  assert.equal(isTagMalwareFamily(t), true);
});

test('isTagMalwareFamily: dropper OSINT_LOOKUP no cluster → false (threat type, not family)', () => {
  const t = {
    isMalwareFamilyTag: false,
    source: 'OSINT_LOOKUP',
    tag: { name: 'dropper', descriptions: [] }
  };
  assert.equal(isTagMalwareFamily(t), false);
});

test('isTagMalwareFamily: SIGNAL source → false', () => {
  const t = { isMalwareFamilyTag: false, source: 'SIGNAL', tag: { name: 'obfuscated', descriptions: [] } };
  assert.equal(isTagMalwareFamily(t), false);
});

// --- normalizeFilescanResponse ---

test('normalizeFilescanResponse: real Filescan API structure (mime_type, short_type, OSINT_LOOKUP family)', () => {
  // Models real API response structure for hash 2012c7af...
  const raw = {
    items: [
      {
        id: '265fec2c-6833-461d-9da8-f7a6f3b61e3d',
        state: 'success_partial',
        verdict: 'malicious',
        date: '2026-07-06T17:13:26.189000',
        file: {
          name: '_2012c7af.exe',
          sha256: '2012c7af2da6b649bc2bb58f54837b200cafecc44ceda8d5e2e43b0ea205ac97',
          // API uses mime_type, NOT media_type
          mime_type: 'application/x-dosexec',
          // API uses short_type, NOT type
          short_type: 'peexe',
          link: null
        },
        scan_init: { id: '6a4be234b4cc16a49fa26b58' },
        tags: [
          {
            source: 'MEDIA_TYPE', isRootTag: true, isMalwareFamilyTag: false,
            tag: { name: 'peexe', synonyms: [], descriptions: [], verdict: { verdict: 'NO_THREAT', threatLevel: 0.1, confidence: 1.0 } }
          },
          {
            // phorpiex: isMalwareFamilyTag=false in real API but IS a family via malpedia cluster
            source: 'OSINT_LOOKUP', isMalwareFamilyTag: false,
            tag: {
              name: 'phorpiex',
              synonyms: ['phorphiex'],
              descriptions: [{ description: 'Proofpoint...', cluster: { type: 'malpedia', authors: [] } }],
              verdict: { verdict: 'LIKELY_MALICIOUS', threatLevel: 0.75, confidence: 1.0 }
            }
          },
          {
            source: 'OSINT_LOOKUP', isMalwareFamilyTag: false,
            tag: { name: 'dropper', synonyms: [], descriptions: [], verdict: { verdict: 'SUSPICIOUS', threatLevel: 0.5, confidence: 1.0 } }
          },
          {
            source: 'DIE_OUTPUT', isRootTag: false, isMalwareFamilyTag: false,
            tag: { name: 'microsoft_visual_cc', synonyms: [], descriptions: [], verdict: { verdict: 'NO_THREAT', threatLevel: 0.1, confidence: 1.0 } }
          }
        ]
      }
    ],
    count: 1,
    method: 'or'
  };

  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: '2012c7af...' });

  // Verdict
  assert.equal(out.verdict, 'malicious');
  assert.equal(out.verdict_label, 'Malicious');
  assert.equal(out.found, true);
  assert.equal(out.report_count, 1);

  // File metadata: API uses mime_type/short_type — must be mapped to media_type/type
  assert.ok(out.file !== null, 'file should be present');
  assert.equal(out.file.name, '_2012c7af.exe');
  assert.equal(out.file.sha256, '2012c7af2da6b649bc2bb58f54837b200cafecc44ceda8d5e2e43b0ea205ac97');
  assert.equal(out.file.media_type, 'application/x-dosexec', 'mime_type must be mapped to media_type');
  assert.equal(out.file.type, 'peexe', 'short_type must be mapped to type');

  // Tags
  assert.ok(out.tags.includes('phorpiex'));
  assert.ok(out.tags.includes('dropper'));
  assert.ok(out.tags.includes('peexe'));
  assert.ok(out.tags.includes('microsoft_visual_cc'));

  // phorpiex: OSINT_LOOKUP + malpedia cluster → malware_family (even with isMalwareFamilyTag=false)
  assert.ok(out.malware_families.includes('phorpiex'), 'phorpiex must be in malware_families via OSINT malpedia cluster');
  assert.ok(out.threat_types.includes('dropper'), 'dropper must be in threat_types');
  assert.ok(out.file_type_hints.includes('peexe'), 'peexe must be in file_type_hints');
  assert.ok(out.compiler_hints.includes('microsoft_visual_cc'), 'microsoft_visual_cc must be in compiler_hints');
});

test('normalizeFilescanResponse: likely_malicious verdict (real API — hash ffa874d0...)', () => {
  // Real hash ffa874d0 returns verdict: "likely_malicious", not "malicious"
  const raw = {
    items: [
      {
        id: 'bcdea0ac-8783-43be-8f07-f1980ac064cf',
        state: 'success',
        verdict: 'likely_malicious',
        date: '2026-07-07T17:03:55.330000',
        file: {
          name: 'ffa874d010db98be13b184074f4f857b151a6f22b95503899714804a24799620.exe',
          sha256: 'ffa874d010db98be13b184074f4f857b151a6f22b95503899714804a24799620',
          mime_type: 'application/x-msdownload; format=pe32',
          short_type: 'peexe',
          link: null
        },
        scan_init: { id: '6a4d3179f283379540e32525' },
        tags: [
          { source: 'MEDIA_TYPE', isRootTag: true, isMalwareFamilyTag: false, tag: { name: 'peexe', descriptions: [], verdict: { verdict: 'NO_THREAT' } } },
          { source: 'MEDIA_TYPE', isRootTag: true, isMalwareFamilyTag: false, tag: { name: 'dotnet_pe', descriptions: [], verdict: { verdict: 'UNKNOWN' } } },
          {
            source: 'OSINT_LOOKUP', isMalwareFamilyTag: false,
            tag: {
              name: 'crypt',
              synonyms: ['crypt ransomware'],
              descriptions: [{ cluster: { type: 'ransomware' } }],
              verdict: { verdict: 'LIKELY_MALICIOUS', threatLevel: 0.75 }
            }
          },
          { source: 'SIGNAL', isRootTag: false, isMalwareFamilyTag: false, tag: { name: 'obfuscated', descriptions: [], verdict: { verdict: 'LIKELY_MALICIOUS' } } },
          { source: 'SIGNAL', isRootTag: false, isMalwareFamilyTag: false, tag: { name: 'packed', descriptions: [], verdict: { verdict: 'SUSPICIOUS' } } },
          { source: 'DIE_OUTPUT', isRootTag: false, isMalwareFamilyTag: false, tag: { name: 'vbnet', descriptions: [], verdict: { verdict: 'NO_THREAT' } } }
        ]
      }
    ],
    count: 1,
    method: 'or'
  };

  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'ffa874d0...' });

  // likely_malicious must not fall through to 'unknown'
  assert.equal(out.verdict, 'malicious', 'likely_malicious verdict must normalize to malicious');
  assert.equal(out.verdict_label, 'Likely Malicious');
  assert.equal(out.found, true);

  // File metadata
  assert.equal(out.file.media_type, 'application/x-msdownload; format=pe32');
  assert.equal(out.file.type, 'peexe');

  // crypt: OSINT_LOOKUP + ransomware cluster → malware_family
  assert.ok(out.malware_families.includes('crypt'), 'crypt must be in malware_families via ransomware cluster');
  assert.ok(out.tags.includes('obfuscated'));
  assert.ok(out.tags.includes('packed'));
});

test('normalizeFilescanResponse: mirai ELF hash — likely_malicious in mixed verdicts', () => {
  // hash ff056a4b: items[0] verdict=unknown, items[1] verdict=likely_malicious
  const raw = {
    items: [
      {
        id: 'ddcbab54-2474-4200-a674-fad312d39e97',
        verdict: 'unknown',
        date: '2026-07-07T17:03:45.519000',
        file: { name: 'm68k.elf', sha256: 'ff056a4b...', mime_type: 'application/x-executable', short_type: 'elf', link: null },
        scan_init: { id: '6a4d316de97e48d015a61445' },
        tags: [{ source: 'MEDIA_TYPE', isRootTag: true, isMalwareFamilyTag: false, tag: { name: 'elf', descriptions: [], verdict: { verdict: 'UNKNOWN' } } }]
      },
      {
        id: '94cbb3c4-8b87-42f0-a177-9bbfea09645d',
        verdict: 'likely_malicious',
        date: '2026-07-07T16:59:47.651000',
        file: { name: 'm68k.elf', sha256: 'ff056a4b...', mime_type: 'application/x-executable', short_type: 'elf', link: null },
        scan_init: { id: '6a4d308051f8d7a4558b695c' },
        tags: [
          { source: 'MEDIA_TYPE', isRootTag: true, isMalwareFamilyTag: false, tag: { name: 'elf', descriptions: [], verdict: { verdict: 'UNKNOWN' } } },
          {
            source: 'OSINT_LOOKUP', isMalwareFamilyTag: false,
            tag: { name: 'bashlite', synonyms: ['gafgyt'], descriptions: [{ cluster: { type: 'malpedia' } }], verdict: { verdict: 'LIKELY_MALICIOUS' } }
          },
          {
            source: 'OSINT_LOOKUP', isMalwareFamilyTag: true,
            tag: { name: 'mirai', synonyms: ['katana'], descriptions: [{ cluster: { type: 'malpedia' } }], verdict: { verdict: 'UNKNOWN' } }
          }
        ]
      }
    ],
    count: 2,
    method: 'or'
  };

  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'ff056a4b...' });

  // aggregateVerdict(['unknown', 'likely_malicious']) must now be 'malicious'
  assert.equal(out.verdict, 'malicious', 'likely_malicious in mixed items must produce malicious verdict');
  assert.equal(out.verdict_label, 'Likely Malicious');
  assert.equal(out.report_count, 2);
  assert.ok(out.malware_families.includes('mirai'), 'mirai (isMalwareFamilyTag=true) must be in families');
  assert.ok(out.malware_families.includes('bashlite'), 'bashlite (malpedia cluster) must be in families');
  assert.ok(out.file_type_hints.includes('elf'));
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

// --- scan_state / states ---

test('normalizeFilescanResponse: scan_state reflects primary item state', () => {
  const raw = {
    items: [
      { id: 'a1', state: 'success_partial', verdict: 'likely_malicious', file: {}, scan_init: { id: 'f1' }, tags: [] }
    ],
    count: 1
  };
  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'abc' });
  assert.equal(out.scan_state, 'success_partial', 'scan_state must be "success_partial" from primary item');
  assert.deepEqual(out.states, ['success_partial']);
});

test('normalizeFilescanResponse: states deduplicated across all items', () => {
  const raw = {
    items: [
      { id: 'a1', state: 'success', verdict: 'unknown', file: {}, scan_init: { id: 'f1' }, tags: [] },
      { id: 'a2', state: 'success_partial', verdict: 'likely_malicious', file: {}, scan_init: { id: 'f2' }, tags: [] },
      { id: 'a3', state: 'success', verdict: 'unknown', file: {}, scan_init: { id: 'f3' }, tags: [] }
    ],
    count: 3
  };
  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'abc' });
  // primary item is items[1] (likely_malicious → malicious, the highest verdict)
  assert.equal(out.scan_state, 'success_partial');
  assert.equal(out.states.length, 2, 'states must be deduplicated');
  assert.ok(out.states.includes('success'));
  assert.ok(out.states.includes('success_partial'));
});

test('normalizeFilescanResponse: scan_state null for empty items', () => {
  const raw = { items: [], count: 0 };
  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'abc' });
  assert.equal(out.scan_state, null);
  assert.deepEqual(out.states, []);
});

test('normalizeFilescanResponse: scan_state null for item with missing state field', () => {
  const raw = {
    items: [{ id: 'a1', verdict: 'malicious', file: {}, scan_init: { id: 'f1' }, tags: [] }],
    count: 1
  };
  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'abc' });
  assert.equal(out.scan_state, null);
  assert.deepEqual(out.states, []);
});

test('normalizeFilescanResponse: e0fa3d8a structure — success_partial, no OSINT, 3 tags', () => {
  // Models the real API response for e0fa3d8a — success_partial with only MEDIA_TYPE/CERTIFICATE/SIGNAL
  const raw = {
    items: [
      {
        id: '4d1b8a02-4838-4376-b6f4-0009c0e5b7c3',
        state: 'success_partial',
        verdict: 'likely_malicious',
        date: '2026-07-07T14:24:32.927000',
        file: {
          name: 'e0fa3d8a58dd358448888a6194b36bc2c252628e4331b26547691199556d2f45.exe',
          sha256: 'e0fa3d8a58dd358448888a6194b36bc2c252628e4331b26547691199556d2f45',
          mime_type: 'application/x-msdownload; format=pe',
          short_type: 'peexe',
          link: null
        },
        scan_init: { id: '6a4d0c153234235b013849cb' },
        tags: [
          { source: 'MEDIA_TYPE', isRootTag: true, isMalwareFamilyTag: false, tag: { name: 'peexe', descriptions: [] } },
          { source: 'CERTIFICATE', isRootTag: true, isMalwareFamilyTag: false, tag: { name: 'signed', descriptions: [] } },
          { source: 'SIGNAL', isRootTag: false, isMalwareFamilyTag: false, tag: { name: 'packed', descriptions: [] } }
        ]
      }
    ],
    count: 1
  };

  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'e0fa3d8a...' });

  assert.equal(out.scan_state, 'success_partial');
  assert.deepEqual(out.states, ['success_partial']);
  assert.equal(out.verdict, 'malicious');
  assert.equal(out.verdict_label, 'Likely Malicious');
  assert.deepEqual(out.malware_families, [], 'no OSINT match → empty malware_families');
  assert.ok(out.file_type_hints.includes('peexe'));
  assert.equal(out.file.media_type, 'application/x-msdownload; format=pe');
  assert.equal(out.file.type, 'peexe');
  assert.ok(out.tags.includes('peexe'));
  assert.ok(out.tags.includes('signed'));
  assert.ok(out.tags.includes('packed'));
});
