import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildUrlhausCanonicalIocHash,
  evaluateUrlhausExportSkip,
  hashUrlhausRawContent,
  parseUrlhausCheckpoint,
  parseUrlhausRecentCsv,
  serializeUrlhausCheckpoint
} from './urlhaus.js';

const SAMPLE_CSV_A = `################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)
# Last updated: 2026-05-27 11:52:06 (UTC)
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3853890","2026-05-27 11:52:06","http://110.36.23.67:57501/bin.sh","online","2026-05-27 11:52:06","malware_download","None","https://urlhaus.abuse.ch/url/3853890/","GAYINT_DOT_ORG"
"3853889","2026-05-27 11:51:06","https://reoen.webgondozas.hu/a44f43f1-dc49-4a45-b725-33106ce13f94","offline","","malware_download","ClearFake","https://urlhaus.abuse.ch/url/3853889/","anonymous"
`;

const SAMPLE_CSV_B = `################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)
# Last updated: 2026-05-27 12:00:00 (UTC)
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3853889","2026-05-27 11:51:06","https://reoen.webgondozas.hu/a44f43f1-dc49-4a45-b725-33106ce13f94","offline","","malware_download","ClearFake","https://urlhaus.abuse.ch/url/3853889/","anonymous"
"3853890","2026-05-27 11:52:06","http://110.36.23.67:57501/bin.sh","online","2026-05-27 11:52:06","malware_download","None","https://urlhaus.abuse.ch/url/3853890/","GAYINT_DOT_ORG"
`;

describe('buildUrlhausCanonicalIocHash', () => {
  it('is stable regardless of CSV row order and header comments', () => {
    const a = parseUrlhausRecentCsv(SAMPLE_CSV_A);
    const b = parseUrlhausRecentCsv(SAMPLE_CSV_B);
    assert.equal(buildUrlhausCanonicalIocHash(a.entries), buildUrlhausCanonicalIocHash(b.entries));
  });

  it('changes when IOC set changes', () => {
    const base = parseUrlhausRecentCsv(SAMPLE_CSV_A).entries;
    const changed = [...base, {
      observable: 'https://new.example.test/x',
      observableType: 'url'
    }];
    assert.notEqual(buildUrlhausCanonicalIocHash(base), buildUrlhausCanonicalIocHash(changed));
  });

  it('deduplicates normalized observables', () => {
    const hash = buildUrlhausCanonicalIocHash([
      { observable: 'https://example.test/a', observableType: 'url' },
      { observable: '  https://example.test/a  ', observableType: 'url' }
    ]);
    const single = buildUrlhausCanonicalIocHash([
      { observable: 'https://example.test/a', observableType: 'url' }
    ]);
    assert.equal(hash, single);
  });
});

describe('hashUrlhausRawContent', () => {
  it('differs when raw bytes differ even if canonical IOC set matches', () => {
    assert.notEqual(hashUrlhausRawContent(SAMPLE_CSV_A), hashUrlhausRawContent(SAMPLE_CSV_B));
  });
});

describe('parseUrlhausCheckpoint', () => {
  it('parses JSON checkpoint payload', () => {
    const cp = parseUrlhausCheckpoint(JSON.stringify({
      v: 1,
      etag: '"abc"',
      canonical_ioc_hash: 'deadbeef'
    }));
    assert.equal(cp.etag, '"abc"');
    assert.equal(cp.canonical_ioc_hash, 'deadbeef');
  });

  it('supports legacy hash: prefix', () => {
    const cp = parseUrlhausCheckpoint('hash:legacy123');
    assert.equal(cp.canonical_ioc_hash, 'legacy123');
  });
});

describe('serializeUrlhausCheckpoint', () => {
  it('round-trips through parseUrlhausCheckpoint', () => {
    const raw = serializeUrlhausCheckpoint({
      etag: 'W/"etag1"',
      last_modified: 'Wed, 01 Jan 2025 00:00:00 GMT',
      raw_content_hash: 'raw1',
      canonical_ioc_hash: 'can1'
    });
    const cp = parseUrlhausCheckpoint(raw);
    assert.equal(cp.canonical_ioc_hash, 'can1');
    assert.equal(cp.raw_content_hash, 'raw1');
  });
});

describe('evaluateUrlhausExportSkip', () => {
  const checkpoint = {
    etag: 'W/"same"',
    last_modified: 'Wed, 01 Jan 2025 00:00:00 GMT',
    canonical_ioc_hash: 'canon1'
  };

  it('skips on HTTP 304', () => {
    const r = evaluateUrlhausExportSkip({ checkpoint, statusCode: 304 });
    assert.equal(r.skip, true);
    assert.equal(r.reason, 'not_modified');
  });

  it('skips when ETag unchanged', () => {
    const r = evaluateUrlhausExportSkip({
      checkpoint,
      statusCode: 200,
      responseEtag: 'W/"same"'
    });
    assert.equal(r.skip, true);
    assert.equal(r.reason, 'etag_unchanged');
  });

  it('skips when Last-Modified unchanged', () => {
    const r = evaluateUrlhausExportSkip({
      checkpoint: { last_modified: 'Wed, 01 Jan 2025 00:00:00 GMT' },
      statusCode: 200,
      responseLastModified: 'Wed, 01 Jan 2025 00:00:00 GMT'
    });
    assert.equal(r.skip, true);
    assert.equal(r.reason, 'last_modified_unchanged');
  });

  it('skips when canonical IOC hash unchanged despite different raw CSV', () => {
    const entries = parseUrlhausRecentCsv(SAMPLE_CSV_A).entries;
    const canonical = buildUrlhausCanonicalIocHash(entries);
    const r = evaluateUrlhausExportSkip({
      checkpoint: { canonical_ioc_hash: canonical },
      statusCode: 200,
      responseEtag: 'W/"different"',
      canonicalIocHash: buildUrlhausCanonicalIocHash(parseUrlhausRecentCsv(SAMPLE_CSV_B).entries)
    });
    assert.equal(r.skip, true);
    assert.equal(r.reason, 'canonical_unchanged');
  });

  it('imports when canonical IOC hash changes', () => {
    const base = parseUrlhausRecentCsv(SAMPLE_CSV_A).entries;
    const canonical = buildUrlhausCanonicalIocHash(base);
    const changed = buildUrlhausCanonicalIocHash([
      ...base,
      { observable: 'https://changed.example.test/y', observableType: 'url' }
    ]);
    const r = evaluateUrlhausExportSkip({
      checkpoint: { canonical_ioc_hash: canonical },
      statusCode: 200,
      responseEtag: 'W/"new"',
      canonicalIocHash: changed
    });
    assert.equal(r.skip, false);
  });
});

describe('fetchUrlhausExport', () => {
  it('throws on fetch error status', async () => {
    const { fetchUrlhausExport } = await import('./urlhaus.js');
    await assert.rejects(
      () => fetchUrlhausExport('test-key', {
        fetchImpl: async () => ({ ok: false, status: 403, headers: { get: () => null } })
      }),
      /403/
    );
  });

  it('returns 304 without body when server not modified', async () => {
    const { fetchUrlhausExport } = await import('./urlhaus.js');
    const res = await fetchUrlhausExport('test-key', {
      checkpoint: { etag: 'W/"same"' },
      fetchImpl: async () => ({
        ok: true,
        status: 304,
        headers: { get: (h) => (h === 'etag' ? 'W/"same"' : null) }
      })
    });
    assert.equal(res.status, 304);
    assert.equal(res.text, null);
  });
});

describe('URLHaus import confidence', () => {
  it('uses feed default high when row confidence is absent', async () => {
    const { resolveImportConfidenceFields } = await import('../lib/iocConfidence.js');
    const fields = resolveImportConfidenceFields({
      parsedSourceConfidence: null,
      feedDefaultConfidence: 'high'
    });
    assert.equal(fields.confidence, 'high');
    assert.equal(fields.feed_default_confidence, 'high');
    assert.equal(fields.source_confidence, null);
  });

  it('prefers explicit row confidence over feed default', async () => {
    const { resolveImportConfidenceFields } = await import('../lib/iocConfidence.js');
    const fields = resolveImportConfidenceFields({
      parsedSourceConfidence: 'low',
      feedDefaultConfidence: 'high'
    });
    assert.equal(fields.confidence, 'low');
    assert.equal(fields.source_confidence, 'low');
  });

  it('falls back to medium when confidence and feed default are missing', async () => {
    const { resolveImportConfidenceFields } = await import('../lib/iocConfidence.js');
    const fields = resolveImportConfidenceFields({ parsedSourceConfidence: null });
    assert.equal(fields.confidence, 'medium');
  });

  it('normalizes invalid confidence to medium via fallback chain', async () => {
    const { resolveImportConfidenceFields } = await import('../lib/iocConfidence.js');
    const fields = resolveImportConfidenceFields({
      parsedSourceConfidence: 'very_high',
      feedDefaultConfidence: 'high'
    });
    assert.equal(fields.confidence, 'high');
  });
});
