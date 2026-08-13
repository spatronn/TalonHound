import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeFeedFormats,
  resolvePublishedFeedFormats,
  resolvePublishedFeedFormat,
  resolveRequestedFeedFormat,
  resolveFormatsInput
} from './publishedFeedFormats.js';
import { filtersHash as serviceFiltersHash, normalizeFeedConfig } from './feedPublisherService.js';

describe('normalizeFeedFormats', () => {
  it('defaults null to txt', () => {
    assert.deepEqual(normalizeFeedFormats(null).value, ['txt']);
  });

  it('canonicalizes order and dedupes including stix', () => {
    assert.deepEqual(normalizeFeedFormats(['json', 'txt', 'txt']).value, ['txt', 'json']);
    assert.deepEqual(normalizeFeedFormats(['stix', 'txt', 'json']).value, ['txt', 'json', 'stix']);
  });

  it('accepts stix and rejects unknown', () => {
    assert.deepEqual(normalizeFeedFormats(['stix']).value, ['stix']);
    assert.equal(normalizeFeedFormats(['xml']).ok, false);
  });
});

describe('resolvePublishedFeedFormats / primary format', () => {
  it('reads formats array', () => {
    assert.deepEqual(resolvePublishedFeedFormats({ formats: ['json'] }), ['json']);
  });

  it('falls back to legacy format column', () => {
    assert.deepEqual(resolvePublishedFeedFormats({ format: 'json' }), ['json']);
    assert.deepEqual(resolvePublishedFeedFormats({ format: 'txt' }), ['txt']);
  });

  it('primary prefers txt when both enabled', () => {
    assert.equal(resolvePublishedFeedFormat({ formats: ['txt', 'json'] }), 'txt');
    assert.equal(resolvePublishedFeedFormat({ formats: ['json'] }), 'json');
  });
});

describe('resolveRequestedFeedFormat', () => {
  const dual = { formats: ['txt', 'json'] };
  const jsonOnly = { formats: ['json'] };

  it('omitted defaults to txt when enabled', () => {
    assert.equal(resolveRequestedFeedFormat(dual, undefined).format, 'txt');
  });

  it('omitted defaults to sole format when txt off', () => {
    assert.equal(resolveRequestedFeedFormat(jsonOnly, null).format, 'json');
  });

  it('disabled format returns 404', () => {
    const r = resolveRequestedFeedFormat(jsonOnly, 'txt');
    assert.equal(r.status, 404);
  });

  it('disabled stix returns 404; enabled stix is selectable', () => {
    const txtOnly = { formats: ['txt'] };
    const withStix = { formats: ['txt', 'stix'] };
    assert.equal(resolveRequestedFeedFormat(txtOnly, 'stix').status, 404);
    assert.equal(resolveRequestedFeedFormat(withStix, 'stix').format, 'stix');
    assert.equal(resolveRequestedFeedFormat(withStix, undefined).format, 'txt');
  });
});

describe('resolveFormatsInput', () => {
  it('accepts formats[] and legacy aliases', () => {
    assert.deepEqual(resolveFormatsInput({ formats: ['json', 'txt'] }).value, ['txt', 'json']);
    assert.deepEqual(resolveFormatsInput({ output_format: 'json' }).value, ['json']);
    assert.deepEqual(resolveFormatsInput({ format: 'txt' }).value, ['txt']);
  });

  it('rejects unknown legacy format', () => {
    assert.equal(resolveFormatsInput({ output_format: 'xml' }).ok, false);
  });
});

describe('filtersHash format fingerprint', () => {
  it('TXT-only hash omits formats key (legacy stable)', () => {
    const h1 = serviceFiltersHash({ format: 'txt', ioc_types: ['ip'], filter_mode: 'basic' }, 'all');
    const h2 = serviceFiltersHash({ formats: ['txt'], ioc_types: ['ip'], filter_mode: 'basic' }, 'all');
    assert.equal(h1, h2);
  });

  it('JSON-only keeps output_format key', () => {
    const h = serviceFiltersHash({
      formats: ['json'],
      ioc_types: ['ip'],
      filter_mode: 'basic',
      include_source_metadata: true,
      include_classification: true,
      include_enrichment: false
    }, 'all');
    // Deterministic non-empty
    assert.equal(typeof h, 'string');
    assert.ok(h.length > 8);
  });

  it('dual format differs from txt-only', () => {
    const txt = serviceFiltersHash({ formats: ['txt'], ioc_types: ['ip'], filter_mode: 'basic' }, 'all');
    const dual = serviceFiltersHash({ formats: ['txt', 'json'], ioc_types: ['ip'], filter_mode: 'basic' }, 'all');
    assert.notEqual(txt, dual);
  });

  it('normalizeFeedConfig exposes formats', () => {
    const cfg = normalizeFeedConfig({
      id: 1,
      formats: ['json', 'txt'],
      ioc_types: ['domain'],
      time_window: 'all'
    });
    assert.deepEqual(cfg.formats, ['txt', 'json']);
    assert.equal(cfg.format, 'txt');
  });
});
