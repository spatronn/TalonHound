import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  emptyFeedForm,
  feedToForm,
  toggleFilterMode,
  validateFeedForm,
  buildFeedPayload,
  normalizeFilterMode,
  normalizeOutputFormat
} from './publishedFeedForm.js';

describe('publishedFeedForm mode handling', () => {
  it('a feed without filter_mode opens in basic mode', () => {
    const form = feedToForm({ name: 'Legacy', ioc_types: ['ip'] });
    assert.equal(form.filter_mode, 'basic');
    assert.equal(form.advanced_query, '');
  });

  it('edit form opens in the persisted mode (query)', () => {
    const form = feedToForm({
      name: 'Adv',
      filter_mode: 'query',
      advanced_query: 'source equals "MalwareBazaar"',
      ioc_types: ['hash']
    });
    assert.equal(form.filter_mode, 'query');
    assert.equal(form.advanced_query, 'source equals "MalwareBazaar"');
    // Basic selectors are still hydrated so a switch back is lossless.
    assert.deepEqual(form.ioc_types, ['hash']);
  });

  it('edit form opens in the persisted mode (basic)', () => {
    const form = feedToForm({ name: 'B', filter_mode: 'basic', ioc_types: ['domain', 'url'] });
    assert.equal(form.filter_mode, 'basic');
    assert.deepEqual(form.ioc_types, ['domain', 'url']);
  });

  it('Basic -> Advanced -> Basic preserves unsaved values', () => {
    // Start basic, edit basic selectors, then type a query, toggle back and forth.
    let form = emptyFeedForm();
    form = { ...form, ioc_types: ['domain', 'url'], time_window: '7d', include_tags: 'mirai' };

    form = toggleFilterMode(form); // -> query
    assert.equal(form.filter_mode, 'query');
    form = { ...form, advanced_query: 'source equals "USOM"' };
    // Basic values survive the switch to query.
    assert.deepEqual(form.ioc_types, ['domain', 'url']);
    assert.equal(form.time_window, '7d');

    form = toggleFilterMode(form); // -> basic
    assert.equal(form.filter_mode, 'basic');
    // Both the basic values and the unsaved query survive round-tripping.
    assert.deepEqual(form.ioc_types, ['domain', 'url']);
    assert.equal(form.time_window, '7d');
    assert.equal(form.include_tags, 'mirai');
    assert.equal(form.advanced_query, 'source equals "USOM"');

    form = toggleFilterMode(form); // -> query again, query text still there
    assert.equal(form.filter_mode, 'query');
    assert.equal(form.advanced_query, 'source equals "USOM"');
  });

  it('normalizeFilterMode defaults unknown values to basic', () => {
    assert.equal(normalizeFilterMode('query'), 'query');
    assert.equal(normalizeFilterMode('QUERY'), 'query');
    assert.equal(normalizeFilterMode(undefined), 'basic');
    assert.equal(normalizeFilterMode('nonsense'), 'basic');
  });
});

describe('publishedFeedForm validation', () => {
  it('query mode requires a non-empty query', () => {
    const base = { ...emptyFeedForm(), name: 'Q', filter_mode: 'query', advanced_query: '   ' };
    assert.match(validateFeedForm(base), /Advanced Query/);
    assert.equal(validateFeedForm({ ...base, advanced_query: 'ioc contains "x"' }), null);
  });

  it('basic mode requires at least one IOC type', () => {
    const base = { ...emptyFeedForm(), name: 'B', filter_mode: 'basic', ioc_types: [] };
    assert.match(validateFeedForm(base), /IOC type/);
    assert.equal(validateFeedForm({ ...base, ioc_types: ['ip'] }), null);
  });

  it('name is always required', () => {
    assert.match(validateFeedForm({ ...emptyFeedForm(), name: '' }), /Name is required/);
  });
});

describe('publishedFeedForm payload', () => {
  it('query mode sends advanced_query and null-safe basic fields', () => {
    const form = {
      ...emptyFeedForm(),
      name: 'Q',
      filter_mode: 'query',
      advanced_query: '  source equals "USOM"  ',
      ioc_types: ['domain'],
      include_tags: 'a, b',
      max_items: '500'
    };
    const payload = buildFeedPayload(form);
    assert.equal(payload.filter_mode, 'query');
    assert.equal(payload.advanced_query, 'source equals "USOM"');
    assert.deepEqual(payload.include_tags, ['a', 'b']);
    assert.equal(payload.max_items, 500);
  });

  it('basic mode sends filter_mode basic and null advanced_query', () => {
    const form = { ...emptyFeedForm(), name: 'B', filter_mode: 'basic', advanced_query: 'leftover query' };
    const payload = buildFeedPayload(form);
    assert.equal(payload.filter_mode, 'basic');
    assert.equal(payload.advanced_query, null);
  });
});

describe('publishedFeedForm output format', () => {
  it('default formats is txt-only with default include flags', () => {
    const form = emptyFeedForm();
    assert.deepEqual(form.formats, ['txt']);
    assert.equal(form.include_source_metadata, true);
    assert.equal(form.include_classification, true);
    assert.equal(form.include_enrichment, false);
  });

  it('a legacy feed with no format opens as txt', () => {
    const form = feedToForm({ name: 'Legacy', ioc_types: ['ip'] });
    assert.deepEqual(form.formats, ['txt']);
  });

  it('saved JSON config reloads correctly (formats + flags)', () => {
    const form = feedToForm({
      name: 'J', ioc_types: ['domain'], format: 'json',
      include_source_metadata: false, include_classification: true, include_enrichment: true
    });
    assert.deepEqual(form.formats, ['json']);
    assert.equal(form.include_source_metadata, false);
    assert.equal(form.include_classification, true);
    assert.equal(form.include_enrichment, true);
  });

  it('dual formats reload and payload uses formats[]', () => {
    const form = feedToForm({ name: 'D', ioc_types: ['ip'], formats: ['json', 'txt'] });
    assert.deepEqual(form.formats, ['txt', 'json']);
    const payload = buildFeedPayload(form);
    assert.deepEqual(payload.formats, ['txt', 'json']);
    assert.equal(payload.output_format, undefined);
  });

  it('cannot save with zero formats selected', () => {
    const form = { ...emptyFeedForm(), name: 'X', formats: [] };
    assert.match(validateFeedForm(form), /output format/i);
  });

  it('buildFeedPayload sends formats and include flags', () => {
    const txt = buildFeedPayload({ ...emptyFeedForm(), name: 'T' });
    assert.deepEqual(txt.formats, ['txt']);
    assert.equal(txt.include_source_metadata, true);
    assert.equal(txt.include_enrichment, false);

    const json = buildFeedPayload({
      ...emptyFeedForm(), name: 'J', formats: ['json'], include_enrichment: true, include_classification: false
    });
    assert.deepEqual(json.formats, ['json']);
    assert.equal(json.include_enrichment, true);
    assert.equal(json.include_classification, false);
  });

  it('normalizeOutputFormat defaults unknown values to txt', () => {
    assert.equal(normalizeOutputFormat('json'), 'json');
    assert.equal(normalizeOutputFormat('JSON'), 'json');
    assert.equal(normalizeOutputFormat(undefined), 'txt');
    assert.equal(normalizeOutputFormat('xml'), 'txt');
  });
});
