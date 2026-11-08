import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  emptyFeedForm,
  feedToForm,
  toggleFilterMode,
  setFilterMode,
  toggleFeedFormat,
  validateFeedForm,
  buildFeedPayload,
  normalizeFilterMode,
  normalizeOutputFormat,
  normalizeFeedFormats,
  filterModeLabel,
  parseCuratedPublicIdsText
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
    assert.deepEqual(form.ioc_types, ['hash']);
  });

  it('edit form opens in curated mode with public ids', () => {
    const form = feedToForm({
      name: 'C',
      filter_mode: 'curated',
      curated_ioc_public_ids: ['11111111-1111-4111-8111-111111111111']
    });
    assert.equal(form.filter_mode, 'curated');
    assert.match(form.curated_ioc_public_ids_text, /11111111/);
    assert.equal(filterModeLabel('curated'), 'Curated');
  });

  it('Basic -> Query -> Curated -> Basic preserves unsaved values', () => {
    let form = emptyFeedForm();
    form = { ...form, ioc_types: ['domain', 'url'], time_window: '7d', include_tags: 'mirai' };

    form = toggleFilterMode(form); // -> query
    assert.equal(form.filter_mode, 'query');
    form = { ...form, advanced_query: 'source equals "USOM"' };

    form = toggleFilterMode(form); // -> curated
    assert.equal(form.filter_mode, 'curated');
    form = { ...form, curated_ioc_public_ids_text: '11111111-1111-4111-8111-111111111111' };
    assert.equal(form.advanced_query, 'source equals "USOM"');
    assert.deepEqual(form.ioc_types, ['domain', 'url']);

    form = toggleFilterMode(form); // -> basic
    assert.equal(form.filter_mode, 'basic');
    assert.equal(form.curated_ioc_public_ids_text, '11111111-1111-4111-8111-111111111111');
    assert.equal(form.advanced_query, 'source equals "USOM"');
  });

  it('setFilterMode jumps directly', () => {
    const form = setFilterMode(emptyFeedForm(), 'curated');
    assert.equal(form.filter_mode, 'curated');
  });

  it('normalizeFilterMode defaults unknown values to basic', () => {
    assert.equal(normalizeFilterMode('query'), 'query');
    assert.equal(normalizeFilterMode('CURATED'), 'curated');
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

  it('curated mode rejects invalid UUIDs', () => {
    const base = {
      ...emptyFeedForm(),
      name: 'C',
      filter_mode: 'curated',
      curated_ioc_public_ids_text: 'not-uuid'
    };
    assert.match(validateFeedForm(base), /Invalid curated/);
    assert.equal(
      validateFeedForm({
        ...base,
        curated_ioc_public_ids_text: '11111111-1111-4111-8111-111111111111'
      }),
      null
    );
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
      include_tags: 'a, b'
    };
    const payload = buildFeedPayload(form);
    assert.equal(payload.filter_mode, 'query');
    assert.equal(payload.advanced_query, 'source equals "USOM"');
    assert.equal(payload.curated_ioc_public_ids, undefined);
  });

  it('curated mode sends curated_ioc_public_ids', () => {
    const form = {
      ...emptyFeedForm(),
      name: 'C',
      filter_mode: 'curated',
      curated_ioc_public_ids_text: '11111111-1111-4111-8111-111111111111\n22222222-2222-4222-8222-222222222222'
    };
    const payload = buildFeedPayload(form);
    assert.equal(payload.filter_mode, 'curated');
    assert.equal(payload.advanced_query, null);
    assert.deepEqual(payload.curated_ioc_public_ids, [
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222'
    ]);
  });

  it('parseCuratedPublicIdsText splits on whitespace and commas', () => {
    assert.deepEqual(
      parseCuratedPublicIdsText('a, b\nc'),
      ['a', 'b', 'c']
    );
  });
});

describe('publishedFeedForm formats helpers', () => {
  it('toggleFeedFormat flips formats', () => {
    let form = emptyFeedForm();
    form = toggleFeedFormat(form, 'json');
    assert.deepEqual(normalizeFeedFormats(form.formats), ['txt', 'json']);
    assert.equal(normalizeOutputFormat('json'), 'json');
  });
});
