import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateAdvancedQuery,
  validateFeedPayload,
  normalizeCuratedIocInput,
  resolveFilterModeInput,
  toPublicFeed,
  previewFeedMembership,
  FEED_FILTER_MODES
} from './publishedFeedManagementService.js';

describe('publishedFeedManagementService validation', () => {
  it('accepts basic, query, and curated filter_mode', () => {
    assert.deepEqual(validateFeedPayload({ name: 'A', filter_mode: 'basic', ioc_types: ['ip'] }, false, 'basic'), []);
    assert.deepEqual(validateFeedPayload({ name: 'A', filter_mode: 'query' }, false, 'query'), []);
    assert.deepEqual(
      validateFeedPayload({
        name: 'A',
        filter_mode: 'curated',
        curated_ioc_public_ids: ['11111111-1111-4111-8111-111111111111']
      }, false, 'curated'),
      []
    );
    assert.match(
      validateFeedPayload({ name: 'A', filter_mode: 'weird' }, false, 'basic').join(';'),
      /filter_mode/
    );
  });

  it('does not require ioc_types in curated mode', () => {
    const errors = validateFeedPayload(
      { name: 'C', filter_mode: 'curated', curated_ioc_public_ids: [] },
      false,
      'curated'
    );
    assert.equal(errors.length, 0);
  });

  it('normalizeCuratedIocInput accepts both shapes and caps at 5000', () => {
    const a = normalizeCuratedIocInput({
      curated_iocs: [
        { public_id: '11111111-1111-4111-8111-111111111111', reason: 'keep' },
        { public_id: '11111111-1111-4111-8111-111111111111' } // dup
      ]
    });
    assert.equal(a.ok, true);
    assert.equal(a.value.length, 1);
    assert.equal(a.value[0].reason, 'keep');

    const b = normalizeCuratedIocInput({
      curated_ioc_public_ids: ['22222222-2222-4222-8222-222222222222']
    });
    assert.equal(b.ok, true);
    assert.equal(b.value[0].public_id, '22222222-2222-4222-8222-222222222222');

    const bad = normalizeCuratedIocInput({ curated_ioc_public_ids: ['not-a-uuid'] });
    assert.equal(bad.ok, false);

    const tooMany = normalizeCuratedIocInput({
      curated_ioc_public_ids: Array.from({ length: 5001 }, (_, i) => {
        const hex = i.toString(16).padStart(12, '0');
        return `11111111-1111-4111-8111-${hex}`;
      })
    });
    assert.equal(tooMany.ok, false);
    assert.match(tooMany.error, /5000/);
  });

  it('validateAdvancedQuery requires non-empty valid DSL', () => {
    assert.match(validateAdvancedQuery('').error, /required/);
    assert.equal(validateAdvancedQuery('ioc contains "x"').normalized.includes('ioc'), true);
  });

  it('resolveFilterModeInput prefers body then existing', () => {
    assert.equal(resolveFilterModeInput({ filter_mode: 'curated' }), FEED_FILTER_MODES.CURATED);
    assert.equal(resolveFilterModeInput({}, { filter_mode: 'query' }), FEED_FILTER_MODES.QUERY);
    assert.equal(resolveFilterModeInput({}), FEED_FILTER_MODES.BASIC);
  });

  it('toPublicFeed includes curated summary when provided', () => {
    const pub = toPublicFeed(
      {
        id: 9,
        name: 'C',
        filter_mode: 'curated',
        formats: ['txt'],
        ioc_types: ['ip'],
        time_window: 'all',
        refresh_interval_minutes: 15
      },
      { curated_ioc_count: 2, curated_ioc_public_ids: ['a', 'b'] }
    );
    assert.equal(pub.filter_mode, 'curated');
    assert.equal(pub.curated_ioc_count, 2);
    assert.deepEqual(pub.curated_ioc_public_ids, ['a', 'b']);
  });
});

describe('previewFeedMembership dry semantics', () => {
  it('returns validation_errors without querying when proposed curated ids are invalid', async () => {
    const pool = {
      query: async () => {
        throw new Error('pool should not be queried on validation failure');
      },
      connect: async () => {
        throw new Error('no connect');
      }
    };
    const { preview } = await previewFeedMembership(pool, {
      name: 'X',
      filter_mode: 'curated',
      curated_ioc_public_ids: ['nope']
    });
    assert.ok(preview.validation_errors.length);
    assert.equal(preview.total, 0);
  });

  it('never writes — empty curated preview returns total 0 via mocked pool', async () => {
    const queries = [];
    const pool = {
      query: async (sql, params) => {
        queries.push({ sql: String(sql), params });
        if (String(sql).includes('WITH dedup')) {
          if (String(sql).includes('OFFSET')) {
            return { rows: [] };
          }
          return { rows: [{ total: 0, counts_by_type: {} }] };
        }
        return { rows: [] };
      }
    };
    const { preview } = await previewFeedMembership(pool, {
      name: 'Empty curated',
      filter_mode: 'curated',
      curated_ioc_public_ids: [],
      formats: ['txt']
    });
    assert.equal(preview.filter_mode, 'curated');
    assert.equal(preview.total, 0);
    assert.ok(queries.every((q) => !/INSERT|UPDATE|DELETE/i.test(q.sql)));
  });
});
