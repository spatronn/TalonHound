import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveFeedIocTypes, normalizeFeedConfig } from './feedPublisherService.js';

const baselineSql = fs.readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations', '001_core.sql'),
  'utf8'
);

describe('published feeds ioc_types baseline schema', () => {
  it('001_core defines multi-value ioc_types on published_feeds', () => {
    assert.match(baselineSql, /ioc_types jsonb NOT NULL/);
    assert.match(baselineSql, /chk_published_feeds_ioc_types/);
    assert.match(baselineSql, /published_feeds_bridge_ioc_types/);
    assert.match(baselineSql, /idx_published_feeds_ioc_types/);
  });
});

describe('resolveFeedIocTypes expand-contract reads', () => {
  it('legacy row shape (scalar ioc_type, optional ioc_types) still resolves', () => {
    assert.deepEqual(resolveFeedIocTypes({ ioc_type: 'domain' }), ['domain']);
    assert.deepEqual(
      resolveFeedIocTypes({ ioc_type: 'ip', ioc_types: ['domain', 'url'] }),
      ['domain', 'url']
    );
  });

  it('reads single and multi ioc_types without needing ioc_type', () => {
    assert.deepEqual(resolveFeedIocTypes({ ioc_types: ['hash'] }), ['hash']);
    assert.deepEqual(
      resolveFeedIocTypes({ ioc_types: ['url', 'domain'] }),
      ['domain', 'url']
    );
  });

  it('ioc_types-only rows keep working', () => {
    const row = normalizeFeedConfig({
      id: 9,
      time_window: 'all',
      ioc_types: ['ip', 'hash'],
      include_feed_keys: null,
      include_tags: null,
      exclude_tags: null
    });
    assert.deepEqual(row.ioc_types, ['ip', 'hash']);
    assert.equal(row.ioc_type, undefined);
  });

  it('scalar backfill target remains recoverable as one-element list', () => {
    const restored = resolveFeedIocTypes({
      ioc_type: 'url',
      ioc_types: ['url']
    });
    assert.deepEqual(restored, ['url']);
  });
});
