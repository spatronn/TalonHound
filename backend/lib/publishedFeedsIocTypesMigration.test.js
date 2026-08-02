import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRunnableMigrationFile } from './migrationFiles.js';
import { resolveFeedIocTypes, normalizeFeedConfig } from './feedPublisherService.js';

const migrationsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
const mig139 = fs.readFileSync(path.join(migrationsDir, '139_published_feeds_ioc_types.sql'), 'utf8');
const mig140 = fs.readFileSync(
  path.join(migrationsDir, '140_drop_published_feeds_legacy_ioc_type.sql.disabled'),
  'utf8'
);

describe('published feeds ioc_types migration compatibility', () => {
  it('139 and 140 migration files exist; 140 stays disabled until post-smoke cleanup', () => {
    assert.equal(isRunnableMigrationFile('139_published_feeds_ioc_types.sql'), true);
    assert.equal(isRunnableMigrationFile('140_drop_published_feeds_legacy_ioc_type.sql.disabled'), false);
  });

  it('139 is additive: adds ioc_types but does not drop legacy ioc_type column or index', () => {
    assert.match(mig139, /ADD COLUMN IF NOT EXISTS ioc_types JSONB/);
    assert.match(mig139, /SET ioc_types = to_jsonb\(ARRAY\[lower\(ioc_type\)\]\)/);
    assert.match(mig139, /ALTER COLUMN ioc_types SET NOT NULL/);
    assert.match(mig139, /chk_published_feeds_ioc_types/);
    assert.match(mig139, /idx_published_feeds_ioc_types/);
    assert.match(mig139, /trg_published_feeds_bridge_ioc_types/);
    assert.doesNotMatch(mig139, /DROP COLUMN(?:\s+IF EXISTS)?\s+ioc_type/i);
    assert.doesNotMatch(mig139, /DROP INDEX(?:\s+IF EXISTS)?\s+idx_published_feeds_ioc_type/i);
    assert.doesNotMatch(mig139, /DROP CONSTRAINT(?:\s+IF EXISTS)?\s+chk_published_feeds_ioc_type\b/i);
  });

  it('140 cleans up legacy ioc_type only after a null/empty ioc_types safety check', () => {
    assert.match(mig140, /ioc_types IS NULL/i);
    assert.match(mig140, /jsonb_array_length\(ioc_types\) < 1/);
    assert.match(mig140, /RAISE EXCEPTION/);
    assert.match(mig140, /DROP COLUMN IF EXISTS ioc_type/);
    assert.match(mig140, /DROP INDEX IF EXISTS idx_published_feeds_ioc_type/);
    assert.match(mig140, /DROP TRIGGER IF EXISTS trg_published_feeds_bridge_ioc_types/);
  });
});

describe('resolveFeedIocTypes expand-contract reads', () => {
  it('post-139 old backend row shape (scalar ioc_type, optional ioc_types) still resolves', () => {
    // Pre-backfill edge: only legacy column present.
    assert.deepEqual(resolveFeedIocTypes({ ioc_type: 'domain' }), ['domain']);
    // After 139 backfill both columns exist; ioc_types wins.
    assert.deepEqual(
      resolveFeedIocTypes({ ioc_type: 'ip', ioc_types: ['domain', 'url'] }),
      ['domain', 'url']
    );
  });

  it('new backend reads single and multi ioc_types without needing ioc_type', () => {
    assert.deepEqual(resolveFeedIocTypes({ ioc_types: ['hash'] }), ['hash']);
    assert.deepEqual(
      resolveFeedIocTypes({ ioc_types: ['url', 'domain'] }),
      ['domain', 'url']
    );
  });

  it('post-140 rows with only ioc_types keep working (legacy column gone)', () => {
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

  it('rollback-safe: scalar backfill target remains recoverable as one-element list', () => {
    // Simulates restoring pre-140 backup where both columns exist; no data loss.
    const restored = resolveFeedIocTypes({
      ioc_type: 'url',
      ioc_types: ['url']
    });
    assert.deepEqual(restored, ['url']);
  });
});
