import test from 'node:test';
import assert from 'node:assert/strict';
import {
  categoryToLegacyType,
  legacyTypeToCategory,
  normalizeTagName,
  normalizeTagSearch,
  normalizeTagSlug,
  parseExcludeTagIds,
  parseTagListLimit,
  toPublicTag
} from './tagHelpers.js';

test('normalizeTagName trims and lowercases', () => {
  assert.equal(normalizeTagName('  Phishing  '), 'phishing');
});

test('normalizeTagSlug slugifies values', () => {
  assert.equal(normalizeTagSlug('APT-29'), 'apt-29');
  assert.equal(normalizeTagSlug('  click fix '), 'click-fix');
});

test('categoryToLegacyType maps categories to enum', () => {
  assert.equal(categoryToLegacyType('malware'), 'context');
  assert.equal(categoryToLegacyType('actor'), 'context');
  assert.equal(categoryToLegacyType('behavior'), 'technique');
  assert.equal(categoryToLegacyType('campaign'), 'threat');
  assert.equal(categoryToLegacyType('custom'), 'context');
});

test('legacyTypeToCategory maps enum to categories', () => {
  assert.equal(legacyTypeToCategory('threat'), 'campaign');
  assert.equal(legacyTypeToCategory('actor'), 'custom');
  assert.equal(legacyTypeToCategory('technique'), 'behavior');
});

test('parseTagListLimit defaults and caps', () => {
  assert.equal(parseTagListLimit(undefined), 5);
  assert.equal(parseTagListLimit('5'), 5);
  assert.equal(parseTagListLimit('100'), 50);
  assert.equal(parseTagListLimit('0'), 5);
});

test('parseExcludeTagIds deduplicates ids', () => {
  assert.deepEqual(parseExcludeTagIds('1,2,2,3'), [1, 2, 3]);
  assert.deepEqual(parseExcludeTagIds(''), []);
});

test('normalizeTagSearch trims and caps length', () => {
  assert.equal(normalizeTagSearch('  apt  '), 'apt');
  assert.equal(normalizeTagSearch('x'.repeat(120)).length, 100);
});

test('toPublicTag exposes is_active alias', () => {
  const row = {
    id: 7,
    name: 'c2',
    slug: 'c2',
    description: null,
    color: '#fff',
    category: 'malware',
    type: 'threat',
    enabled: true,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-02T00:00:00.000Z'
  };
  const tag = toPublicTag(row);
  assert.equal(tag.is_active, true);
  assert.equal(tag.enabled, true);
  assert.equal(tag.category, 'malware');
});
