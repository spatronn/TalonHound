import test from 'node:test';
import assert from 'node:assert/strict';
import {
  categoryToLegacyType,
  formatTagSourceLabels,
  legacyTypeToCategory,
  MAX_TAG_NAME_LENGTH,
  normalizeTagName,
  normalizeTagSearch,
  normalizeTagSlug,
  parseExcludeTagIds,
  parseNormalizedTagName,
  parseTagListLimit,
  toPublicTag
} from './tagHelpers.js';

test('normalizeTagName trims, lowercases, and collapses whitespace', () => {
  assert.equal(normalizeTagName('  Mirai  '), 'mirai');
  assert.equal(normalizeTagName('MIRAI'), 'mirai');
  assert.equal(normalizeTagName('mirai'), 'mirai');
  assert.equal(normalizeTagName('  foo   bar  '), 'foo bar');
});

test('normalizeTagName does not convert hyphen underscore or space', () => {
  assert.equal(normalizeTagName('mirai-bot'), 'mirai-bot');
  assert.equal(normalizeTagName('mirai_bot'), 'mirai_bot');
  assert.equal(normalizeTagName('mirai bot'), 'mirai bot');
  assert.notEqual(normalizeTagName('mirai-bot'), normalizeTagName('mirai_bot'));
  assert.notEqual(normalizeTagName('mirai_bot'), normalizeTagName('mirai bot'));
});

test('parseNormalizedTagName rejects empty and too-long names', () => {
  assert.deepEqual(parseNormalizedTagName('   '), { ok: false, error: 'empty' });
  assert.deepEqual(parseNormalizedTagName(''), { ok: false, error: 'empty' });
  assert.equal(parseNormalizedTagName('x'.repeat(MAX_TAG_NAME_LENGTH + 1)).ok, false);
  assert.equal(parseNormalizedTagName('x'.repeat(MAX_TAG_NAME_LENGTH + 1)).error, 'too_long');
  assert.deepEqual(parseNormalizedTagName('  Mirai '), { ok: true, name: 'mirai' });
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

test('toPublicTag exposes is_active alias and optional sources', () => {
  const row = {
    id: 7,
    name: 'c2',
    slug: 'c2',
    description: null,
    color: '#fff',
    category: 'malware',
    type: 'threat',
    enabled: true,
    created_origin: 'manual',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-02T00:00:00.000Z'
  };
  const tag = toPublicTag(row, { sources: ['Manual'] });
  assert.equal(tag.is_active, true);
  assert.equal(tag.enabled, true);
  assert.equal(tag.category, 'malware');
  assert.deepEqual(tag.sources, ['Manual']);
  assert.equal(tag.created_origin, 'manual');
});

test('toPublicTag derives category from legacy type when column is null', () => {
  // Older rows created before the category column existed still render.
  const tag = toPublicTag({
    id: 9,
    name: 'legacy',
    slug: 'legacy',
    category: null,
    type: 'technique',
    enabled: false,
    created_origin: 'integration'
  });
  assert.equal(tag.category, 'behavior');
  assert.equal(tag.is_active, false);
});

test('formatTagSourceLabels puts Manual first and dedupes feeds', () => {
  assert.deepEqual(
    formatTagSourceLabels(['URLhaus abuse.ch', 'Manual', 'URLhaus abuse.ch', 'ThreatFox abuse.ch']),
    ['Manual', 'ThreatFox abuse.ch', 'URLhaus abuse.ch']
  );
});
