import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_SOURCE_COLOR,
  isValidHexColor,
  normalizeHexColor,
  readableTextColor,
  shadeHexColor,
  sourceBadgeStyle,
  buildSourceColorIndex,
  resolveSourceColor,
  resolveSourceBadgeStyle
} from './sourceBadge.js';

test('isValidHexColor / normalizeHexColor', () => {
  assert.equal(isValidHexColor('#7C3AED'), true);
  assert.equal(isValidHexColor('#abc'), false);
  assert.equal(normalizeHexColor('  #7C3AED '), '#7c3aed');
  assert.equal(normalizeHexColor('nope'), null);
  assert.equal(normalizeHexColor(42), null);
});

test('readableTextColor picks dark text on light bg and light on dark', () => {
  assert.equal(readableTextColor('#ffffff'), '#0b1220');
  assert.equal(readableTextColor('#000000'), '#f8fafc');
  // USOM purple is dark -> light text
  assert.equal(readableTextColor('#7c3aed'), '#f8fafc');
  // A pale green -> dark text
  assert.equal(readableTextColor('#a7f3d0'), '#0b1220');
});

test('shadeHexColor blends toward black/white', () => {
  assert.equal(shadeHexColor('#808080', -1), '#000000');
  assert.equal(shadeHexColor('#808080', 1), '#ffffff');
  assert.equal(shadeHexColor('#808080', 0), '#808080');
});

test('sourceBadgeStyle produces bg, readable text and derived border', () => {
  const style = sourceBadgeStyle('#16a34a');
  assert.equal(style.background, '#16a34a');
  assert.equal(style.color, '#f8fafc');
  assert.match(style.border, /^1px solid #[0-9a-f]{6}$/);
});

test('sourceBadgeStyle falls back to default on invalid input', () => {
  const style = sourceBadgeStyle('garbage');
  assert.equal(style.background, DEFAULT_SOURCE_COLOR);
});

test('buildSourceColorIndex normalizes names, first writer wins', () => {
  const index = buildSourceColorIndex([
    { name: 'USOM:TR-CERT', color: '#7C3AED' },
    { name: 'usom:tr-cert', color: '#000000' }, // ignored (dup key)
    { name: 'MalwareBazaar', color: '#16a34a' },
    { name: 'Bad', color: 'not-a-color' }, // dropped
    { name: '', color: '#111111' } // dropped
  ]);
  assert.equal(index.get('usom:tr-cert'), '#7c3aed');
  assert.equal(index.get('malwarebazaar'), '#16a34a');
  assert.equal(index.has('bad'), false);
  assert.equal(index.size, 2);
});

test('buildSourceColorIndex resolves feed-vs-source name conflicts deterministically (feed wins)', () => {
  // Same display name present in both catalogs, with source listed first.
  const sourceFirst = buildSourceColorIndex([
    { name: 'Shared Name', color: '#111111', type: 'source' },
    { name: 'Shared Name', color: '#7c3aed', type: 'feed' }
  ]);
  // ...and with feed listed first. Both must yield the feed color.
  const feedFirst = buildSourceColorIndex([
    { name: 'Shared Name', color: '#7c3aed', type: 'feed' },
    { name: 'Shared Name', color: '#111111', type: 'source' }
  ]);
  assert.equal(sourceFirst.get('shared name'), '#7c3aed');
  assert.equal(feedFirst.get('shared name'), '#7c3aed');
  assert.equal(sourceFirst.get('shared name'), feedFirst.get('shared name'));
});

test('buildSourceColorIndex is order-independent for same-type conflicts via stable input order', () => {
  // Equal precedence (both sources): first entry wins; backend supplies a
  // deterministic order so this is stable across requests.
  const index = buildSourceColorIndex([
    { name: 'Dup', color: '#aaaaaa', type: 'source' },
    { name: 'Dup', color: '#bbbbbb', type: 'source' }
  ]);
  assert.equal(index.get('dup'), '#aaaaaa');
});

test('resolveSourceColor + resolveSourceBadgeStyle', () => {
  const index = buildSourceColorIndex([{ name: 'USOM:TR-CERT', color: '#7c3aed' }]);
  assert.equal(resolveSourceColor(index, ' usom:tr-cert '), '#7c3aed');
  assert.equal(resolveSourceColor(index, 'Unknown'), null);
  assert.equal(resolveSourceColor(null, 'x'), null);

  assert.equal(resolveSourceBadgeStyle(index, 'USOM:TR-CERT').background, '#7c3aed');
  // unknown -> fallback
  assert.equal(resolveSourceBadgeStyle(index, 'Unknown').background, DEFAULT_SOURCE_COLOR);
});
