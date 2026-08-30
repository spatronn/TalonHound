/**
 * Structural guards for global toast positioning.
 * Parses the shared App CSS in main.jsx — no DOM harness.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const mainSrc = readFileSync(
  fileURLToPath(new URL('../main.jsx', import.meta.url)),
  'utf8'
);

function extractRule(src, selector) {
  const start = src.indexOf(selector);
  assert.ok(start >= 0, `${selector} not found`);
  const brace = src.indexOf('{', start);
  const end = src.indexOf('}', brace);
  assert.ok(end > brace, `${selector} rule not closed`);
  return src.slice(brace + 1, end);
}

test('toast stack is fixed, top-centered, and not pinned to the upper-right', () => {
  const rule = extractRule(mainSrc, '.app-feedback-stack {');
  assert.match(rule, /position:\s*fixed/);
  assert.match(rule, /align-items:\s*center/);
  assert.match(rule, /left:\s*0/);
  assert.match(rule, /right:\s*0/);
  assert.doesNotMatch(rule, /right:\s*16px/);
  assert.match(rule, /z-index:\s*900/);
});

test('desktop toast inset uses app-shell sidebar tokens, not a magic right offset', () => {
  assert.match(mainSrc, /--th-sidebar-width:\s*260px/);
  assert.match(mainSrc, /--th-shell-pad:\s*16px/);
  assert.match(
    mainSrc,
    /body:has\(\.app-shell > \.sidebar\) \.app-feedback-stack/
  );
  assert.match(
    mainSrc,
    /padding-left:\s*calc\(var\(--th-shell-pad\) \+ var\(--th-sidebar-width\) \+ var\(--th-shell-gap\)\)/
  );
});

test('toast z-index stays below modal overlays', () => {
  const z = Number((mainSrc.match(/\.app-feedback-stack \{[\s\S]*?z-index:\s*(\d+)/) || [])[1]);
  assert.ok(Number.isFinite(z), 'toast z-index missing');
  assert.ok(z < 1000, `toast z-index ${z} must stay below modal overlays (1000+)`);
  assert.ok(z > 200, `toast z-index ${z} must stay above page chrome`);
});

test('narrow viewports drop the toast below the mobile topbar', () => {
  assert.match(mainSrc, /top:\s*calc\(var\(--th-mobile-topbar-height\) \+ 8px\)/);
  assert.match(mainSrc, /\.app-feedback-text \{[\s\S]*overflow-wrap:\s*anywhere/);
  assert.match(mainSrc, /\.app-feedback \{[\s\S]*box-sizing:\s*border-box/);
});
