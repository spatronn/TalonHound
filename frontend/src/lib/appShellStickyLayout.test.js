/**
 * Source contract for position: sticky in the narrow (< 1024px) layout, where
 * the document scrolls instead of .main-content. overflow-x: hidden on <body>
 * makes it a scroll container that never scrolls, which silently disabled the
 * sticky topbar and every sticky toolbar below it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const mainSrc = readFileSync(path.join(here, '..', 'main.jsx'), 'utf8');
const reportCss = readFileSync(path.join(here, '..', 'components', 'threatLibrary', 'reportPage.css'), 'utf8');

function narrowLayoutBlock() {
  const start = mainSrc.indexOf('@media (max-width: 1023px) {');
  assert.ok(start >= 0, 'narrow layout breakpoint exists');
  const end = mainSrc.indexOf('\n        }\n', mainSrc.indexOf('.app-feedback-stack {', start));
  return mainSrc.slice(start, end);
}

test('narrow layout clips horizontal overflow without creating a scroll container', () => {
  const block = narrowLayoutBlock();
  // hidden first as the fallback for engines without clip; clip must win.
  assert.match(block, /html, body \{\s*overflow-x: hidden;\s*overflow-x: clip;\s*\}/);
  assert.doesNotMatch(block, /overflow-x: clip;\s*overflow-x: hidden;/);
  assert.match(block, /\.mobile-topbar \{\s*display: flex !important;\s*\}/);
  assert.match(mainSrc, /\.mobile-topbar \{\s*display: none;[\s\S]*?position: sticky;\s*top: 0;\s*z-index: 100;/);
});

test('sticky content is inset below the narrow-layout topbar through one shell token', () => {
  assert.match(mainSrc, /--th-sticky-top: 0px;/, 'desktop: no inset (.main-content is the scroller)');
  const block = narrowLayoutBlock();
  assert.match(block, /:root \{\s*--th-sticky-top: var\(--th-mobile-topbar-height\);\s*\}/);
  assert.match(block, /html \{\s*scroll-padding-top: var\(--th-sticky-top\);\s*\}/, 'focus/anchor scrolling clears the topbar');
  assert.match(reportCss, /\.tl-bulkbar \{\s*position: sticky;\s*top: var\(--th-sticky-top, 0px\);/);
  assert.match(reportCss, /\.tl-table thead th \{\s*position: sticky;\s*top: calc\(var\(--th-sticky-top, 0px\) \+ var\(--tl-sticky-offset, 0px\)\);/);
});

test('modal scroll lock freezes the viewport without re-breaking sticky on <body>', () => {
  assert.match(mainSrc, /html\.modal-scroll-lock \{\s*overflow: hidden !important;\s*\}/);
  assert.match(mainSrc, /body\.modal-scroll-lock \{\s*overflow: hidden !important;\s*overflow: clip !important;\s*\}/);
});
