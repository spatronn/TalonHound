/**
 * Source contract for the narrow-viewport navigation toggle in AppShell.
 * The open/close controls once rendered a literal "?" (non-ASCII glyphs lost
 * in an encoding round-trip); they must render the shared SVG nav icons and
 * expose the drawer state to assistive technology.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const mainSrc = readFileSync(path.join(here, '..', 'main.jsx'), 'utf8');
const iconsSrc = readFileSync(path.join(here, '..', 'components', 'NavIcons.jsx'), 'utf8');

function elementSource(src, marker) {
  const at = src.indexOf(marker);
  assert.ok(at >= 0, `${marker} is rendered`);
  const start = src.lastIndexOf('<button', at);
  const end = src.indexOf('</button>', at);
  return src.slice(start, end + '</button>'.length);
}

test('NavIcons provides menu and close icons as inline SVG (no icon font / extra dependency)', () => {
  assert.match(iconsSrc, /\n  menu: \(\s*<Icon>[\s\S]*?<path d="M4 6h16" \/>[\s\S]*?<\/Icon>\s*\)/);
  assert.match(iconsSrc, /\n  close: \(\s*<Icon>[\s\S]*?<path d="M18 6 6 18" \/>[\s\S]*?<\/Icon>\s*\)/);
});

test('topbar trigger is a real toggle button that renders the menu icon', () => {
  const btn = elementSource(mainSrc, 'className="mobile-menu-btn"');
  assert.match(btn, /type="button"/);
  assert.match(btn, /onClick=\{\(\) => setIsMobileNavOpen\(\(v\) => !v\)\}/, 'still toggles the drawer');
  assert.match(btn, /aria-label=\{isMobileNavOpen \? 'Close navigation' : 'Open navigation'\}/);
  assert.match(btn, /aria-expanded=\{isMobileNavOpen\}/);
  assert.match(btn, /aria-controls="app-sidebar"/);
  assert.match(btn, />\s*\{NavIcons\.menu\}\s*<\/button>/);
  assert.match(mainSrc, /<aside id="app-sidebar" className=\{`sidebar\$\{isMobileNavOpen \? ' sidebar--open' : ''\}`\}/, 'aria-controls target exists');
});

test('drawer close button renders the close icon', () => {
  const btn = elementSource(mainSrc, 'aria-label="Close navigation">{NavIcons.close}');
  assert.match(btn, /type="button"/);
  assert.match(btn, /onClick=\{\(\) => setIsMobileNavOpen\(false\)\}/);
});

test('no control renders a bare "?" glyph as its only content', () => {
  assert.doesNotMatch(mainSrc, /<button[^>]*>\s*\?\s*<\/button>/);
  assert.doesNotMatch(mainSrc, /\? '\?' : ''/, 'busy indicators use an ellipsis, not a lost-glyph "?"');
});
