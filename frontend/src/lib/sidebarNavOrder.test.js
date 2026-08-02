/**
 * Structural guards for sidebar information architecture.
 *
 * No DOM harness — parse the AppShell <nav> in main.jsx and assert
 * section order, item placement, stable routes, and no duplicate links.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const mainSrc = readFileSync(
  fileURLToPath(new URL('../main.jsx', import.meta.url)),
  'utf8'
);

function extractSidebarNav(src) {
  const start = src.indexOf('<nav className="sidebar-nav">');
  assert.ok(start >= 0, 'sidebar-nav not found');
  const end = src.indexOf('</nav>', start);
  assert.ok(end > start, 'sidebar-nav closing tag not found');
  return src.slice(start, end + '</nav>'.length);
}

function sectionLabels(navSrc) {
  return [...navSrc.matchAll(/sidebar-nav-section-label">([^<]+)</g)].map((m) => m[1]);
}

function decodeLabel(label) {
  return label.replace(/&amp;/g, '&');
}

function linkEntries(navSrc) {
  const entries = [];
  const re = /to="([^"]+)"[\s\S]*?<span>([^<]+)<\/span>/g;
  let m;
  while ((m = re.exec(navSrc)) !== null) {
    entries.push({ to: m[1], label: decodeLabel(m[2]) });
  }
  return entries;
}

function labelsInSection(navSrc, sectionLabel) {
  const sections = navSrc.split(/<div className="sidebar-nav-section">/).slice(1);
  const target = sections.find((s) =>
    s.includes(`sidebar-nav-section-label">${sectionLabel}<`)
  );
  assert.ok(target, `section "${sectionLabel}" not found`);
  return linkEntries(target).map((e) => e.label);
}

const navSrc = extractSidebarNav(mainSrc);

const EXPECTED_SECTIONS = ['Operations', 'Threat Intelligence', 'Administration', 'System'];

const EXPECTED_ITEMS = {
  Operations: ['IOC List', 'Add IOC', 'IOC Suppressions', 'Action Center'],
  'Threat Intelligence': [
    'Feeds',
    'Custom Threat Feeds',
    'Published Feeds',
    'IOC Sources',
    'Threat Actors',
    'Threat Classifications',
    'Tags',
    'Enrichment Providers'
  ],
  Administration: ['Users', 'API Keys', 'Audit Logs'],
  System: ['Settings', 'Job Queue Status', 'Backup & Restore']
};

const EXPECTED_ROUTES = {
  'IOC List': '/ioc',
  'Add IOC': '/ioc/new',
  'IOC Suppressions': '/operations/ioc-suppressions',
  'Action Center': '/action-center',
  Feeds: '/threat-intelligence/feeds',
  'Custom Threat Feeds': '/threat-intelligence/custom-threat-feeds',
  'Published Feeds': '/threat-intelligence/published-feeds',
  'IOC Sources': '/administration/ioc-sources',
  'Threat Actors': '/administration/threat-actors',
  'Threat Classifications': '/administration/threat-classifications',
  Tags: '/administration/tags',
  'Enrichment Providers': '/administration/enrichment-providers',
  Users: '/administration/users',
  'API Keys': '/administration/api-keys',
  'Audit Logs': '/administration/audit-logs',
  Settings: '/administration',
  'Job Queue Status': '/threat-intelligence/queue',
  'Backup & Restore': '/administration/backup-restore'
};

test('sidebar sections follow target IA order', () => {
  assert.deepEqual(sectionLabels(navSrc), EXPECTED_SECTIONS);
});

test('sidebar items match target IA order per section', () => {
  for (const [section, expected] of Object.entries(EXPECTED_ITEMS)) {
    assert.deepEqual(
      labelsInSection(navSrc, section),
      expected,
      `section "${section}" item order`
    );
  }
});

test('sidebar links keep prior routes', () => {
  const byLabel = Object.fromEntries(linkEntries(navSrc).map((e) => [e.label, e.to]));
  for (const [label, path] of Object.entries(EXPECTED_ROUTES)) {
    assert.equal(byLabel[label], path, `route for "${label}"`);
  }
});

test('sidebar has no duplicate menu labels or routes', () => {
  const entries = linkEntries(navSrc);
  const labels = entries.map((e) => e.label);
  const routes = entries.map((e) => e.to);
  assert.equal(new Set(labels).size, labels.length, 'duplicate labels');
  assert.equal(new Set(routes).size, routes.length, 'duplicate routes');
});

test('admin-gated items retain isAdmin conditions', () => {
  const gated = [
    ['/administration/users', 'Users'],
    ['/administration/ioc-sources', 'IOC Sources'],
    ['/administration/threat-actors', 'Threat Actors'],
    ['/administration/threat-classifications', 'Threat Classifications'],
    ['/administration/backup-restore', 'Backup &amp; Restore']
  ];
  for (const [path, label] of gated) {
    const re = new RegExp(
      String.raw`\{isAdmin \? <Link to="${path.replace(/\//g, '\\/')}"[\s\S]*?<span>${label}</span></Link> : null\}`
    );
    assert.ok(re.test(navSrc), `isAdmin gate for ${label}`);
  }
});
