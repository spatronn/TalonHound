/**
 * Additional IOC Sources: selective auto-discovery may insert `discovered`
 * rows, but analysis / retry / refresh must never attach, extract, or approve.
 * The only analyst creation entry point remains Add Source URL.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, '../../..');

function sourceFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(full, out);
    else if (/\.(c|m)?js$/.test(entry.name) && !/\.test\.(c|m)?js$/.test(entry.name)) out.push(full);
  }
  return out;
}

const runtimeFiles = [
  ...sourceFiles(path.join(backendRoot, 'lib')),
  ...sourceFiles(path.join(backendRoot, 'routes')),
  ...sourceFiles(path.join(backendRoot, 'services')),
  ...sourceFiles(path.join(backendRoot, 'scripts')),
  ...fs.readdirSync(backendRoot).filter((f) => f.endsWith('.js')).map((f) => path.join(backendRoot, f))
];
const read = (f) => fs.readFileSync(f, 'utf8');
const rel = (f) => path.relative(backendRoot, f).replace(/\\/g, '/');

test('discovery modules exist and pipeline may invoke discovery only', () => {
  assert.equal(fs.existsSync(path.join(here, 'discover.js')), true);
  assert.equal(fs.existsSync(path.join(here, 'runDiscovery.js')), true);
  const pipeline = read(path.join(here, '..', 'pipeline.js'));
  assert.match(pipeline, /runIocSourceDiscoveryForReport/);
  assert.doesNotMatch(pipeline, /extractIocSource|inspectIocSource|transitionSource\([^)]*'approve'/);
});

test('IOC Source INSERT writers are manual create + discovery upsert only', () => {
  const inserts = runtimeFiles.filter((f) => /INSERT INTO threat_report_ioc_sources\b/.test(read(f)));
  assert.deepEqual(inserts.map(rel).sort(), [
    'lib/threatLibrary/iocSources/discover.js',
    'lib/threatLibrary/iocSources/store.js'
  ]);
  const store = read(path.join(here, 'store.js'));
  const fn = store.slice(store.indexOf('export async function createManualIocSource('));
  const body = fn.slice(0, fn.indexOf('\n}\n'));
  assert.match(body, /INSERT INTO threat_report_ioc_sources/);
  assert.match(body, /'manual'/);
  assert.doesNotMatch(body, /'auto'/);

  const discover = read(path.join(here, 'discover.js'));
  assert.match(discover, /upsertDiscoveredSources/);
  assert.match(discover, /discovery_method \|\| 'auto'/);
  assert.match(discover, /IOC_SOURCE_LIFECYCLE\.DISCOVERED/);
});

test('report import / analysis / refresh paths never attach or extract IOC Sources', () => {
  for (const file of ['pipeline.js', 'extractionRefresh.js', 'extractionStages.js', 'urlIngest.js', 'pdfIngest.js', 'thibImport.js']) {
    const src = read(path.join(here, '..', file));
    assert.doesNotMatch(src, /extractIocSource|inspectIocSource/, file);
    assert.doesNotMatch(src, /(UPDATE|DELETE FROM)\s+threat_report_ioc_sources/, file);
  }
  // Analysis + refresh may discover; the worker process itself does not.
  const worker = read(path.join(backendRoot, 'threat-library-worker.js'));
  assert.doesNotMatch(worker, /runIocSourceDiscoveryForReport/);
  const refresh = read(path.join(here, '..', 'extractionRefresh.js'));
  assert.match(refresh, /runIocSourceDiscoveryForReport/);
});

test('the Add Source URL route stays the manual creation entry point and checks intelligence before queueing', () => {
  const routes = read(path.join(backendRoot, 'routes/threatLibrary.js'));
  const start = routes.indexOf("'/api/threat-library/reports/:publicId/ioc-sources',\n    requireRole");
  assert.ok(start > 0, 'POST /reports/:id/ioc-sources exists');
  const block = routes.slice(start, routes.indexOf('app.get(', start));
  const intel = block.indexOf('assessIocSourceDestination');
  const create = block.indexOf('createManualIocSource');
  const blocked = block.indexOf('THREAT_LIBRARY_IOC_SOURCE_BLOCKED');
  const queue = block.indexOf('queueIocSourceJob');
  assert.ok(intel > 0 && create > intel && blocked > create && queue > blocked, 'intel -> record -> blocked audit (return) -> queue');
  assert.match(block.slice(blocked, queue), /return res\.status\(422\)/, 'a blocked source is never queued for inspection');
});

test('IOC Source lifecycle stamps the analyst public id that resolveActor returns (publicId)', () => {
  const routes = read(path.join(backendRoot, 'routes/threatLibrary.js'));
  assert.doesNotMatch(routes, /(requestedBy|_by): actor\?\.public_id/, 'resolveActor exposes publicId, not public_id');
  assert.match(routes, /approved_by: actorPublicId\(actor\)/);
  assert.match(routes, /dismissed_by: actorPublicId\(actor\)/);
  assert.match(routes, /function actorPublicId\(actor\) \{\s*return actor\?\.publicId \|\| actor\?\.public_id \|\| null;/);
});
