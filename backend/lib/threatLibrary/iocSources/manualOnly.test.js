/**
 * Additional IOC Sources are manual-only. No import, analysis, retry, re-run,
 * refresh, worker or scheduled path may create IOC Source rows; the only
 * writer is the explicit Add Source URL action (createManualIocSource).
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

test('automatic discovery modules are gone and nothing references them', () => {
  assert.equal(fs.existsSync(path.join(here, 'discover.js')), false);
  assert.equal(fs.existsSync(path.join(here, 'runDiscovery.js')), false);
  const offenders = runtimeFiles.filter((f) => /runIocSourceDiscoveryForReport|discoverIocSourcesFrom(Html|Text)|upsertDiscoveredSources|iocSources\/(discover|runDiscovery)\.js/.test(read(f)));
  assert.deepEqual(offenders.map(rel), []);
});

test('the only IOC Source insert is the manual Add Source URL action', () => {
  const inserts = runtimeFiles.filter((f) => /INSERT INTO threat_report_ioc_sources\b/.test(read(f)));
  assert.deepEqual(inserts.map(rel), ['lib/threatLibrary/iocSources/store.js']);
  const store = read(path.join(here, 'store.js'));
  const fn = store.slice(store.indexOf('export async function createManualIocSource('));
  const body = fn.slice(0, fn.indexOf('\n}\n'));
  assert.match(body, /INSERT INTO threat_report_ioc_sources/);
  assert.match(body, /'manual'/, 'rows are created with manual provenance');
  assert.doesNotMatch(body, /'auto'/);
  assert.equal(store.split('INSERT INTO threat_report_ioc_sources').length - 1, 1);
});

test('report import / analysis / retry / re-run / refresh paths never touch IOC Sources', () => {
  for (const file of ['pipeline.js', 'extractionRefresh.js', 'extractionStages.js', 'urlIngest.js', 'pdfIngest.js', 'thibImport.js']) {
    const src = read(path.join(here, '..', file));
    assert.doesNotMatch(src, /['"]\.\/iocSources\//, `${file} imports no IOC Source module (static or dynamic)`);
    assert.doesNotMatch(src, /(INSERT INTO|UPDATE|DELETE FROM)\s+threat_report_ioc_sources/, file);
  }
  const worker = read(path.join(backendRoot, 'threat-library-worker.js'));
  assert.doesNotMatch(worker, /discover/i);
});

test('the Add Source URL route stays the creation entry point and checks intelligence before queueing', () => {
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
