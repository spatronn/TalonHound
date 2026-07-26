/**
 * Structural guards for merging "Recent Runs" into "Job Queue Status".
 *
 * The app has no DOM/component test harness, so these assertions read the
 * app source and verify the wiring that the merge depends on:
 *   - the standalone Recent Runs page / route / menu link are gone
 *   - the Job Queue Status table carries the Finished At + Duration columns
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const mainSrc = readFileSync(
  fileURLToPath(new URL('../main.jsx', import.meta.url)),
  'utf8'
);

test('Recent Runs page component is removed', () => {
  assert.equal(mainSrc.includes('IntegrationsRecentRunsPage'), false);
});

test('Recent Runs route is removed', () => {
  assert.equal(mainSrc.includes('/threat-intelligence/runs'), false);
});

test('Recent Runs sidebar link is removed', () => {
  assert.equal(/>\s*Recent Runs\s*</.test(mainSrc), false);
});

test('Job Queue Status remains routed', () => {
  assert.ok(mainSrc.includes('IntegrationsQueueStatusPage'));
  assert.ok(mainSrc.includes('/threat-intelligence/queue'));
});

test('Job Queue Status table exposes Finished At, Duration, and Result columns', () => {
  assert.ok(mainSrc.includes('>Finished At<'));
  assert.ok(mainSrc.includes('>Duration<'));
  assert.ok(mainSrc.includes('>Result<'));
});

test('Job Queue Status main table does not expose a Reason column', () => {
  assert.equal(mainSrc.includes("startResize('reason'"), false);
  assert.equal(mainSrc.includes(">Reason<div onMouseDown={(e) => startResize('reason'"), false);
  assert.equal(/\breason:\s*\d+/.test(mainSrc.match(/function IntegrationsQueueStatusPage[\s\S]*?setTableWidths\([\s\S]*?\}\);/)?.[0] || ''), false);
});

test('Job Queue Status details still show Reason', () => {
  assert.ok(mainSrc.includes("color: '#94a3b8' }}>Reason</b>"));
  assert.ok(mainSrc.includes('presentQueueJobReason'));
  assert.ok(mainSrc.includes('integrationJobReasonLabel'));
});

test('Job Queue Status wires the duration helpers', () => {
  assert.ok(mainSrc.includes("from './lib/integrationJobDuration.js'"));
  assert.ok(mainSrc.includes('formatJobDuration(computeJobDurationMs(j))'));
});

test('Job Queue Status uses shared result helpers', () => {
  assert.ok(mainSrc.includes("from './lib/jobQueueResult.js'"));
  assert.ok(mainSrc.includes('presentQueueJobResult'));
  assert.ok(mainSrc.includes('presentQueueJobReason'));
});

test('Job Queue Status does not hardcode Completed successfully for success', () => {
  assert.equal(mainSrc.includes("if (state === 'success') return 'Completed successfully'"), false);
});
