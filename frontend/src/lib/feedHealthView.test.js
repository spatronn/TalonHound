/**
 * Structural guards for Feeds operational health table.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const mainSrc = readFileSync(
  fileURLToPath(new URL('../main.jsx', import.meta.url)),
  'utf8'
);

test('Feeds table uses Last Result column', () => {
  assert.ok(mainSrc.includes('>Last Result<'));
  assert.equal(mainSrc.includes('>Last Run Metrics<'), false);
});

test('Feeds summary cards are operational-health oriented', () => {
  assert.ok(mainSrc.includes('>Healthy<'));
  assert.ok(mainSrc.includes('>Needs Attention<'));
  assert.ok(mainSrc.includes('>Running / Queued<'));
  assert.equal(mainSrc.includes('>Last Run Processed<'), false);
  assert.equal(mainSrc.includes('>Failing Feeds<'), false);
});

test('Feeds health presentation labels Healthy / Never run', () => {
  assert.ok(mainSrc.includes("label: 'Healthy'"));
  assert.ok(mainSrc.includes("label: 'Never run'"));
});

test('Feeds wires feedLastResult helpers', () => {
  assert.ok(mainSrc.includes("from './lib/feedLastResult.js'"));
  assert.ok(mainSrc.includes('presentFeedLastResult'));
  assert.ok(mainSrc.includes('resolveFeedLastResult'));
});

test('Edit detail distinguishes Filtered from Failed/Rejected', () => {
  assert.ok(mainSrc.includes('Filtered:'));
  assert.ok(mainSrc.includes('Failed/Rejected:'));
  assert.ok(mainSrc.includes('FEED_RESULT_METRIC_TOOLTIPS.filtered'));
  assert.equal(mainSrc.includes('title={FEED_RESULT_METRIC_TOOLTIPS.rejected}>Rejected:'), false);
});

test('USOM compact last/next run helpers remain', () => {
  assert.ok(mainSrc.includes('formatFeedLastRunCell'));
  assert.ok(mainSrc.includes('Incremental ·'));
  assert.ok(mainSrc.includes('Last full sync'));
});
