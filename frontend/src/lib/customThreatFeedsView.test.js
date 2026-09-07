import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  isCustomFeedEnabled,
  summarizeCustomThreatFeeds,
  customFeedStatePresentation,
  customFeedLastResultPresentation,
  customFeedMetadataParts
} from './customThreatFeedsView.js';

const feed = (o = {}) => ({ active: true, ...o });

describe('isCustomFeedEnabled', () => {
  test('true when active and not archived', () => {
    assert.equal(isCustomFeedEnabled(feed()), true);
  });
  test('false when disabled or archived', () => {
    assert.equal(isCustomFeedEnabled(feed({ active: false })), false);
    assert.equal(isCustomFeedEnabled(feed({ archived_at: '2026-01-01' })), false);
  });
});

describe('summarizeCustomThreatFeeds', () => {
  test('counts total/enabled/needs-attention/running from real statuses', () => {
    const s = summarizeCustomThreatFeeds([
      feed({ last_run_status: 'success' }),
      feed({ last_run_status: 'failed' }),
      feed({ last_run_status: 'partial_success' }),
      feed({ active: false, last_run_status: 'success' }),
      feed({ last_run_status: 'running' }),
      feed({ last_run_status: 'queued' }),
      feed({ last_run_status: null })
    ]);
    assert.equal(s.total, 7);
    assert.equal(s.enabled, 6);            // all except the disabled one
    assert.equal(s.needs_attention, 2);    // failed + partial_success
    assert.equal(s.running_queued, 2);     // running + queued
  });
  test('archived feed is not counted as enabled', () => {
    const s = summarizeCustomThreatFeeds([feed({ archived_at: '2026-01-01', last_run_status: 'success' })]);
    assert.equal(s.enabled, 0);
  });
  test('handles empty / non-array input', () => {
    assert.deepEqual(summarizeCustomThreatFeeds([]), { total: 0, enabled: 0, needs_attention: 0, running_queued: 0 });
    assert.deepEqual(summarizeCustomThreatFeeds(null), { total: 0, enabled: 0, needs_attention: 0, running_queued: 0 });
  });
});

describe('customFeedStatePresentation', () => {
  test('enabled / disabled / archived', () => {
    assert.deepEqual(customFeedStatePresentation(feed()), { label: 'Enabled', kind: 'enabled' });
    assert.deepEqual(customFeedStatePresentation(feed({ active: false })), { label: 'Disabled', kind: 'disabled' });
    assert.deepEqual(customFeedStatePresentation(feed({ archived_at: 'x' })), { label: 'Archived', kind: 'archived' });
  });
});

describe('customFeedLastResultPresentation', () => {
  test('success', () => {
    const r = customFeedLastResultPresentation(feed({ last_run_status: 'success' }));
    assert.equal(r.primary, 'Completed');
    assert.equal(r.tone, 'success');
  });
  test('failed shows truncated error + full tooltip', () => {
    const longErr = 'x'.repeat(200);
    const r = customFeedLastResultPresentation(feed({ last_run_status: 'failed', last_error: longErr }));
    assert.ok(r.primary.startsWith('Failed · '));
    assert.ok(r.primary.length < 80);       // truncated for the cell
    assert.equal(r.tone, 'danger');
    assert.equal(r.title, longErr);         // full error preserved in tooltip
  });
  test('failed without error text', () => {
    const r = customFeedLastResultPresentation(feed({ last_run_status: 'failed' }));
    assert.equal(r.primary, 'Failed');
    assert.equal(r.tone, 'danger');
  });
  test('partial / running / queued / never', () => {
    assert.equal(customFeedLastResultPresentation(feed({ last_run_status: 'partial_success' })).tone, 'warning');
    assert.equal(customFeedLastResultPresentation(feed({ last_run_status: 'running' })).primary, 'Running');
    assert.equal(customFeedLastResultPresentation(feed({ last_run_status: 'queued' })).primary, 'Queued');
    assert.equal(customFeedLastResultPresentation(feed({ last_run_status: null })).primary, 'Never run');
  });
});

describe('customFeedMetadataParts', () => {
  test('assembles compact secondary line, omitting missing values', () => {
    const parts = customFeedMetadataParts(feed({
      url_host: 'raw.githubusercontent.com',
      format: 'auto',
      ioc_type_mode: 'auto',
      default_confidence: 'medium',
      expiration_summary: '365d'
    }));
    assert.deepEqual(parts, ['raw.githubusercontent.com', 'auto', 'auto', 'Medium', '365d']);
  });
  test('shows fixed IOC type when set', () => {
    const parts = customFeedMetadataParts(feed({ ioc_type_mode: 'fixed', fixed_ioc_type: 'domain' }));
    assert.ok(parts.includes('fixed (domain)'));
  });
  test('omits blanks', () => {
    const parts = customFeedMetadataParts(feed({ url_host: 'h.example.com' }));
    assert.deepEqual(parts, ['h.example.com']);
  });
});
