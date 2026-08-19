import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getIocStatusCardPresentation, normalizeIocLifecycleStatus } from './iocStatusCard.js';

describe('normalizeIocLifecycleStatus', () => {
  it('maps suppression banner to false_positive lifecycle', () => {
    assert.equal(normalizeIocLifecycleStatus('active', { suppressionActive: true }), 'false_positive');
  });

  it('maps suppressed status to false_positive', () => {
    assert.equal(normalizeIocLifecycleStatus('suppressed'), 'false_positive');
  });
});

describe('getIocStatusCardPresentation', () => {
  const activeSummary = {
    status: 'active',
    expires_at: '2026-06-26T16:35:50.000Z',
    expired_at: null,
    expiration_reason: null,
    manual_status_override: false,
    active_source_count: 1,
    expiration_summary: { label: 'Active on 1/1 source · No expiration' }
  };

  const expiredSummary = {
    status: 'expired',
    expires_at: '2026-06-26T16:35:50.000Z',
    expired_at: '2026-05-01T10:00:00.000Z',
    expiration_reason: 'manual',
    manual_status_override: true,
    manual_status: 'expired',
    active_source_count: 0
  };

  it('active IOC shows expires_at only and expire actions', () => {
    const p = getIocStatusCardPresentation(activeSummary);
    assert.equal(p.lifecycle, 'active');
    assert.ok(p.fields.some((f) => f.key === 'expires_at'));
    assert.ok(!p.fields.some((f) => f.key === 'expired_at'));
    assert.ok(!p.fields.some((f) => f.key === 'expiration_reason'));
    assert.deepEqual(p.buttons, ['custom_expire_ioc', 'expire_ioc']);
    assert.ok(!p.buttons.includes('reactivate_ioc'));
  });

  it('shows sources and splits expiration summary secondary text', () => {
    const p = getIocStatusCardPresentation(activeSummary);
    const sources = p.fields.find((f) => f.key === 'sources');
    assert.equal(sources.value, '1 active source');
    const summary = p.fields.find((f) => f.key === 'expiration_summary');
    assert.equal(summary.value, 'Active on 1/1 source');
    assert.equal(summary.secondary, 'No expiration');
  });

  it('does not show empty expiration reason as its own field', () => {
    const p = getIocStatusCardPresentation({
      ...activeSummary,
      expiration_reason: ''
    });
    assert.ok(!p.fields.some((f) => f.key === 'expiration_reason'));
  });

  it('shows reactivated_by_match_at when present', () => {
    const p = getIocStatusCardPresentation({
      status: 'active',
      expires_at: '2026-07-01T00:00:00.000Z',
      reactivated_by_match_at: '2026-06-14T10:00:00.000Z',
      active_source_count: 2
    });
    assert.ok(p.fields.some((f) => f.key === 'reactivated_by_match_at'));
  });

  it('expired IOC shows expired_at only and reactivate actions', () => {
    const p = getIocStatusCardPresentation(expiredSummary);
    assert.equal(p.lifecycle, 'expired');
    assert.ok(p.fields.some((f) => f.key === 'expired_at'));
    assert.ok(!p.fields.some((f) => f.key === 'expires_at'));
    assert.ok(p.buttons.includes('reactivate_ioc'));
    assert.ok(!p.buttons.includes('custom_expire_ioc'));
    assert.ok(!p.buttons.includes('expire_ioc'));
    const override = p.fields.find((f) => f.key === 'manual_override');
    assert.equal(override.value, 'Yes');
    assert.match(override.secondary, /expired/i);
  });

  it('override IOC includes clear override', () => {
    const p = getIocStatusCardPresentation(expiredSummary);
    assert.ok(p.buttons.includes('clear_ioc_override'));
  });

  it('active IOC re-added via a manual source shows Manual Override: No and hides Clear override', () => {
    // Reproduction: expired feed IOC re-added through a manual source. The backend reports
    // manual_status_override=false (source bookkeeping is not a lifecycle override), even
    // though an active manual source exists. The card must not offer to clear an override.
    const p = getIocStatusCardPresentation({
      status: 'active',
      expires_at: '2026-09-18T12:00:00.000Z',
      expired_at: null,
      expiration_reason: null,
      manual_status_override: false,
      active_source_count: 1,
      expiration_summary: { label: 'Active on 1/2 sources · Expires 2026-09-18' }
    });
    const override = p.fields.find((f) => f.key === 'manual_override');
    assert.equal(override.value, 'No');
    assert.equal(override.secondary, 'No override set');
    assert.ok(!p.buttons.includes('clear_ioc_override'));
    assert.deepEqual(p.buttons, ['custom_expire_ioc', 'expire_ioc']);
  });

  it('false positive hides expiration actions', () => {
    const p = getIocStatusCardPresentation(activeSummary, { suppressionActive: true });
    assert.equal(p.lifecycle, 'false_positive');
    assert.equal(p.buttons.length, 0);
    assert.ok(!p.fields.some((f) => f.key === 'expires_at'));
  });
});
