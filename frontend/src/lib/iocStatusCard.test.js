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
    manual_status_override: false
  };

  const expiredSummary = {
    status: 'expired',
    expires_at: '2026-06-26T16:35:50.000Z',
    expired_at: '2026-05-01T10:00:00.000Z',
    expiration_reason: 'manual',
    manual_status_override: true,
    manual_status: 'expired'
  };

  it('active IOC shows expires_at only and expire actions', () => {
    const p = getIocStatusCardPresentation(activeSummary);
    assert.equal(p.lifecycle, 'active');
    assert.ok(p.fields.some((f) => f.key === 'expires_at'));
    assert.ok(!p.fields.some((f) => f.key === 'expired_at'));
    assert.deepEqual(p.buttons, ['custom_expire_ioc', 'expire_ioc']);
    assert.ok(!p.buttons.includes('reactivate_ioc'));
  });

  it('expired IOC shows expired_at only and reactivate actions', () => {
    const p = getIocStatusCardPresentation(expiredSummary);
    assert.equal(p.lifecycle, 'expired');
    assert.ok(p.fields.some((f) => f.key === 'expired_at'));
    assert.ok(!p.fields.some((f) => f.key === 'expires_at'));
    assert.ok(p.buttons.includes('reactivate_ioc'));
    assert.ok(!p.buttons.includes('expire_ioc'));
  });

  it('override IOC includes clear override', () => {
    const p = getIocStatusCardPresentation(expiredSummary);
    assert.ok(p.buttons.includes('clear_ioc_override'));
  });

  it('false positive hides expiration actions', () => {
    const p = getIocStatusCardPresentation(activeSummary, { suppressionActive: true });
    assert.equal(p.lifecycle, 'false_positive');
    assert.equal(p.buttons.length, 0);
    assert.ok(!p.fields.some((f) => f.key === 'expires_at'));
  });
});
