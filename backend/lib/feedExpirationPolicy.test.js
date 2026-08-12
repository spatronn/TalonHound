import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveExpirationPolicy,
  normalizeIocTypeForPolicy,
  validateExpirationTypePolicies
} from './feedExpirationPolicy.js';

describe('resolveExpirationPolicy', () => {
  const feedDefault = { enabled: true, mode: 'fixed_ttl', ttlDays: 30 };

  it('1. domain override fixed_ttl 90 → enabled, ttlDays=90, type_override', () => {
    const r = resolveExpirationPolicy(feedDefault, { mode: 'fixed_ttl', ttl_days: 90 });
    assert.deepEqual(r, { enabled: true, ttlDays: 90, source: 'type_override' });
  });

  it('2. url override fixed_ttl 40 → enabled, ttlDays=40, type_override', () => {
    const r = resolveExpirationPolicy(feedDefault, { mode: 'fixed_ttl', ttl_days: 40 });
    assert.deepEqual(r, { enabled: true, ttlDays: 40, source: 'type_override' });
  });

  it('3. file_hash override no_expire → disabled, type_override', () => {
    const r = resolveExpirationPolicy(feedDefault, { mode: 'no_expire', ttl_days: null });
    assert.deepEqual(r, { enabled: false, ttlDays: null, source: 'type_override' });
  });

  it('4. ip override inherit → falls back to feed default', () => {
    const r = resolveExpirationPolicy(feedDefault, { mode: 'inherit', ttl_days: null });
    assert.deepEqual(r, { enabled: true, ttlDays: 30, source: 'feed_default' });
  });

  it('5. missing override (null) → falls back to feed default', () => {
    const r = resolveExpirationPolicy(feedDefault, null);
    assert.deepEqual(r, { enabled: true, ttlDays: 30, source: 'feed_default' });
  });

  it('6. feed default disabled, no override → disabled', () => {
    const r = resolveExpirationPolicy({ enabled: false, mode: 'never', ttlDays: null }, null);
    assert.deepEqual(r, { enabled: false, ttlDays: null, source: 'feed_default' });
  });

  it('7. fixed_ttl override with null ttl_days → gracefully falls back to feed default', () => {
    const r = resolveExpirationPolicy(feedDefault, { mode: 'fixed_ttl', ttl_days: null });
    assert.deepEqual(r, { enabled: true, ttlDays: 30, source: 'feed_default' });
  });
});

describe('normalizeIocTypeForPolicy', () => {
  it('maps concrete hash types to file_hash', () => {
    for (const t of ['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh', 'hash', 'file_hash']) {
      assert.equal(normalizeIocTypeForPolicy(t), 'file_hash', `expected ${t} → file_hash`);
    }
  });

  it('normalizes ip variants', () => {
    assert.equal(normalizeIocTypeForPolicy('ip'), 'ip');
    assert.equal(normalizeIocTypeForPolicy('ip6'), 'ip');
    assert.equal(normalizeIocTypeForPolicy('ipv4'), 'ip');
  });

  it('passes through domain/url and rejects unknown', () => {
    assert.equal(normalizeIocTypeForPolicy('domain'), 'domain');
    assert.equal(normalizeIocTypeForPolicy('url'), 'url');
    assert.equal(normalizeIocTypeForPolicy('mutex'), null);
    assert.equal(normalizeIocTypeForPolicy(''), null);
  });
});

describe('validateExpirationTypePolicies', () => {
  it('accepts null/undefined (no overrides supplied)', () => {
    const r = validateExpirationTypePolicies(undefined);
    assert.equal(r.ok, true);
    assert.deepEqual(r.normalized, []);
  });

  it('accepts a valid mixed list and nulls ttl for non-fixed modes', () => {
    const r = validateExpirationTypePolicies([
      { ioc_type: 'domain', mode: 'fixed_ttl', ttl_days: 90 },
      { ioc_type: 'file_hash', mode: 'no_expire', ttl_days: 5 },
      { ioc_type: 'ip', mode: 'inherit' }
    ]);
    assert.equal(r.ok, true);
    assert.deepEqual(r.normalized, [
      { ioc_type: 'domain', mode: 'fixed_ttl', ttl_days: 90 },
      { ioc_type: 'file_hash', mode: 'no_expire', ttl_days: null },
      { ioc_type: 'ip', mode: 'inherit', ttl_days: null }
    ]);
  });

  it('rejects fixed_ttl without a positive ttl_days', () => {
    const r = validateExpirationTypePolicies([{ ioc_type: 'url', mode: 'fixed_ttl', ttl_days: 0 }]);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('ttl_days')));
  });

  it('rejects last_seen_ttl as a type override mode', () => {
    const r = validateExpirationTypePolicies([
      { ioc_type: 'domain', mode: 'last_seen_ttl', ttl_days: 30 }
    ]);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('must be one of')));
  });

  it('rejects unknown ioc_type and duplicate entries', () => {
    assert.equal(validateExpirationTypePolicies([{ ioc_type: 'mutex', mode: 'inherit' }]).ok, false);
    const dup = validateExpirationTypePolicies([
      { ioc_type: 'ip', mode: 'inherit' },
      { ioc_type: 'ip', mode: 'no_expire' }
    ]);
    assert.equal(dup.ok, false);
  });
});
