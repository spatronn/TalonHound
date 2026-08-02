import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertProviderEnabled,
  guardProviderEnabled,
  runWithProviderEnabled,
  registerEnrichmentProvider,
  getEnrichmentProvider,
  ProviderDisabledError,
  UnknownProviderError,
  providerDisabledPayload
} from './enrichmentProviderRegistry.js';

// Fake pg pool returning a single threat_intel_provider_configs row per provider.
function fakePool(rowsByProvider) {
  return {
    calls: [],
    async query(sql, params) {
      this.calls.push({ sql, params });
      const provider = params?.[0];
      const row = rowsByProvider[provider];
      return { rows: row ? [row] : [] };
    }
  };
}

function fakeRes() {
  return {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; }
  };
}

test('guard blocks a disabled provider and never invokes the external client (two providers)', async () => {
  // VirusTotal row disabled, AbuseIPDB row disabled — different default semantics,
  // same central guard.
  const pool = fakePool({
    virustotal: { enabled: false, api_key: 'vt-key' },
    abuseipdb: { enabled: false, api_key: 'abuse-key' }
  });

  for (const provider of ['virustotal', 'abuseipdb']) {
    let externalCalled = false;
    // Model an execution entry point: guard first, external client second.
    async function runEnrichment() {
      await assertProviderEnabled(pool, provider);
      externalCalled = true; // only reached when enabled
    }
    await assert.rejects(runEnrichment(), (err) => {
      assert.ok(err instanceof ProviderDisabledError);
      assert.equal(err.code, 'PROVIDER_DISABLED');
      assert.equal(err.provider, provider);
      assert.equal(err.httpStatus, 409);
      assert.match(err.userMessage, /provider is disabled\.$/);
      return true;
    });
    assert.equal(externalCalled, false, `${provider}: external client must not be called`);
  }
});

test('guard allows an enabled provider and returns its state', async () => {
  const pool = fakePool({
    virustotal: { enabled: true, api_key: 'vt-key' },
    ipinfo_lite: { enabled: true, api_key: 'ip-token' }
  });

  const vt = await assertProviderEnabled(pool, 'virustotal');
  assert.equal(vt.enabled, true);
  assert.equal(vt.configured, true);

  const ip = await assertProviderEnabled(pool, 'ipinfo_lite');
  assert.equal(ip.enabled, true);
});

test('guardProviderEnabled writes the standard 409 payload and returns false when disabled', async () => {
  const pool = fakePool({ virustotal: { enabled: false, api_key: 'vt-key' } });
  const res = fakeRes();
  const ok = await guardProviderEnabled(pool, 'virustotal', res);
  assert.equal(ok, false);
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.error, 'PROVIDER_DISABLED');
  assert.equal(res.body.provider, 'virustotal');
  assert.equal(res.body.message, 'VirusTotal enrichment provider is disabled.');
  // Back-compat aliases for existing IOC-detail cards.
  assert.equal(res.body.provider_status, 'disabled');
  assert.equal(res.body.status, 'disabled');
});

test('guardProviderEnabled returns true and writes nothing when enabled', async () => {
  const pool = fakePool({ virustotal: { enabled: true, api_key: 'vt-key' } });
  const res = fakeRes();
  const ok = await guardProviderEnabled(pool, 'virustotal', res);
  assert.equal(ok, true);
  assert.equal(res.statusCode, null);
  assert.equal(res.body, null);
});

test('provider-specific enabled defaults are preserved (no row): VT enabled, AbuseIPDB disabled', async () => {
  const pool = fakePool({}); // no rows at all
  // VirusTotal defaults to enabled when no row exists.
  await assert.doesNotReject(assertProviderEnabled(pool, 'virustotal'));
  // AbuseIPDB defaults to disabled when no row exists.
  await assert.rejects(assertProviderEnabled(pool, 'abuseipdb'), ProviderDisabledError);
});

test('a newly registered provider gets the same guard with no execution-site changes', async () => {
  let disabled = true;
  registerEnrichmentProvider({
    key: 'sample_provider',
    displayName: 'Sample Provider',
    // State can come from anywhere — here a closure standing in for a config row.
    loadState: async () => ({ enabled: !disabled, configured: true })
  });

  assert.ok(getEnrichmentProvider('sample_provider'));

  // Disabled → same central guard blocks it, standard message uses the display name.
  await assert.rejects(assertProviderEnabled(null, 'sample_provider'), (err) => {
    assert.ok(err instanceof ProviderDisabledError);
    assert.equal(err.provider, 'sample_provider');
    assert.equal(err.userMessage, 'Sample Provider enrichment provider is disabled.');
    return true;
  });

  // Enable it → guard now allows, still no execution-site code changed.
  disabled = false;
  const state = await assertProviderEnabled(null, 'sample_provider');
  assert.equal(state.enabled, true);
});

test('runWithProviderEnabled runs fn only when enabled, else writes 409 and skips fn', async () => {
  // Enabled → fn runs, result returned, nothing written.
  const enabledPool = fakePool({ virustotal: { enabled: true, api_key: 'k' } });
  const res1 = fakeRes();
  let ran = false;
  const out = await runWithProviderEnabled(enabledPool, 'virustotal', res1, async () => { ran = true; return 'done'; });
  assert.equal(ran, true);
  assert.equal(out, 'done');
  assert.equal(res1.statusCode, null);

  // Disabled → fn is never invoked, standard 409 written, returns undefined.
  const disabledPool = fakePool({ virustotal: { enabled: false, api_key: 'k' } });
  const res2 = fakeRes();
  let ran2 = false;
  const out2 = await runWithProviderEnabled(disabledPool, 'virustotal', res2, async () => { ran2 = true; return 'done'; });
  assert.equal(ran2, false);
  assert.equal(out2, undefined);
  assert.equal(res2.statusCode, 409);
  assert.equal(res2.body.error, 'PROVIDER_DISABLED');
});

test('unknown provider raises UnknownProviderError', async () => {
  await assert.rejects(assertProviderEnabled(null, 'does_not_exist'), (err) => {
    assert.ok(err instanceof UnknownProviderError);
    assert.equal(err.code, 'UNKNOWN_PROVIDER');
    return true;
  });
});

test('providerDisabledPayload shape matches the documented contract', () => {
  const payload = providerDisabledPayload(new ProviderDisabledError('virustotal', 'VirusTotal'));
  assert.deepEqual(payload, {
    error: 'PROVIDER_DISABLED',
    provider: 'virustotal',
    message: 'VirusTotal enrichment provider is disabled.',
    provider_status: 'disabled',
    status: 'disabled'
  });
});
