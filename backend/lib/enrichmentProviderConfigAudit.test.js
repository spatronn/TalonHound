import test from 'node:test';
import assert from 'node:assert/strict';
import { auditProviderConfigUpdate } from './enrichmentProviderConfigAudit.js';

function spyAudit() {
  const calls = [];
  return { calls, auditSuccess: async (event) => { calls.push(event); } };
}

test('records provider id, previous/new enabled, and forwards req for actor capture (two providers)', async () => {
  const audit = spyAudit();
  const req = { user: { username: 'admin1', role: 'admin' } };

  await auditProviderConfigUpdate(audit, req, {
    provider: 'virustotal',
    displayName: 'VirusTotal',
    previousEnabled: true,
    newEnabled: false,
    after: { ttl_hours: 24 },
    metadata: { reason: 'toggle' }
  });
  await auditProviderConfigUpdate(audit, req, {
    provider: 'ipinfo_lite',
    displayName: 'IPinfo Lite',
    previousEnabled: false,
    newEnabled: true
  });

  assert.equal(audit.calls.length, 2);

  const vt = audit.calls[0];
  assert.equal(vt.action, 'enrichment.provider_config.updated');
  assert.equal(vt.entityId, 'virustotal');
  assert.equal(vt.entityDisplay, 'VirusTotal');
  assert.equal(vt.before.enabled, true);
  assert.equal(vt.after.enabled, false);
  assert.equal(vt.after.ttl_hours, 24);
  assert.equal(vt.metadata.provider, 'virustotal');
  assert.equal(vt.metadata.reason, 'toggle');
  assert.equal(vt.req, req, 'req forwarded so auditLogService derives the actor');

  const ip = audit.calls[1];
  assert.equal(ip.entityId, 'ipinfo_lite');
  assert.equal(ip.before.enabled, false);
  assert.equal(ip.after.enabled, true);
});

test('is a no-op when no audit service is provided', async () => {
  await assert.doesNotReject(auditProviderConfigUpdate(null, {}, {
    provider: 'virustotal', displayName: 'VirusTotal', previousEnabled: true, newEnabled: false
  }));
});
