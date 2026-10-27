import test from 'node:test';
import assert from 'node:assert/strict';
import { inferObservableType, resolveIocStorageIdentity } from '../manualIocCreate.js';
import { iocStorageIdentity } from './promotion.js';
import { parseTxtFeedContent } from '../customThreatFeedParser.js';
import { classifyStoredNetworkRow, planHistoricalTypeRepair } from '../iocTypeIntegrity.js';

const REPORT = '3ba72c2e-4b68-4128-b101-489489ce83b3';
const V6 = '2001:db8::1';

function tlRow(overrides = {}) {
  return {
    id: 10,
    observable_type: 'domain',
    observable: V6,
    source_name: 'Threat_Library',
    created_origin: 'manual_add',
    note: `Threat Library report ${REPORT}: unknown (malicious)`,
    candidate_type: 'ipv6',
    normalized_value: V6,
    review_status: 'approved',
    matched_ioc_id: 10,
    matched_ioc_observable_type: 'domain',
    report_public_id: REPORT,
    ...overrides
  };
}

test('legacy inference stores an IPv6 address as a domain; storage identity does not', () => {
  assert.equal(inferObservableType(V6), 'domain');
  assert.equal(inferObservableType('198.51.100.0/24'), 'url');
  const v6 = resolveIocStorageIdentity(V6);
  assert.equal(v6.ok, true);
  assert.equal(v6.type, 'ipv6');
  assert.equal(v6.value, V6);
  const cidr = resolveIocStorageIdentity('198.51.100.5/24');
  assert.equal(cidr.type, 'ip');
  assert.equal(cidr.value, '198.51.100.0/24');
  assert.deepEqual(iocStorageIdentity({ candidate_type: 'ipv6', normalized_value: '2001:DB8::1' }), {
    type: 'ipv6',
    value: V6
  });
});

test('classifier confirms network values stored as the wrong type and ignores real domains and URLs', () => {
  const ipv6 = classifyStoredNetworkRow({ observable_type: 'domain', observable: V6 });
  assert.equal(ipv6.confirmed, true);
  assert.equal(ipv6.defect, 'ipv6_host_as_domain');
  assert.equal(ipv6.expected_type, 'ipv6');

  const cidr = classifyStoredNetworkRow({ observable_type: 'url', observable: '198.51.100.0/24' });
  assert.equal(cidr.confirmed, true);
  assert.equal(cidr.defect, 'ip_cidr_as_url');
  assert.equal(cidr.expected_type, 'ip');

  const v4 = classifyStoredNetworkRow({ observable_type: 'domain', observable: '203.0.113.8' });
  assert.equal(v4.confirmed, true);
  assert.equal(v4.defect, 'ip_host_as_domain');

  assert.equal(classifyStoredNetworkRow({ observable_type: 'ipv6', observable: V6 }), null);
  assert.equal(classifyStoredNetworkRow({ observable_type: 'domain', observable: 'evil.example' }), null);
  assert.equal(classifyStoredNetworkRow({ observable_type: 'url', observable: 'http://203.0.113.8/path' }), null);
  assert.equal(classifyStoredNetworkRow({ observable_type: 'url', observable: 'evil.example/path' }), null);
  assert.equal(classifyStoredNetworkRow({ observable_type: 'domain', observable: 'not an ip' }), null);

  const drift = classifyStoredNetworkRow({ observable_type: 'ipv6', observable: '2001:DB8::1' });
  assert.equal(drift.confirmed, false);
  assert.equal(drift.canonical, V6);
});

test('repair plan retypes only a corroborated Threat Library IPv6 and leaves other mismatches', () => {
  const plan = planHistoricalTypeRepair(tlRow());
  assert.equal(plan.action, 'retype');
  assert.equal(plan.change, true);
  assert.equal(plan.canonical, V6);

  const blocked = planHistoricalTypeRepair(tlRow(), { collision: true });
  assert.equal(blocked.action, 'blocked');
  assert.equal(blocked.change, false);

  const usom = planHistoricalTypeRepair({
    id: 3,
    observable_type: 'domain',
    observable: '203.0.113.8',
    source_name: 'USOM:TR-CERT',
    created_origin: null,
    note: 'Auto-imported from Siber Güvenlik Başkanlığı / USOM'
  });
  assert.equal(usom.action, 'out_of_scope');
  assert.equal(usom.change, false);

  assert.equal(planHistoricalTypeRepair(tlRow({ review_status: 'pending' })).action, 'out_of_scope');
  assert.equal(planHistoricalTypeRepair(tlRow({ candidate_type: 'domain' })).action, 'out_of_scope');
  assert.equal(planHistoricalTypeRepair(tlRow({ normalized_value: 'other.example' })).action, 'out_of_scope');
  assert.equal(planHistoricalTypeRepair({ observable_type: 'domain', observable: 'evil.example' }).action, 'unchanged');
});

test('custom feed auto mode stores IPv6 and CIDR as network IOCs, not domain or URL', () => {
  const parsed = parseTxtFeedContent(
    '2001:DB8::1\n198.51.100.5/24\nevil.example\nhttp://evil.example/a\n198.51.100.0/99\n',
    { iocTypeMode: 'auto' }
  );
  const byType = Object.fromEntries(parsed.valid.map((row) => [row.observable, row.observableType]));
  assert.equal(byType['2001:db8::1'], 'ipv6');
  assert.equal(byType['198.51.100.0/24'], 'ip');
  assert.equal(byType['evil.example'], 'domain');
  assert.equal(byType['http://evil.example/a'], 'url');
  assert.equal(parsed.invalidRows.length, 1);

  const explicit = parseTxtFeedContent('evil.example\n', { iocTypeMode: 'fixed', fixedIocType: 'domain' });
  assert.equal(explicit.valid[0].observableType, 'domain');
});
