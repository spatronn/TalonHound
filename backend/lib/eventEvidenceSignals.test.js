import test from 'node:test';
import assert from 'node:assert/strict';
import {
  rawLooksLikeSquidOrHttpProxy,
  inferEventFamilyFromRow,
  isProxyFailedEvent,
  isProxyAccessObservedEvent,
  isSubstantiveDnsEvent
} from './eventEvidenceSignals.js';

test('squid CONNECT TCP_TUNNEL/503 is proxy failed not access observed', () => {
  const raw = 'squid-access: 192.168.1.8 TCP_TUNNEL/503 0 CONNECT evil.example.com:443 -';
  const row = { raw_log_snapshot: raw, source_type: 'generic', parser_source: 'unknown' };

  assert.equal(rawLooksLikeSquidOrHttpProxy(raw), true);
  assert.equal(inferEventFamilyFromRow(row), 'proxy');
  assert.equal(isProxyFailedEvent(row), true);
  assert.equal(isProxyAccessObservedEvent(row), false);
});

test('substantive dns requires query/resolution payload', () => {
  assert.equal(isSubstantiveDnsEvent({
    source_type: 'dns',
    parser_source: 'syslog_observables',
    raw_log_snapshot: ''
  }), false);

  assert.equal(isSubstantiveDnsEvent({
    source_type: 'dns',
    parser_source: 'bind_dns',
    raw_log_snapshot: 'client 10.0.0.5#52341: query: evil.example.com IN A'
  }), true);
});
