import test from 'node:test';
import assert from 'node:assert/strict';
import { normEventSourceType } from './eventSourceNorm.js';

test('generic source_type with bind_dns raw classifies as dns', () => {
  const family = normEventSourceType({
    source_type: 'generic',
    parser_source: 'syslog',
    raw_log_snapshot: 'client 10.0.0.5#52341: query: evil.example.com IN A'
  });
  assert.equal(family, 'dns');
});

test('generic source_type with squid proxy raw classifies as proxy', () => {
  const family = normEventSourceType({
    source_type: 'generic',
    parser_source: 'syslog',
    raw_log_snapshot: '10.0.0.5 TCP_MISS/200 512 CONNECT evil.example.com:443'
  });
  assert.equal(family, 'proxy');
});

test('explicit dns source_type stays dns', () => {
  assert.equal(normEventSourceType({ source_type: 'dns' }), 'dns');
});
