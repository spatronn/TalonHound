import test from 'node:test';
import assert from 'node:assert/strict';
import {
  filterRetroRowsWithRealtimeDuplicates,
  filterRetroRowsPresentAtIngest,
  isRealtimeEquivalentForRetro,
  normalizeRetroSourceType,
  shouldSkipRetroBecauseIocPresentAtIngest
} from './iocRetroDedup.js';

test('retro source type normalizes generic bind DNS realtime as DNS', () => {
  assert.equal(normalizeRetroSourceType({ source_type: 'generic', parser_source: 'bind_dns' }), 'dns');
  assert.equal(normalizeRetroSourceType({ source_type: 'dns', parser_source: 'syslog_observables' }), 'dns');
  assert.equal(normalizeRetroSourceType({ source_type: 'proxy', parser_source: 'squid_proxy' }), 'proxy');
});

test('skip retro rows when IOC was already present at ingest', () => {
  const row = {
    matched_ioc: 'aasdaonz.mechanickhodakarami.shop',
    match_context: { ioc_was_present_at_ingest: true }
  };
  assert.equal(shouldSkipRetroBecauseIocPresentAtIngest(row), true);
  const out = filterRetroRowsPresentAtIngest([row, { matched_ioc: 'other.test', match_context: { ioc_was_present_at_ingest: false } }]);
  assert.equal(out.kept.length, 1);
  assert.equal(out.skipped.length, 1);
});

test('incident #900 pattern: generic realtime and syslog_observables dns retro are equivalent', () => {
  const retro = {
    matched_ioc: 'aasdaonz.mechanickhodakarami.shop',
    ioc_type: 'domain',
    source: 'syslog:192.168.1.140',
    host: 'ollama',
    _bucketStart: '2026-06-14T21:55:00.000Z',
    parser_source: 'syslog_observables',
    source_type: 'dns'
  };
  const realtime = {
    matched_ioc: 'aasdaonz.mechanickhodakarami.shop',
    ioc_type: 'domain',
    source: 'syslog:192.168.1.140',
    host_name: 'ollama',
    bucket_start: '2026-06-14T21:55:00.000Z',
    detection_type: 'realtime',
    parser_source: 'unknown',
    source_type: 'generic'
  };
  assert.equal(isRealtimeEquivalentForRetro(retro, realtime), true);
});

test('retro realtime equivalent ignores parser name but keeps source type boundary', () => {
  const retro = {
    matched_ioc: 'kapindakimutlulukhemenal.com',
    ioc_type: 'domain',
    source: 'syslog:192.168.1.140',
    host: '192.168.1.140',
    _bucketStart: '2026-05-09T15:10:00.000Z',
    parser_source: 'syslog_observables',
    source_type: 'dns'
  };

  assert.equal(isRealtimeEquivalentForRetro(retro, {
    id: 58625,
    matched_ioc: 'kapindakimutlulukhemenal.com',
    ioc_type: 'domain',
    source: 'syslog:192.168.1.140',
    host_name: '192.168.1.140',
    bucket_start: '2026-05-09T15:10:00.000Z',
    detection_type: 'realtime',
    parser_source: 'bind_dns',
    source_type: 'generic'
  }), true);

  assert.equal(isRealtimeEquivalentForRetro(retro, {
    id: 58624,
    matched_ioc: 'kapindakimutlulukhemenal.com',
    ioc_type: 'domain',
    source: 'syslog:192.168.1.140',
    host_name: '192.168.1.140',
    bucket_start: '2026-05-09T15:10:00.000Z',
    detection_type: 'realtime',
    parser_source: 'squid_proxy',
    source_type: 'proxy'
  }), false);
});

test('retro filter skips duplicate DNS evidence when realtime equivalent exists', async () => {
  const rows = [{
    matched_ioc: 'kapindakimutlulukhemenal.com',
    ioc_type: 'domain',
    source: 'syslog:192.168.1.140',
    host: '192.168.1.140',
    _bucketStart: '2026-05-09T15:10:00.000Z',
    parser_source: 'syslog_observables',
    source_type: 'dns'
  }];
  const client = {
    async query(sql, params) {
      assert.match(sql, /WITH candidates/);
      assert.equal(params[1], 'kapindakimutlulukhemenal.com');
      return {
        rows: [{
          idx: 0,
          id: 58625,
          matched_ioc: 'kapindakimutlulukhemenal.com',
          ioc_type: 'domain',
          source: 'syslog:192.168.1.140',
          host_name: '192.168.1.140',
          bucket_start: '2026-05-09T15:10:00.000Z',
          detection_type: 'realtime',
          parser_source: 'bind_dns',
          source_type: 'generic'
        }]
      };
    }
  };

  const out = await filterRetroRowsWithRealtimeDuplicates(client, rows);
  assert.deepEqual(out.kept, []);
  assert.equal(out.skipped.length, 1);
  assert.deepEqual(out.skipped[0].duplicateEventIds, [58625]);
});

test('retro filter preserves valid retroactive match when only proxy realtime exists', async () => {
  const rows = [{
    matched_ioc: 'kapindakimutlulukhemenal.com',
    ioc_type: 'domain',
    source: 'syslog:192.168.1.140',
    host: '192.168.1.140',
    _bucketStart: '2026-05-09T15:10:00.000Z',
    parser_source: 'syslog_observables',
    source_type: 'dns'
  }];
  const client = {
    async query() {
      return {
        rows: [{
          idx: 0,
          id: 58624,
          matched_ioc: 'kapindakimutlulukhemenal.com',
          ioc_type: 'domain',
          source: 'syslog:192.168.1.140',
          host_name: '192.168.1.140',
          bucket_start: '2026-05-09T15:10:00.000Z',
          detection_type: 'realtime',
          parser_source: 'squid_proxy',
          source_type: 'proxy'
        }]
      };
    }
  };

  const out = await filterRetroRowsWithRealtimeDuplicates(client, rows);
  assert.equal(out.kept.length, 1);
  assert.deepEqual(out.skipped, []);
});
