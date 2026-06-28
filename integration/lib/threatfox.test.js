import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  THREATFOX_AUTH_REQUIRED_MSG,
  buildThreatFoxNote,
  buildThreatFoxRecentRequestBody,
  classifyThreatFoxObservable,
  fetchThreatFoxRecentIocs,
  mapThreatFoxApiRow,
  parseThreatFoxApiResponse,
  sanitizeThreatFoxErrorMessage,
  stripThreatFoxVolatileNoteParts,
  validateThreatFoxRecentDays
} from './threatfox.js';

describe('validateThreatFoxRecentDays', () => {
  it('clamps invalid values to default', () => {
    assert.equal(validateThreatFoxRecentDays(3), 3);
    assert.equal(validateThreatFoxRecentDays(0), 3);
    assert.equal(validateThreatFoxRecentDays(99), 3);
    assert.equal(validateThreatFoxRecentDays('7'), 7);
  });
});

describe('classifyThreatFoxObservable', () => {
  it('maps domain and hashes', () => {
    assert.deepEqual(classifyThreatFoxObservable('evil.test', 'domain'), {
      observable: 'evil.test',
      observableType: 'domain'
    });
    assert.deepEqual(
      classifyThreatFoxObservable('abc'.repeat(21) + 'a', 'sha256_hash'),
      { observable: ('abc'.repeat(21) + 'a').toLowerCase(), observableType: 'sha256' }
    );
  });

  it('maps ip:port to ip when possible', () => {
    assert.deepEqual(classifyThreatFoxObservable('1.2.3.4:443', 'ip:port'), {
      observable: '1.2.3.4',
      observableType: 'ip'
    });
  });
});

describe('parseThreatFoxApiResponse', () => {
  it('accepts no_result as empty success', () => {
    const parsed = parseThreatFoxApiResponse({ query_status: 'no_result' });
    assert.equal(parsed.entries.length, 0);
    assert.equal(parsed.queryStatus, 'no_result');
  });

  it('maps API rows', () => {
    const parsed = parseThreatFoxApiResponse({
      query_status: 'ok',
      data: [
        {
          id: '41',
          ioc: 'gaga.com',
          ioc_type: 'domain',
          threat_type: 'botnet_cc',
          malware_printable: 'Dridex',
          confidence_level: 50,
          first_seen: '2020-12-08 13:36:27 UTC',
          reporter: 'abuse_ch',
          tags: ['exe']
        }
      ]
    });
    assert.equal(parsed.parsed, 1);
    assert.equal(parsed.entries[0].iocId, '41');
    assert.equal(parsed.entries[0].confidence, 'medium');
  });

  it('throws on auth query status', () => {
    assert.throws(
      () => parseThreatFoxApiResponse({ query_status: 'invalid_auth_key' }),
      /invalid_auth_key|ThreatFox API query failed/i
    );
  });
});

describe('fetchThreatFoxRecentIocs', () => {
  it('requires auth key', async () => {
    await assert.rejects(
      () => fetchThreatFoxRecentIocs({ authKey: '', fetchFn: async () => ({ ok: true, text: async () => '{}' }) }),
      (err) => err.message === THREATFOX_AUTH_REQUIRED_MSG
    );
  });

  it('sends POST with Auth-Key header and get_iocs body', async () => {
    let captured = null;
    await fetchThreatFoxRecentIocs({
      authKey: 'secret-key',
      days: 3,
      fetchFn: async (url, init) => {
        captured = { url, init };
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ query_status: 'no_result' })
        };
      }
    });
    assert.equal(captured.url, 'https://threatfox-api.abuse.ch/api/v1/');
    assert.equal(captured.init.method, 'POST');
    assert.equal(captured.init.headers['Auth-Key'], 'secret-key');
    assert.deepEqual(JSON.parse(captured.init.body), buildThreatFoxRecentRequestBody(3));
  });

  it('maps 401 to auth failure without leaking key', async () => {
    await assert.rejects(
      () => fetchThreatFoxRecentIocs({
        authKey: 'bad-key',
        fetchFn: async () => ({
          ok: false,
          status: 401,
          text: async () => JSON.stringify({ query_status: 'invalid_auth_key' })
        })
      }),
      (err) => err.statusCode === 401 && !String(err.message).includes('bad-key')
    );
  });
});

describe('sanitizeThreatFoxErrorMessage', () => {
  it('redacts auth key fragments', () => {
    const out = sanitizeThreatFoxErrorMessage('Auth-Key: supersecret failed');
    assert.equal(out.includes('supersecret'), false);
    assert.match(out, /Auth-Key: \*\*\*/);
  });
});

describe('buildThreatFoxNote', () => {
  it('includes metadata fields', () => {
    const note = buildThreatFoxNote({
      iocId: '1',
      threatType: 'botnet_cc',
      malwarePrintable: 'Dridex',
      tags: ['exe']
    });
    assert.match(note, /ioc_id=1/);
    assert.match(note, /malware=Dridex/);
  });
});

describe('stripThreatFoxVolatileNoteParts', () => {
  it('removes last_seen from note comparison key', () => {
    const older = buildThreatFoxNote({
      iocId: '1',
      threatType: 'botnet_cc',
      firstSeen: new Date('2026-06-26T12:25:15.000Z'),
      lastSeen: new Date('2026-06-26T12:25:15.000Z')
    });
    const newer = buildThreatFoxNote({
      iocId: '1',
      threatType: 'botnet_cc',
      firstSeen: new Date('2026-06-26T12:25:15.000Z'),
      lastSeen: new Date('2026-06-28T19:25:13.000Z')
    });
    assert.notEqual(older, newer);
    assert.equal(stripThreatFoxVolatileNoteParts(older), stripThreatFoxVolatileNoteParts(newer));
  });
});
