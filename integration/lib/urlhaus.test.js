import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  URLHAUS_AUTH_REQUIRED_MSG,
  URLHAUS_EXPORT_URL_MASKED,
  buildUrlhausNote,
  buildUrlhausRecentCsvUrl,
  mapUrlhausRow,
  normalizeUrlhausTags,
  parseUrlhausRecentCsv,
  resolveUrlhausAuthKey,
  sanitizeUrlhausErrorMessage,
  splitCsvLine,
  stripUrlhausVolatileNoteParts
} from './urlhaus.js';

const SAMPLE_CSV = `################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)
# Last updated: 2026-05-27 11:52:06 (UTC)
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3853890","2026-05-27 11:52:06","http://110.36.23.67:57501/bin.sh","online","2026-05-27 11:52:06","malware_download","None","https://urlhaus.abuse.ch/url/3853890/","GAYINT_DOT_ORG"
"3853889","2026-05-27 11:51:06","https://reoen.webgondozas.hu/a44f43f1-dc49-4a45-b725-33106ce13f94","offline","","malware_download","ClearFake","https://urlhaus.abuse.ch/url/3853889/","anonymous"
`;

describe('parseUrlhausRecentCsv', () => {
  it('ignores comment and header lines', () => {
    const { entries, fetched, skipped } = parseUrlhausRecentCsv(SAMPLE_CSV);
    assert.equal(fetched, 2);
    assert.equal(skipped, 0);
    assert.equal(entries.length, 2);
  });

  it('parses quoted CSV fields', () => {
    const line = '"1","2026-05-27 11:52:06","https://example.com/path,with,commas","online","","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/1/","reporter"';
    const cols = splitCsvLine(line);
    const row = mapUrlhausRow(cols);
    assert.equal(row.observable, 'https://example.com/path,with,commas');
    assert.deepEqual(row.tags, ['32-bit', 'elf', 'mips', 'Mozi', 'malware_download']);
  });

  it('normalizes tags None to empty', () => {
    assert.deepEqual(normalizeUrlhausTags('None'), []);
    assert.deepEqual(normalizeUrlhausTags(''), []);
  });

  it('parses comma-separated tags', () => {
    assert.deepEqual(normalizeUrlhausTags('32-bit,elf,mips,Mozi'), ['32-bit', 'elf', 'mips', 'Mozi']);
  });

  it('sets last_online null when empty', () => {
    const offline = mapUrlhausRow(splitCsvLine(
      '"3853889","2026-05-27 11:51:06","https://example.test/x","offline","","malware_download","ClearFake","https://urlhaus.abuse.ch/url/3853889/","anonymous"'
    ));
    assert.equal(offline.lastOnline, null);
    assert.equal(offline.urlStatus, 'offline');
  });

  it('does not skip offline URLs', () => {
    const { entries } = parseUrlhausRecentCsv(SAMPLE_CSV);
    const offline = entries.find((e) => e.externalId === '3853889');
    assert.ok(offline);
    assert.equal(offline.urlStatus, 'offline');
  });

  it('maps id, threat, reference_url, reporter', () => {
    const { entries } = parseUrlhausRecentCsv(SAMPLE_CSV);
    const row = entries.find((e) => e.externalId === '3853890');
    assert.equal(row.threat, 'malware_download');
    assert.equal(row.referenceUrl, 'https://urlhaus.abuse.ch/url/3853890/');
    assert.equal(row.reporter, 'GAYINT_DOT_ORG');
    assert.ok(row.dateAdded instanceof Date);
  });

  it('counts invalid rows once in skipped (= fetched - parsed)', () => {
    const csv = `${SAMPLE_CSV}
"bad","","","","","","","",""
`;
    const { fetched, parsed, skipped } = parseUrlhausRecentCsv(csv);
    assert.equal(skipped, fetched - parsed);
    assert.ok(skipped >= 1);
    // Importer must call noteSkipped(skipped) only — never skipped + (fetched - parsed).
    assert.equal(skipped + Math.max(0, fetched - parsed), skipped * 2);
  });
});

describe('buildUrlhausRecentCsvUrl', () => {
  it('builds export URL from auth key', () => {
    assert.equal(
      buildUrlhausRecentCsvUrl('<URLHAUS_AUTH_KEY>'),
      'https://urlhaus-api.abuse.ch/v2/files/exports/%3CURLHAUS_AUTH_KEY%3E/recent.csv'
    );
  });

  it('throws when auth key missing', () => {
    assert.throws(() => buildUrlhausRecentCsvUrl(''), { message: URLHAUS_AUTH_REQUIRED_MSG });
  });
});

describe('resolveUrlhausAuthKey', () => {
  it('prefers integration credentials over env', async () => {
    const client = {
      query: async () => ({ rows: [{ credentials: { auth_key: 'from-db' } }] })
    };
    const key = await resolveUrlhausAuthKey(client, 'from-env');
    assert.equal(key, 'from-db');
  });

  it('falls back to env when db empty', async () => {
    const client = {
      query: async () => ({ rows: [{ credentials: {} }] })
    };
    const key = await resolveUrlhausAuthKey(client, 'from-env');
    assert.equal(key, 'from-env');
  });

  it('returns null when neither configured', async () => {
    const client = { query: async () => ({ rows: [{ credentials: {} }] }) };
    assert.equal(await resolveUrlhausAuthKey(client, ''), null);
  });
});

describe('sanitizeUrlhausErrorMessage', () => {
  it('masks export URL in errors', () => {
    const err = 'fetch failed: https://urlhaus-api.abuse.ch/v2/files/exports/secret-key-123/recent.csv 403';
    assert.equal(
      sanitizeUrlhausErrorMessage(err),
      `fetch failed: ${URLHAUS_EXPORT_URL_MASKED} 403`
    );
  });
});

describe('buildUrlhausNote', () => {
  it('includes metadata fields', () => {
    const note = buildUrlhausNote({
      externalId: '1',
      referenceUrl: 'https://urlhaus.abuse.ch/url/1/',
      urlStatus: 'online',
      reporter: 'anon',
      tags: ['malware_download'],
      dateAdded: new Date('2026-05-27T11:52:06.000Z'),
      lastOnline: null
    });
    assert.match(note, /external_id=1/);
    assert.match(note, /reference_url=https:\/\/urlhaus\.abuse\.ch\/url\/1\//);
    assert.match(note, /url_status=online/);
    assert.doesNotMatch(note, /<URLHAUS_AUTH_KEY>/);
  });
});

describe('stripUrlhausVolatileNoteParts', () => {
  it('removes last_online from note comparison key', () => {
    const older = buildUrlhausNote({
      externalId: '1',
      urlStatus: 'online',
      tags: ['malware_download'],
      dateAdded: new Date('2026-05-27T11:52:06.000Z'),
      lastOnline: new Date('2026-05-27T11:52:06.000Z')
    });
    const newer = buildUrlhausNote({
      externalId: '1',
      urlStatus: 'online',
      tags: ['malware_download'],
      dateAdded: new Date('2026-05-27T11:52:06.000Z'),
      lastOnline: new Date('2026-06-28T17:40:00.000Z')
    });
    assert.equal(stripUrlhausVolatileNoteParts(older), stripUrlhausVolatileNoteParts(newer));
  });
});
