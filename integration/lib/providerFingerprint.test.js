import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeUrlhausProviderFingerprint } from './urlhaus.js';
import { computeThreatFoxProviderFingerprint } from './threatfox.js';
import { createImportMetrics } from './import-metrics.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUrlhausEntry(overrides = {}) {
  return {
    observable: 'https://evil.example.com/payload.exe',
    observableType: 'url',
    externalId: '123456',
    dateAdded: new Date('2026-06-01T00:00:00Z'),
    urlStatus: 'online',
    lastOnline: new Date('2026-06-20T12:00:00Z'),
    threat: 'malware-download',
    tags: ['malware', 'exe'],
    referenceUrl: 'https://urlhaus.abuse.ch/url/123456/',
    reporter: 'anonymous',
    ...overrides
  };
}

function makeThreatFoxEntry(overrides = {}) {
  return {
    observable: 'https://voltrix.lol/Beta/Voltrix.zip',
    observableType: 'url',
    iocId: 'tf-001',
    threatType: 'payload_delivery',
    malware: 'Voltrix',
    malwarePrintable: 'Voltrix',
    malwareAlias: null,
    confidence: 'high',
    firstSeen: new Date('2026-06-01T00:00:00Z'),
    lastSeen: new Date('2026-06-20T12:00:00Z'),
    reference: null,
    tags: ['malware'],
    reporter: 'abuse.ch',
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// URLHaus fingerprint unit tests
// ---------------------------------------------------------------------------

describe('computeUrlhausProviderFingerprint', () => {
  it('is stable — same entry produces the same fingerprint', () => {
    const e = makeUrlhausEntry();
    assert.equal(computeUrlhausProviderFingerprint(e), computeUrlhausProviderFingerprint(e));
  });

  it('changes when tags change', () => {
    const a = makeUrlhausEntry({ tags: ['malware'] });
    const b = makeUrlhausEntry({ tags: ['malware', 'ransomware'] });
    assert.notEqual(computeUrlhausProviderFingerprint(a), computeUrlhausProviderFingerprint(b));
  });

  it('is unchanged when only last_online changes (volatile field excluded)', () => {
    const a = makeUrlhausEntry({ lastOnline: new Date('2026-06-01T00:00:00Z') });
    const b = makeUrlhausEntry({ lastOnline: new Date('2026-06-30T23:59:59Z') });
    assert.equal(computeUrlhausProviderFingerprint(a), computeUrlhausProviderFingerprint(b));
  });

  it('changes when url_status changes', () => {
    const a = makeUrlhausEntry({ urlStatus: 'online' });
    const b = makeUrlhausEntry({ urlStatus: 'offline' });
    assert.notEqual(computeUrlhausProviderFingerprint(a), computeUrlhausProviderFingerprint(b));
  });

  it('is insensitive to tag ordering', () => {
    const a = makeUrlhausEntry({ tags: ['exe', 'malware'] });
    const b = makeUrlhausEntry({ tags: ['malware', 'exe'] });
    assert.equal(computeUrlhausProviderFingerprint(a), computeUrlhausProviderFingerprint(b));
  });

  it('changes when reporter changes', () => {
    const a = makeUrlhausEntry({ reporter: 'anonymous' });
    const b = makeUrlhausEntry({ reporter: 'researcher' });
    assert.notEqual(computeUrlhausProviderFingerprint(a), computeUrlhausProviderFingerprint(b));
  });

  it('differs across different observables', () => {
    const a = makeUrlhausEntry({ observable: 'https://evil.example.com/a.exe' });
    const b = makeUrlhausEntry({ observable: 'https://evil.example.com/b.exe' });
    assert.notEqual(computeUrlhausProviderFingerprint(a), computeUrlhausProviderFingerprint(b));
  });
});

// ---------------------------------------------------------------------------
// ThreatFox fingerprint unit tests
// ---------------------------------------------------------------------------

describe('computeThreatFoxProviderFingerprint', () => {
  it('is stable — same entry produces the same fingerprint', () => {
    const e = makeThreatFoxEntry();
    assert.equal(computeThreatFoxProviderFingerprint(e), computeThreatFoxProviderFingerprint(e));
  });

  it('changes when confidence changes', () => {
    const a = makeThreatFoxEntry({ confidence: 'high' });
    const b = makeThreatFoxEntry({ confidence: 'low' });
    assert.notEqual(computeThreatFoxProviderFingerprint(a), computeThreatFoxProviderFingerprint(b));
  });

  it('is unchanged when only last_seen changes (volatile field excluded)', () => {
    const a = makeThreatFoxEntry({ lastSeen: new Date('2026-06-01T00:00:00Z') });
    const b = makeThreatFoxEntry({ lastSeen: new Date('2026-06-30T23:59:59Z') });
    assert.equal(computeThreatFoxProviderFingerprint(a), computeThreatFoxProviderFingerprint(b));
  });

  it('changes when malware name changes', () => {
    const a = makeThreatFoxEntry({ malwarePrintable: 'Voltrix' });
    const b = makeThreatFoxEntry({ malwarePrintable: 'AgentTesla' });
    assert.notEqual(computeThreatFoxProviderFingerprint(a), computeThreatFoxProviderFingerprint(b));
  });

  it('is insensitive to tag ordering', () => {
    const a = makeThreatFoxEntry({ tags: ['rat', 'malware'] });
    const b = makeThreatFoxEntry({ tags: ['malware', 'rat'] });
    assert.equal(computeThreatFoxProviderFingerprint(a), computeThreatFoxProviderFingerprint(b));
  });

  it('changes when threat_type changes', () => {
    const a = makeThreatFoxEntry({ threatType: 'payload_delivery' });
    const b = makeThreatFoxEntry({ threatType: 'botnet_cc' });
    assert.notEqual(computeThreatFoxProviderFingerprint(a), computeThreatFoxProviderFingerprint(b));
  });

  it('differs across different observables', () => {
    const a = makeThreatFoxEntry({ observable: 'https://voltrix.lol/a.zip' });
    const b = makeThreatFoxEntry({ observable: 'https://voltrix.lol/b.zip' });
    assert.notEqual(computeThreatFoxProviderFingerprint(a), computeThreatFoxProviderFingerprint(b));
  });
});

// ---------------------------------------------------------------------------
// createImportMetrics — noteUnchanged
// ---------------------------------------------------------------------------

describe('createImportMetrics noteUnchanged', () => {
  it('increments both records_unchanged and records_skipped', () => {
    const m = createImportMetrics();
    m.noteUnchanged();
    assert.equal(m.records_unchanged, 1);
    assert.equal(m.records_skipped, 1);
  });

  it('noteUnchanged(3) increments by 3', () => {
    const m = createImportMetrics();
    m.noteUnchanged(3);
    assert.equal(m.records_unchanged, 3);
    assert.equal(m.records_skipped, 3);
  });

  it('records_unchanged appears in toJSON()', () => {
    const m = createImportMetrics();
    m.noteUnchanged(2);
    const json = m.toJSON();
    assert.equal(json.records_unchanged, 2);
    assert.equal(json.records_skipped, 2);
  });

  it('merge() propagates records_unchanged', () => {
    const a = createImportMetrics();
    a.noteUnchanged(5);
    const b = createImportMetrics();
    b.merge(a);
    assert.equal(b.records_unchanged, 5);
    assert.equal(b.records_skipped, 5);
  });

  it('noteUnchanged contributes to recordsProcessed via records_skipped', () => {
    const m = createImportMetrics();
    m.noteUnchanged(2);
    assert.equal(m.recordsProcessed(), 2);
  });

  it('noteUnchanged does not double-count in recordsProcessed', () => {
    const m = createImportMetrics();
    m.noteUnchanged(1);
    m.noteSkipped(1);
    // records_skipped = 2, records_unchanged = 1; recordsProcessed = 2 (not 3)
    assert.equal(m.recordsProcessed(), 2);
    assert.equal(m.records_unchanged, 1);
  });
});
