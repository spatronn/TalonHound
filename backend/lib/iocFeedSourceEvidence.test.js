import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MISSING_MEMBERSHIP_EVIDENCE_NOTE,
  buildIocDetailsSourceEvidence
} from './iocFeedSourceEvidence.js';

test('buildIocDetailsSourceEvidence returns stored and fallback rows for active memberships', () => {
  const rows = [{
    id: 1,
    source_name: 'ThreatFox:abuse.ch',
    source_url: 'https://threatfox-api.abuse.ch/api/v1/',
    confidence: 'medium',
    category: 'payload_delivery',
    note: 'Auto-imported from ThreatFox API',
    created_at: '2026-06-17T13:20:02.692Z',
    status: 'active'
  }];

  const membershipSummary = {
    activeSources: [
      {
        id: 'feed:1',
        source_type: 'feed',
        membership_id: 1,
        feed_key: 'threatfox-abusech',
        feed_name: 'ThreatFox abuse.ch',
        first_seen_at: '2026-06-17T13:20:03.349Z'
      },
      {
        id: 'feed:2',
        source_type: 'feed',
        membership_id: 2,
        feed_key: 'urlhaus-abusech',
        feed_name: 'URLhaus abuse.ch',
        first_seen_at: '2026-06-18T16:34:55.157Z'
      }
    ]
  };

  const evidenceRows = [{
    id: 10,
    feed_key: 'threatfox-abusech',
    source_name: 'ThreatFox:abuse.ch',
    source_url: 'https://threatfox-api.abuse.ch/api/v1/',
    confidence: 'medium',
    category: 'payload_delivery',
    note: 'Auto-imported from ThreatFox API',
    created_at: '2026-06-17T13:20:02.692Z'
  }];

  const out = buildIocDetailsSourceEvidence({ iocRows: rows, membershipSummary, evidenceRows });
  assert.equal(out.length, 2);
  assert.equal(out[0].source_name, 'ThreatFox:abuse.ch');
  assert.equal(out[0].evidence_kind, 'stored');
  assert.equal(out[1].source_name, 'URLhaus:abuse.ch');
  assert.equal(out[1].evidence_kind, 'membership_fallback');
  assert.equal(out[1].note, MISSING_MEMBERSHIP_EVIDENCE_NOTE);
});

test('buildIocDetailsSourceEvidence falls back to legacy ioc rows when no memberships', () => {
  const rows = [{
    id: 5,
    source_name: 'ThreatFox:abuse.ch',
    source_url: 'https://threatfox-api.abuse.ch/api/v1/',
    confidence: 'medium',
    category: 'payload_delivery',
    note: 'note',
    created_at: '2026-06-17T13:20:02.692Z',
    status: 'active'
  }];
  const out = buildIocDetailsSourceEvidence({ iocRows: rows, membershipSummary: { activeSources: [] }, evidenceRows: [] });
  assert.equal(out.length, 1);
  assert.equal(out[0].evidence_kind, 'legacy_ioc_item');
});
