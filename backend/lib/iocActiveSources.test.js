import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isActiveFeedMembership,
  isHistoricalFeedMembership,
  parseIocListStatusFilter,
  iocStatusSqlClause
} from './iocActiveSources.js';
import {
  buildIocInheritedConfidenceSummary,
  computeInheritedEffectiveConfidence
} from './iocConfidence.js';

test('isActiveFeedMembership excludes purged memberships', () => {
  assert.equal(isActiveFeedMembership({ status: 'active', purged_at: null }), true);
  assert.equal(isActiveFeedMembership({ status: 'active', purged_at: new Date() }), false);
  assert.equal(isActiveFeedMembership({ status: 'purged', purged_at: new Date() }), false);
  assert.equal(isActiveFeedMembership({ status: 'expired' }), false);
});

test('isHistoricalFeedMembership includes purged and expired', () => {
  assert.equal(isHistoricalFeedMembership({ status: 'purged', purged_at: new Date() }), true);
  assert.equal(isHistoricalFeedMembership({ status: 'expired' }), true);
  assert.equal(isHistoricalFeedMembership({ status: 'active', purged_at: null }), false);
});

test('parseIocListStatusFilter defaults to active', () => {
  assert.equal(parseIocListStatusFilter(undefined), 'active');
  assert.equal(parseIocListStatusFilter('expired'), 'expired');
  assert.equal(parseIocListStatusFilter('all'), 'all');
});

test('iocStatusSqlClause builds active filter', () => {
  assert.match(iocStatusSqlClause('active', 'i'), /COALESCE\(i\.status, 'active'\) = 'active'/);
  assert.equal(iocStatusSqlClause('all'), null);
});

test('purged membership is not used for confidence source', () => {
  const result = computeInheritedEffectiveConfidence({
    memberships: [{
      status: 'purged',
      purged_at: new Date(),
      feed_default_confidence: 'high',
      feed_name: 'USOM TR-CERT'
    }]
  });
  assert.equal(result.effective, null);
  assert.equal(result.confidence_source, 'unknown');
});

test('buildIocInheritedConfidenceSummary ignores purged feed default', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, public_id: '11111111-1111-1111-1111-111111111111', analyst_confidence_override: null, status: 'expired' },
    membershipRows: [{
      status: 'purged',
      purged_at: new Date(),
      explicit_confidence: null,
      feed_default_confidence: 'high',
      feed_name: 'USOM TR-CERT',
      feed_key: 'usom-trcert'
    }],
    iocRows: [{ status: 'expired', source_name: 'USOM TR-CERT' }]
  });
  assert.equal(summary.effective, null);
  assert.equal(summary.confidence_source, 'unknown');
  assert.equal(summary.has_active_source, false);
  assert.equal(summary.historical_memberships.length, 1);
  assert.equal(summary.historical_memberships[0].status, 'purged');
});

test('shared IOC keeps active feed confidence when other feed purged', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, public_id: '11111111-1111-1111-1111-111111111111', analyst_confidence_override: null, status: 'active' },
    membershipRows: [
      {
        status: 'purged',
        purged_at: new Date(),
        feed_default_confidence: 'high',
        feed_name: 'USOM TR-CERT',
        feed_key: 'usom'
      },
      {
        status: 'active',
        purged_at: null,
        feed_default_confidence: 'medium',
        feed_name: 'Other Feed',
        feed_key: 'other'
      }
    ],
    iocRows: [{ status: 'active', source_name: 'Other Feed' }]
  });
  assert.equal(summary.effective, 'medium');
  assert.equal(summary.confidence_feed_name, 'Other Feed');
  assert.equal(summary.has_active_source, true);
  assert.equal(summary.membership_breakdown.length, 1);
});
