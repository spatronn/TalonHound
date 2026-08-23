import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatBuildDateDetail,
  formatCommitDetail,
  formatProductVersionLabel
} from './productVersionView.js';

test('formatProductVersionLabel renders TalonHound product version', () => {
  assert.equal(
    formatProductVersionLabel({ product: 'TalonHound', version: '0.1.0-beta.1' }),
    'TalonHound v0.1.0-beta.1'
  );
});

test('formatCommitDetail abbreviates known SHAs only', () => {
  assert.equal(formatCommitDetail({ commit: 'abc1234567890' }), 'abc1234');
  assert.equal(formatCommitDetail({ commit: 'unknown' }), null);
});

test('formatBuildDateDetail hides unknown build dates', () => {
  assert.equal(formatBuildDateDetail({ buildDate: '2026-08-23T12:00:00.000Z' }), '2026-08-23T12:00:00.000Z');
  assert.equal(formatBuildDateDetail({ buildDate: 'unknown' }), null);
});
