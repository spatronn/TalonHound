import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatReleaseChannelLabel,
  formatUpdateAvailabilityNotice,
  formatUpdateStatusMessage
} from './updateStatusView.js';

test('formatReleaseChannelLabel capitalizes channel', () => {
  assert.equal(formatReleaseChannelLabel('beta'), 'Beta');
  assert.equal(formatReleaseChannelLabel('stable'), 'Stable');
  assert.equal(formatReleaseChannelLabel(''), '—');
});

test('formatUpdateStatusMessage covers known states', () => {
  assert.equal(formatUpdateStatusMessage({ status: 'up_to_date' }), "You're up to date");
  assert.equal(formatUpdateStatusMessage({ status: 'update_available' }), 'Update available');
  assert.equal(formatUpdateStatusMessage({ status: 'unknown' }), 'Update status: Unknown');
  assert.match(
    formatUpdateStatusMessage({ status: 'unknown', automaticChecksEnabled: false }),
    /automatic checking is disabled/
  );
});

test('formatUpdateAvailabilityNotice only for available updates', () => {
  assert.equal(
    formatUpdateAvailabilityNotice({ status: 'update_available', latestVersion: '0.1.0-beta.3' }),
    'TalonHound 0.1.0-beta.3 is available.'
  );
  assert.equal(formatUpdateAvailabilityNotice({ status: 'up_to_date', latestVersion: '0.1.0-beta.3' }), null);
});
