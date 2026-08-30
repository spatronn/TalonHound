import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatReleaseChannelLabel,
  formatUpdateAvailabilityNotice,
  formatUpdateCheckFeedback,
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
  assert.match(
    formatUpdateStatusMessage({ status: 'development_build', latestVersion: '0.1.0-beta.1' }),
    /Development build.*0\.1\.0-beta\.1/
  );
  assert.match(
    formatUpdateStatusMessage({ status: 'no_release_published' }),
    /No release is currently published/
  );
  assert.match(
    formatUpdateStatusMessage({ status: 'check_failed', error: 'Unable to reach the update server' }),
    /Update check failed: Unable to reach/
  );
  assert.equal(formatUpdateStatusMessage({ status: 'unknown' }), 'Update status: Unknown');
  assert.match(
    formatUpdateStatusMessage({ status: 'unknown', automaticChecksEnabled: false }),
    /automatic checking is disabled/
  );
});

test('formatUpdateCheckFeedback maps statuses to toast kinds', () => {
  assert.deepEqual(
    formatUpdateCheckFeedback({ status: 'update_available', latestVersion: '0.1.0-beta.2' }),
    { kind: 'success', message: 'TalonHound 0.1.0-beta.2 is available.' }
  );
  assert.equal(formatUpdateCheckFeedback({ status: 'up_to_date' }).kind, 'success');
  assert.equal(formatUpdateCheckFeedback({ status: 'development_build', latestVersion: '0.1.0-beta.1' }).kind, 'info');
  assert.equal(formatUpdateCheckFeedback({ status: 'no_release_published' }).kind, 'info');
  assert.equal(formatUpdateCheckFeedback({ status: 'check_failed', error: 'Unable to reach the update server' }).kind, 'error');
  assert.equal(formatUpdateCheckFeedback({ status: 'unknown' }).kind, 'info');
});

test('formatUpdateAvailabilityNotice only for available updates', () => {
  assert.equal(
    formatUpdateAvailabilityNotice({ status: 'update_available', latestVersion: '0.1.0-beta.3' }),
    'TalonHound 0.1.0-beta.3 is available.'
  );
  assert.equal(formatUpdateAvailabilityNotice({ status: 'up_to_date', latestVersion: '0.1.0-beta.3' }), null);
});
