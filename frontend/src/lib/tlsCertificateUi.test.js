import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatTlsStatusLabel,
  tlsStatusTone,
  canReplaceTlsCertificate,
  describeTlsSource
} from './tlsCertificateUi.js';

test('tls certificate UI helpers', () => {
  assert.equal(formatTlsStatusLabel('expiring_soon'), 'Expiring Soon');
  assert.equal(tlsStatusTone('expired'), 'error');
  assert.equal(tlsStatusTone('active'), 'ok');
  assert.equal(canReplaceTlsCertificate({ can_edit: true }), true);
  assert.equal(canReplaceTlsCertificate({ can_edit: false }), false);
  assert.equal(describeTlsSource('custom'), 'Custom');
  assert.equal(describeTlsSource('generated'), 'TalonHound Generated');
});
