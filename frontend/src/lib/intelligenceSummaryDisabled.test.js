import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeProviderCoverage,
  providerStateLabel,
  snapshotHasResult
} from './intelligenceSummary.js';

function stateOf(snapshots, keys) {
  const cov = computeProviderCoverage(snapshots, { providerKeys: keys });
  return Object.fromEntries(cov.map((p) => [p.key, p.state]));
}

test('enabled + result → available; enabled + never run → not_run (two providers)', () => {
  const states = stateOf(
    {
      virustotal: { status: 'success', summary: { stats: {} } },
      abuseipdb: { status: 'not_run' }
    },
    ['virustotal', 'abuseipdb']
  );
  assert.equal(states.virustotal, 'available');
  assert.equal(states.abuseipdb, 'not_run');
  assert.equal(providerStateLabel(states.virustotal), 'Available');
  assert.equal(providerStateLabel(states.abuseipdb), 'Not run');
});

test('disabled + historical result → historical_disabled; disabled + no result → disabled (two providers)', () => {
  const states = stateOf(
    {
      virustotal: { status: 'disabled', summary: { stats: { malicious: 3 } }, fetched_at: '2026-01-01T00:00:00Z' },
      abuseipdb: { status: 'disabled' }
    },
    ['virustotal', 'abuseipdb']
  );
  assert.equal(states.virustotal, 'historical_disabled');
  assert.equal(states.abuseipdb, 'disabled');
  assert.equal(providerStateLabel(states.virustotal), 'Historical · Disabled');
  assert.equal(providerStateLabel(states.abuseipdb), 'Disabled');
});

test('enabled but missing key/config → not_configured; enabled but failure → error', () => {
  const states = stateOf(
    {
      virustotal: { status: 'api_key_missing' },
      abuseipdb: { status: 'error', message: 'timeout' }
    },
    ['virustotal', 'abuseipdb']
  );
  assert.equal(states.virustotal, 'not_configured');
  assert.equal(states.abuseipdb, 'error');
  assert.equal(providerStateLabel(states.virustotal), 'Not configured');
  assert.equal(providerStateLabel(states.abuseipdb), 'Error');
});

test('snapshotHasResult recognizes various result shapes but not empty/disabled-only', () => {
  assert.equal(snapshotHasResult({ status: 'disabled' }), false);
  assert.equal(snapshotHasResult({ status: 'disabled', data: { x: 1 } }), true);
  assert.equal(snapshotHasResult({ status: 'disabled', summary: {} }), true);
  assert.equal(snapshotHasResult({ status: 'disabled', listed: false }), true);
  assert.equal(snapshotHasResult({ status: 'disabled', fetched_at: '2026-01-01' }), true);
  assert.equal(snapshotHasResult(null), false);
});

test('historical_disabled requires an actual prior result, not just the disabled flag', () => {
  // Disabled with no result payload must remain plain "disabled".
  const disabledOnly = stateOf({ virustotal: { status: 'disabled' } }, ['virustotal']);
  assert.equal(disabledOnly.virustotal, 'disabled');
});
