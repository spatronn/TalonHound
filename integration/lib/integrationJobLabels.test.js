import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatIntegrationJobDisplayName,
  withIntegrationJobDisplayName
} from '../../backend/lib/integrationJobLabels.js';

describe('formatIntegrationJobDisplayName', () => {
  it('maps ET hourly-import to friendly label', () => {
    assert.equal(
      formatIntegrationJobDisplayName('hourly-import', 'et-blockrules'),
      'Blockrules IP import'
    );
  });

  it('falls back to job name when unknown', () => {
    assert.equal(formatIntegrationJobDisplayName('custom-job'), 'custom-job');
  });

  it('labels MalwareBazaar historical recovery distinctly from recent import', () => {
    assert.equal(
      formatIntegrationJobDisplayName('malwarebazaar-historical-recovery', 'malwarebazaar-abusech'),
      'MalwareBazaar historical recovery'
    );
    assert.equal(
      formatIntegrationJobDisplayName('malwarebazaar-import', 'malwarebazaar-abusech'),
      'Recent malware samples import'
    );
  });
});

describe('withIntegrationJobDisplayName', () => {
  it('preserves technical job_name and sets display name', () => {
    const row = withIntegrationJobDisplayName({
      name: 'hourly-import',
      integration_key: 'et-blockrules'
    });
    assert.equal(row.job_name, 'hourly-import');
    assert.equal(row.name, 'Blockrules IP import');
    assert.equal(row.display_name, 'Blockrules IP import');
  });
});
