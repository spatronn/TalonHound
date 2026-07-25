import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { selectRetentionCandidates } from './retention.js';

describe('backup retention', () => {
  const now = new Date('2026-07-25T12:00:00Z');

  it('selects old completed backups', () => {
    const rows = [
      { backup_id: 'old', status: 'completed', verify_status: 'passed', created_at: '2026-01-01T00:00:00Z' },
      { backup_id: 'new', status: 'completed', verify_status: 'passed', created_at: '2026-07-20T00:00:00Z' },
      { backup_id: 'run', status: 'running', verify_status: null, created_at: '2026-01-01T00:00:00Z' },
      { backup_id: 'pending', status: 'completed', verify_status: 'pending', created_at: '2026-01-01T00:00:00Z' }
    ];
    const selected = selectRetentionCandidates(rows, {
      retentionDays: 30,
      now,
      protectedBackupIds: new Set()
    });
    assert.deepEqual(selected.map((r) => r.backup_id), ['old']);
  });

  it('skips protected backup ids', () => {
    const rows = [
      { backup_id: 'keep', status: 'completed', verify_status: 'passed', created_at: '2026-01-01T00:00:00Z' }
    ];
    const selected = selectRetentionCandidates(rows, {
      retentionDays: 7,
      now,
      protectedBackupIds: new Set(['keep'])
    });
    assert.equal(selected.length, 0);
  });
});
