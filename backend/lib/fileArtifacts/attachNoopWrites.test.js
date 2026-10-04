import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { recomputePrimaryHash, syncCanonicalIocFlag, linkIocToArtifact } from './attach.js';

function recordingClient(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      const s = String(sql);
      calls.push({ sql: s, params });
      for (const h of handlers) {
        if (h.match(s, params)) return h.result(s, params);
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

describe('recomputePrimaryHash no-op when primary already correct', () => {
  it('does not clear/set is_primary when the winner is already primary', async () => {
    const primaryId = '11111111-1111-1111-1111-111111111111';
    const otherId = '22222222-2222-2222-2222-222222222222';
    const client = recordingClient([
      {
        match: (s) => s.includes('FROM file_artifact_hashes') && s.includes('WHERE artifact_id'),
        result: () => ({
          rows: [
            { id: primaryId, hash_type: 'sha256', normalized_hash_value: 'aa'.repeat(32), is_primary: true },
            { id: otherId, hash_type: 'md5', normalized_hash_value: 'bb'.repeat(16), is_primary: false }
          ]
        })
      },
      {
        match: (s) => s.includes('UPDATE file_artifacts') && s.includes('primary_hash_id'),
        result: () => ({ rowCount: 0 })
      },
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links'),
        result: () => ({
          rows: [{
            id: 9,
            ioc_observable_type: 'sha256',
            linked_hash_type: 'sha256',
            is_primary: true,
            is_canonical_ioc: true
          }]
        })
      }
    ]);

    const res = await recomputePrimaryHash(client, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    assert.equal(res.promoted, false);
    assert.equal(res.primary.id, primaryId);

    const primaryFlagWrites = client.calls.filter((c) =>
      c.sql.includes('UPDATE file_artifact_hashes') && c.sql.includes('is_primary'));
    assert.equal(primaryFlagWrites.length, 0, 'must not rewrite is_primary when already correct');
  });

  it('repairs drifted primary_hash_id without clear/set cycle', async () => {
    const primaryId = '11111111-1111-1111-1111-111111111111';
    const client = recordingClient([
      {
        match: (s) => s.includes('FROM file_artifact_hashes') && s.includes('WHERE artifact_id'),
        result: () => ({
          rows: [
            { id: primaryId, hash_type: 'sha256', normalized_hash_value: 'aa'.repeat(32), is_primary: true }
          ]
        })
      },
      {
        match: (s) => s.includes('UPDATE file_artifacts') && s.includes('primary_hash_id IS DISTINCT FROM'),
        result: () => ({ rowCount: 1 })
      },
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links'),
        result: () => ({
          rows: [{
            id: 9,
            ioc_observable_type: 'sha256',
            linked_hash_type: 'sha256',
            is_primary: true,
            is_canonical_ioc: true
          }]
        })
      }
    ]);

    const res = await recomputePrimaryHash(client, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    assert.equal(res.promoted, false);
    const pointerRepair = client.calls.find((c) =>
      c.sql.includes('UPDATE file_artifacts') && c.sql.includes('primary_hash_id IS DISTINCT FROM'));
    assert.ok(pointerRepair, 'drifted pointer must still be repaired');
    assert.equal(
      client.calls.filter((c) => c.sql.includes('UPDATE file_artifact_hashes') && c.sql.includes('is_primary')).length,
      0
    );
  });
});

describe('syncCanonicalIocFlag no-op when already correct', () => {
  it('issues no UPDATEs when a single link is already canonical', async () => {
    const client = recordingClient([
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links'),
        result: () => ({
          rows: [
            {
              id: 1,
              ioc_observable_type: 'sha256',
              linked_hash_type: 'sha256',
              is_primary: true,
              is_canonical_ioc: true
            },
            {
              id: 2,
              ioc_observable_type: 'md5',
              linked_hash_type: 'md5',
              is_primary: false,
              is_canonical_ioc: false
            }
          ]
        })
      }
    ]);

    const id = await syncCanonicalIocFlag(client, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    assert.equal(id, 1);
    assert.equal(
      client.calls.filter((c) => /^\s*UPDATE\b/im.test(c.sql)).length,
      0,
      'already-correct canonical flag must not UPDATE'
    );
  });

  it('loads is_canonical_ioc so the no-op short-circuit can see stored state', async () => {
    const client = recordingClient([
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links'),
        result: () => ({
          rows: [{
            id: 1,
            ioc_observable_type: 'sha256',
            linked_hash_type: 'sha256',
            is_primary: true,
            is_canonical_ioc: true
          }]
        })
      }
    ]);
    await syncCanonicalIocFlag(client, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    assert.match(client.calls[0].sql, /l\.is_canonical_ioc/);
  });

  it('repairs multiple incorrect canonical flags with delta UPDATEs', async () => {
    const client = recordingClient([
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links') && !s.includes('UPDATE'),
        result: () => ({
          rows: [
            {
              id: 1,
              ioc_observable_type: 'md5',
              linked_hash_type: 'md5',
              is_primary: false,
              is_canonical_ioc: true
            },
            {
              id: 2,
              ioc_observable_type: 'sha256',
              linked_hash_type: 'sha256',
              is_primary: true,
              is_canonical_ioc: true
            }
          ]
        })
      },
      {
        match: (s) => s.includes('UPDATE file_artifact_ioc_links'),
        result: () => ({ rowCount: 1 })
      }
    ]);
    const id = await syncCanonicalIocFlag(client, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    assert.equal(id, 2);
    assert.equal(client.calls.filter((c) => /^\s*UPDATE\b/im.test(c.sql)).length, 2);
  });

  it('uses delta-only UPDATEs when the canonical link must change', async () => {
    const client = recordingClient([
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links') && !s.includes('UPDATE'),
        result: () => ({
          rows: [
            {
              id: 1,
              ioc_observable_type: 'md5',
              linked_hash_type: 'md5',
              is_primary: false,
              is_canonical_ioc: true
            },
            {
              id: 2,
              ioc_observable_type: 'sha256',
              linked_hash_type: 'sha256',
              is_primary: true,
              is_canonical_ioc: false
            }
          ]
        })
      },
      {
        match: (s) => s.includes('UPDATE file_artifact_ioc_links'),
        result: () => ({ rowCount: 1 })
      }
    ]);

    const id = await syncCanonicalIocFlag(client, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    assert.equal(id, 2);
    const updates = client.calls.filter((c) => /^\s*UPDATE\b/im.test(c.sql));
    assert.equal(updates.length, 2);
    assert.match(updates[0].sql, /is_canonical_ioc = FALSE/);
    assert.match(updates[0].sql, /id IS DISTINCT FROM \$2/);
    assert.match(updates[1].sql, /is_canonical_ioc = TRUE/);
    assert.match(updates[1].sql, /is_canonical_ioc IS DISTINCT FROM TRUE/);
  });
});

describe('linkIocToArtifact linked_hash_id fill is conditional', () => {
  it('does not UPDATE linked_hash_id when already set', async () => {
    const client = recordingClient([
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links') && s.includes('ioc_item_id'),
        result: () => ({
          rowCount: 1,
          rows: [{ id: 55, artifact_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }]
        })
      },
      {
        match: (s) => s.includes('UPDATE file_artifact_ioc_links') && s.includes('linked_hash_id'),
        result: () => ({ rowCount: 0 })
      },
      {
        match: (s) => s.includes('FROM file_artifact_ioc_links l'),
        result: () => ({
          rows: [{
            id: 55,
            ioc_observable_type: 'sha256',
            linked_hash_type: 'sha256',
            is_primary: true,
            is_canonical_ioc: true
          }]
        })
      }
    ]);

    const res = await linkIocToArtifact(client, {
      artifact_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      ioc_item_id: 99,
      ioc_observable_type: 'sha256',
      ioc_public_id: 'aa'.repeat(32),
      linked_hash_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    });
    assert.equal(res.ok, true);
    assert.equal(res.created, false);
    const linkUpd = client.calls.find((c) =>
      c.sql.includes('UPDATE file_artifact_ioc_links') && c.sql.includes('linked_hash_id'));
    assert.ok(linkUpd);
    assert.match(linkUpd.sql, /linked_hash_id IS NULL/);
  });
});
