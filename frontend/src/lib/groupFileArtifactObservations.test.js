import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { groupFileArtifactObservations } from './groupFileArtifactObservations.js';

const MD5 = '9aed790a18f214b04619837cd71546d3';
const SHA1 = '0f9a253afc55a8ebbd29a70c43d0e3cd668920f4';
const SHA256 = '8ec6066000f5585d6fefbc1d5a30fa094ac9893456dbf4085fec81e6b71cef3b';

describe('groupFileArtifactObservations', () => {
  it('groups MB direct + mappings into one row with additional hashes', () => {
    const grouped = groupFileArtifactObservations([
      {
        id: 1,
        source_name: 'MalwareBazaar',
        feed_id: 'feed-mb',
        observed_as: 'sha256',
        observed_hash_type: 'sha256',
        observed_hash_value: SHA256,
        observation_type: 'direct_source_observation',
        evidence_label: 'Direct source observation',
        first_seen_in_source: '2024-01-01T00:00:00Z',
        last_seen_in_source: '2024-01-02T00:00:00Z'
      },
      {
        id: 2,
        source_name: 'MalwareBazaar',
        feed_id: 'feed-mb',
        observed_as: 'md5',
        observed_hash_type: 'md5',
        observed_hash_value: MD5,
        observation_type: 'provider_hash_mapping',
        evidence_label: 'Provider exact hash mapping'
      },
      {
        id: 3,
        source_name: 'MalwareBazaar',
        feed_id: 'feed-mb',
        observed_as: 'sha1',
        observed_hash_type: 'sha1',
        observed_hash_value: SHA1,
        observation_type: 'provider_hash_mapping'
      }
    ]);
    assert.equal(grouped.length, 1);
    assert.equal(grouped[0].observed_as, 'sha256');
    assert.equal(grouped[0].observed_hash_value, SHA256);
    assert.equal(grouped[0].additional_known_hashes.length, 2);
    assert.ok(grouped[0].mapping_evidence);
  });

  it('keeps Custom Feed separate from MalwareBazaar', () => {
    const grouped = groupFileArtifactObservations([
      {
        id: 1,
        source_name: 'Custom Feed',
        observed_as: 'md5',
        observed_hash_type: 'md5',
        observed_hash_value: MD5,
        observation_type: 'direct_source_observation'
      },
      {
        id: 2,
        source_name: 'MalwareBazaar',
        feed_id: 'feed-mb',
        observed_as: 'sha256',
        observed_hash_type: 'sha256',
        observed_hash_value: SHA256,
        observation_type: 'direct_source_observation'
      }
    ]);
    assert.equal(grouped.length, 2);
    const names = grouped.map((g) => g.source_name).sort();
    assert.deepEqual(names, ['Custom Feed', 'MalwareBazaar']);
  });

  it('does not merge different feed records with same source name', () => {
    const grouped = groupFileArtifactObservations([
      {
        id: 1,
        source_name: 'MalwareBazaar',
        feed_id: 'feed-a',
        observed_as: 'sha256',
        observed_hash_type: 'sha256',
        observed_hash_value: SHA256,
        observation_type: 'direct_source_observation'
      },
      {
        id: 2,
        source_name: 'MalwareBazaar',
        feed_id: 'feed-b',
        observed_as: 'md5',
        observed_hash_type: 'md5',
        observed_hash_value: MD5,
        observation_type: 'direct_source_observation'
      }
    ]);
    assert.equal(grouped.length, 2);
  });
});
