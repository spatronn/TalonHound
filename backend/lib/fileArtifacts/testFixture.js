/**
 * Production-like fixture seed for File Artifact DB tests.
 */

const MD5 = '9aed790a18f214b04619837cd71546d3';
const SHA1 = '0f9a253afc55a8ebbd29a70c43d0e3cd668920f4';
const SHA256 = '8ec6066000f5585d6fefbc1d5a30fa094ac9893456dbf4085fec81e6b71cef3b';
const MD5_PUBLIC = '6d476fe0-8f51-41b7-8b36-a6ac8cf1f0ee';
const SHA256_PUBLIC = '7994273b-f288-4d4f-8875-54af17c2b70b';

function hex(n, seed) {
  // deterministic pseudo hex of length n
  let s = '';
  let x = seed;
  while (s.length < n) {
    x = (x * 1103515245 + 12345) >>> 0;
    s += x.toString(16).padStart(8, '0');
  }
  return s.slice(0, n);
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 */
export async function seedFileArtifactFixture(db) {
  // Manual source so browse active filter (ioc_source_id OR membership) includes fixture rows
  await db.query(
    `INSERT INTO ioc_sources (name, display_name, source_type, active)
     VALUES ('file_artifact_test', 'File Artifact Test', 'test', TRUE)
     ON CONFLICT (name) DO NOTHING`
  );
  const src = await db.query(`SELECT id FROM ioc_sources WHERE name = 'file_artifact_test' LIMIT 1`);
  const sourceId = src.rows[0]?.id || null;

  // Custom Feed MD5
  await db.query(
    `INSERT INTO ioc_items (
       public_id, observable, observable_type, source_name, confidence, category, note,
       created_at, last_seen_at, ioc_source_id
     ) SELECT $1::uuid, $2, 'md5', 'Custom Feed', 'medium', 'custom-threat-feed',
              'Imported from Custom Threat Feed: Custom Feed', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days', $3
       WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE public_id = $1::uuid)`,
    [MD5_PUBLIC, MD5, sourceId]
  );

  // MalwareBazaar SHA256 with sibling note
  const mbNote = `Auto-imported from MalwareBazaar CSV | md5=${MD5} | sha1=${SHA1} | file_name=agent.exe`;
  await db.query(
    `INSERT INTO ioc_items (
       public_id, observable, observable_type, source_name, confidence, category, note,
       created_at, last_seen_at, ioc_source_id
     ) SELECT $1::uuid, $2, 'sha256', 'MalwareBazaar', 'high', 'malware', $3,
              NOW() - INTERVAL '3 days', NOW() - INTERVAL '1 day', $4
       WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE public_id = $1::uuid)`,
    [SHA256_PUBLIC, SHA256, mbNote, sourceId]
  );

  // Separate SHA256 artifact
  const otherSha = hex(64, 42);
  await db.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note, created_at, ioc_source_id)
     SELECT gen_random_uuid(), $1, 'sha256', 'ThreatFox', 'medium', 'malware', 'solo', NOW() - INTERVAL '5 days', $2
     WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE observable = $1 AND observable_type = 'sha256')`,
    [otherSha, sourceId]
  );

  // Legacy MD5 without siblings
  const legacyMd5 = hex(32, 99);
  await db.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note, created_at, ioc_source_id)
     SELECT gen_random_uuid(), $1, 'md5', 'OTX', 'low', 'hash', 'legacy-only', NOW() - INTERVAL '4 days', $2
     WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE observable = $1 AND observable_type = 'md5')`,
    [legacyMd5, sourceId]
  );

  // Non-file IOC
  await db.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note, created_at, ioc_source_id)
     SELECT gen_random_uuid(), 'evil.example', 'domain', 'URLHaus', 'medium', 'domain', 'non-file', NOW() - INTERVAL '1 day', $1
     WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE observable = 'evil.example' AND observable_type = 'domain')`,
    [sourceId]
  );

  // Pagination filler: 60 sha256 identities
  for (let i = 0; i < 60; i += 1) {
    const h = hex(64, 1000 + i);
    await db.query(
      `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note, created_at, ioc_source_id)
       SELECT gen_random_uuid(), $1, 'sha256', 'ThreatFox', 'medium', 'malware', $2, NOW() - ($3 || ' hours')::interval, $4
       WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE observable = $1 AND observable_type = 'sha256')`,
      [h, `pad-${i}`, String(i + 1), sourceId]
    );
  }

  // Conflict fixture: same MD5 claimed by two different SHA256 notes (provider phase should record conflict)
  const conflictMd5 = hex(32, 777);
  const conflictShaA = hex(64, 778);
  const conflictShaB = hex(64, 779);
  await db.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note, created_at, ioc_source_id)
     SELECT gen_random_uuid(), $1, 'sha256', 'MalwareBazaar', 'high', 'malware', $2, NOW() - INTERVAL '6 days', $3
     WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE observable = $1 AND observable_type = 'sha256')`,
    [conflictShaA, `md5=${conflictMd5} | conflict-a`, sourceId]
  );
  await db.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note, created_at, ioc_source_id)
     SELECT gen_random_uuid(), $1, 'sha256', 'VirusTotal', 'high', 'malware', $2, NOW() - INTERVAL '6 days', $3
     WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE observable = $1 AND observable_type = 'sha256')`,
    [conflictShaB, `md5=${conflictMd5} | conflict-b`, sourceId]
  );

  // Malformed hash IOC (invalid length) — backfill should skip/report
  await db.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note, created_at, ioc_source_id)
     SELECT gen_random_uuid(), 'not-a-valid-md5', 'md5', 'BadFeed', 'low', 'hash', 'malformed', NOW() - INTERVAL '7 days', $1
     WHERE NOT EXISTS (SELECT 1 FROM ioc_items WHERE observable = 'not-a-valid-md5' AND observable_type = 'md5')`,
    [sourceId]
  ).catch(() => {
    // Some DBs may reject via check constraint; ignore
  });

  // Ensure any pre-existing fixture rows without source also get the test source
  if (sourceId) {
    await db.query(
      `UPDATE ioc_items SET ioc_source_id = $1 WHERE ioc_source_id IS NULL AND source_name IN (
         'Custom Feed','MalwareBazaar','ThreatFox','OTX','URLHaus','VirusTotal','BadFeed'
       )`,
      [sourceId]
    );
  }

  return {
    MD5,
    SHA1,
    SHA256,
    MD5_PUBLIC,
    SHA256_PUBLIC,
    otherSha,
    legacyMd5,
    conflictMd5,
    conflictShaA,
    conflictShaB,
    sourceId
  };
}

export const FIXTURE_HASHES = { MD5, SHA1, SHA256, MD5_PUBLIC, SHA256_PUBLIC };
