/**
 * Historical digest consistency (tl-candidates-v71, tl-digest-v7): finalized
 * 35418 / 35724 / 35737 held Git commit ids and OCI image index / manifest
 * digests approved as sha1 / sha256 file-hash Indicators.
 *
 * A. "(index sha256:<hex>" / "amd64 manifest sha256:<hex>" are OCI registry
 *    objects; an unprefixed hash on a "Malicious manifest" (package.json) row
 *    stays a file hash.
 * B. "source revision <hex>" names a commit.
 * C. A bare occurrence of a value the document names elsewhere as a commit /
 *    OCI object ("<hex> | Pushed to … next branch" beside "Commit <hex>") is
 *    that object, unless its own label or row names a file.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import {
  DIGEST_KINDS,
  classifyHexDigest,
  coreferencedObjectDigest,
  documentObjectIdentifiers,
  isOciObjectDigest
} from './digestSemantics.js';

const INDEX = '1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e';
const AMD64 = 'bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5';
const ARM64 = '56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf';
const COMMIT = '3eab3ec9304aa26081358330491d3cfeb55cc245';
const REVISION = '20535d8fa11f786a6c24df7488a0e449ed5f09ad';
const FILE = '167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad';
const RAT = 'c8cb3f6d5b90c46686d2bf531dc1a5786e27edc5';

test('historical digest contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v76');
});

function extract(blocks) {
  return extractReportCandidates(
    { source_type: 'url', source_url: 'https://publisher.example/report' },
    createCanonicalDocument({ title: 'Historical digest fixture', blocks })
  );
}
const find = (r, type, value) => r.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;

test('A: OCI index / manifest notation is a registry object; an unprefixed manifest file row is a file', () => {
  const line = `Docker images: ghcr.io/berriai/litellm:v1.107.0 (index sha256:${INDEX}, amd64 manifest sha256:${AMD64}, arm64 manifest sha256:${ARM64})`;
  for (const v of [INDEX, AMD64, ARM64]) {
    assert.equal(isOciObjectDigest(line, v), true, v);
    assert.equal(classifyHexDigest(line, v).kind, DIGEST_KINDS.OBJECT_ID, v);
  }
  assert.equal(classifyHexDigest(`Linux amd64 manifest: sha256:${AMD64}`, AMD64).kind, DIGEST_KINDS.OBJECT_ID);
  assert.equal(isOciObjectDigest(`package.json | Malicious manifest | ${FILE}`, FILE), false);
  assert.equal(classifyHexDigest(`sha256:${FILE} | Malicious litellm macOS x86-64 .whl hash`, FILE).kind, DIGEST_KINDS.FILE);
});

test('B: a source revision names a commit', () => {
  const line = `The provenance attached to the Linux amd64 image identifies the private workflow, run 39587059944, and source revision ${REVISION}.`;
  assert.equal(classifyHexDigest(line, REVISION).kind, DIGEST_KINDS.OBJECT_ID);
});

test('C: a bare row value the document names elsewhere as a commit is that commit', () => {
  const ids = documentObjectIdentifiers([
    { text: `The threat actors pushed malicious commits (e.g., Commit ${COMMIT} by attacker GitHub ID 148100).` },
    { text: `${RAT} | Core Miasma RAT binary.` }
  ]);
  assert.equal(ids.has(COMMIT), true);
  assert.equal(ids.has(RAT), false);
  const bare = classifyHexDigest(`${COMMIT} | Pushed to asyncapi/generator next branch.`, COMMIT);
  assert.equal(coreferencedObjectDigest(bare, COMMIT, ids, 'Pushed to asyncapi/generator next branch.')?.kind, DIGEST_KINDS.OBJECT_ID);
  // A row that names a file keeps the file reading even when the value is known.
  assert.equal(coreferencedObjectDigest(bare, COMMIT, ids, 'Core RAT binary'), null);

  const result = extract([
    { id: 'p1', type: 'paragraph', text: `The threat actors pushed malicious commits directly to these shadow release branches (e.g., Commit ${COMMIT} by attacker GitHub ID 148100).` },
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    createTableBlock({
      id: 't1',
      headers: ['Indicator', 'Context'],
      rows: [
        [RAT, 'Core Miasma RAT binary.'],
        [COMMIT, 'Pushed to asyncapi/generator next branch.']
      ]
    }),
    { id: 'h2', type: 'heading', level: 3, text: 'Container Images' },
    { id: 'l1', type: 'list', text: `Image index: sha256:${INDEX}` },
    { id: 'l2', type: 'list', text: `Linux amd64 manifest: sha256:${AMD64}` }
  ]);
  const rat = find(result, 'sha1', RAT);
  assert.ok(rat && isReportIndicatorMember(rat), 'the RAT binary stays a file-hash Indicator');
  for (const [type, v] of [['sha1', COMMIT], ['sha256', INDEX], ['sha256', AMD64]]) {
    assert.equal(find(result, type, v), null, `${type}:${v} must not be a file-hash candidate`);
    const artifact = find(result, 'technical_artifact', v);
    assert.ok(artifact, `${v} stays visible as context`);
    assert.equal(artifact.digest_kind, DIGEST_KINDS.OBJECT_ID);
  }
});
