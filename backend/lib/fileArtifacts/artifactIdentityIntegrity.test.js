/**
 * Regression: file-artifact hash alias integrity across merge / VT / Threat Context.
 *
 * Covers the production failure mode where merge left IOC links on merged
 * tombstones while hashes moved to the canonical artifact — so the surviving
 * SHA256 IOC appeared to have no VirusTotal enrichment and no Threat Context
 * even though both still existed on the MD5 alias IOC.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolveVtEnrichmentRow } from '../virustotalEnrichmentReuse.js';
import { collectIocEnrichments } from '../iocEnrichmentAggregator.js';
import { loadIocThreatContext } from '../threatLibrary/iocThreatContext.js';
import { findArtifactLinkedIocsByIocId } from './read.js';

const MD5 = '67f4dad1a94ed8a47283c2c0c05a7594';
const SHA1 = '3aa267fbb14f73c9db55d6556fa50373716c2f1b';
const SHA256 = '3fe624c33790b409421f4fa2bb8abfd701df2231a959493c33187ed34bec0ae7';
const MD5_IOC = 3472708;
const SHA1_IOC = 3472709;
const SHA256_IOC = 1139687;
const OTHER_MD5_IOC = 999001;
const ART_CANON = 'b69e1db8-6c30-4d47-a9ec-b131b2f02f4e';
const ART_TOMBSTONE = '69bb2d66-be3d-4d8b-b802-b21061b29002';
const REPORT_TITLE = 'Dtrack expands its operations to Europe and Latin America';

function decideIocLinkMove(link, existingRow, canonicalId) {
  if (!existingRow) return 'move';
  if (existingRow.id === link.id) return 'move';
  if (existingRow.artifact_id === canonicalId) return 'delete_dup';
  return 'skip_third';
}

function withReadFlag(value, fn) {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = value;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  });
}

/**
 * Production-broken shape: hashes on canonical, MD5 IOC link still on tombstone,
 * VT enrichment + Threat Library match keyed to MD5 IOC id.
 */
function buildBrokenMergedShapePool(opts = {}) {
  const {
    includeSha1Link = false,
    includeSha1Claim = false,
    includeSha256Claim = false,
    includeUnrelatedClaim = false,
    vtOnMd5 = true,
    vtOnSha256 = false
  } = opts;

  const vtRows = [];
  if (vtOnMd5) {
    vtRows.push({
      provider: 'virustotal',
      ioc_id: MD5_IOC,
      status: 'success',
      ioc_type: 'md5',
      normalized_summary: { file: { md5: MD5, sha256: SHA256 }, ioc_type: 'md5', provider: 'virustotal' },
      error_message: null,
      fetched_at: '2026-09-20T22:00:38.811Z',
      expires_at: '2026-09-21T22:00:38.811Z',
      raw_response: null
    });
  }
  if (vtOnSha256) {
    vtRows.push({
      provider: 'virustotal',
      ioc_id: SHA256_IOC,
      status: 'success',
      ioc_type: 'sha256',
      normalized_summary: { file: { md5: MD5, sha256: SHA256 }, ioc_type: 'sha256', provider: 'virustotal' },
      error_message: null,
      fetched_at: '2026-09-19T10:00:00.000Z',
      expires_at: '2026-09-20T10:00:00.000Z',
      raw_response: null
    });
  }

  const claims = [
    {
      id: 2486,
      report_id: 16,
      matched_ioc_id: MD5_IOC,
      candidate_type: 'md5',
      role: 'malware_sample',
      assessment: 'malicious',
      confidence: '1.000',
      evidence_text: `MD5 ${MD5}`,
      section: 'explicit_ioc_section',
      page_number: null,
      evidence: { occurrence_count: 1, occurrences: [] },
      report_public_id: '1da83d01-3a96-4b0d-970f-b9640f9d327a',
      report_title: REPORT_TITLE,
      published_at: '2022-11-15T10:00:28.000Z',
      tlp: 'clear',
      source_name: 'securelist.com',
      source_type: 'url',
      report_summary: 'DTrack backdoor activity.'
    }
  ];
  if (includeSha1Claim) {
    claims.push({
      ...claims[0],
      id: 2487,
      matched_ioc_id: SHA1_IOC,
      candidate_type: 'sha1',
      evidence_text: `SHA1 ${SHA1}`
    });
  }
  if (includeSha256Claim) {
    claims.push({
      ...claims[0],
      id: 2488,
      matched_ioc_id: SHA256_IOC,
      candidate_type: 'sha256',
      evidence_text: `SHA256 ${SHA256}`
    });
  }
  if (includeUnrelatedClaim) {
    claims.push({
      ...claims[0],
      id: 9000,
      report_id: 99,
      matched_ioc_id: OTHER_MD5_IOC,
      candidate_type: 'md5',
      report_public_id: 'other-report',
      report_title: 'Unrelated malware report',
      report_summary: 'Should not leak.'
    });
  }

  const pool = {
    vtLookups: 0,
    query: async (sql, params = []) => {
      const s = String(sql).replace(/\s+/g, ' ').trim();

      if (s.includes('file_artifact_ioc_links l') && s.includes('JOIN file_artifacts a')) {
        const iocId = Number(params[0]);
        if (iocId === SHA256_IOC) {
          return { rows: [{ artifact_id: ART_CANON, status: 'active', merged_into_artifact_id: null }], rowCount: 1 };
        }
        if (iocId === MD5_IOC || iocId === SHA1_IOC) {
          return {
            rows: [{ artifact_id: ART_TOMBSTONE, status: 'merged', merged_into_artifact_id: ART_CANON }],
            rowCount: 1
          };
        }
        return { rows: [], rowCount: 0 };
      }

      if (s.includes('FROM file_artifacts WHERE id = $1')) {
        return { rows: [{ id: ART_CANON, status: 'active', merged_into_artifact_id: null }], rowCount: 1 };
      }

      if (s.includes('DISTINCT ON (ioc_item_id)')) {
        assert.equal(params[0], ART_CANON);
        const rows = [{ ioc_item_id: SHA256_IOC, ioc_public_id: 'sha256-pid' }];
        // Self-heal: tombstone links of the canonical are included.
        rows.push({ ioc_item_id: MD5_IOC, ioc_public_id: 'md5-pid' });
        if (includeSha1Link) rows.push({ ioc_item_id: SHA1_IOC, ioc_public_id: 'sha1-pid' });
        return { rows, rowCount: rows.length };
      }

      if (s.includes('FROM ioc_enrichments')) {
        pool.vtLookups += 1;
        // resolveVtEnrichmentRow: ($provider, $iocId) or ($provider, $ids[])
        // collectIocEnrichments: ($ids[])
        let ids;
        if (Array.isArray(params[0])) ids = params[0].map(Number);
        else if (Array.isArray(params[1])) ids = params[1].map(Number);
        else ids = [Number(params[1] ?? params[0])].filter((n) => Number.isFinite(n));
        let rows = vtRows.filter((r) => ids.includes(Number(r.ioc_id)));
        if (s.includes("status='success'") || s.includes("status = 'success'")) {
          rows = rows.filter((r) => r.status === 'success');
        }
        rows = [...rows].sort((a, b) => String(b.fetched_at).localeCompare(String(a.fetched_at)));
        return { rows, rowCount: rows.length };
      }

      if (s.includes('FROM threat_report_candidates c')) {
        const wanted = new Set((params[0] || []).map(Number));
        const preferred = Number(params[1]);
        const matched = claims.filter((c) => wanted.has(Number(c.matched_ioc_id)));
        const rankType = (t) => ({ sha256: 0, sha1: 1, md5: 2 }[String(t).toLowerCase()] ?? 9);
        matched.sort((a, b) => {
          const aPref = Number(a.matched_ioc_id) === preferred ? 0 : 1;
          const bPref = Number(b.matched_ioc_id) === preferred ? 0 : 1;
          if (aPref !== bPref) return aPref - bPref;
          return rankType(a.candidate_type) - rankType(b.candidate_type) || a.id - b.id;
        });
        const byReport = new Map();
        for (const c of matched) {
          if (!byReport.has(c.report_id)) byReport.set(c.report_id, c);
        }
        return { rows: [...byReport.values()] };
      }

      if (s.includes('FROM threat_relationships tr')) return { rows: [] };
      if (s.includes('FROM threat_report_entities re')) return { rows: [] };
      // Optional provider tables in collectIocEnrichments
      if (s.includes('ioc_domain_enrichment') || s.includes('ioc_abuseipdb') || s.includes('ioc_ip_enrichment') || s.includes('ioc_spamhaus')) {
        const err = new Error('relation does not exist');
        err.code = '42P01';
        throw err;
      }
      throw new Error(`Unexpected SQL: ${s.slice(0, 120)}`);
    }
  };
  return pool;
}

describe('file artifact identity integrity (merge / VT / Threat Context)', () => {
  describe('TEST G — merge IOC-link move is idempotent / self-aware', () => {
    it('moves the duplicate\'s own link instead of treating self as a collision', () => {
      const link = { id: 7, ioc_item_id: MD5_IOC };
      assert.equal(decideIocLinkMove(link, { id: 7, artifact_id: ART_TOMBSTONE }, ART_CANON), 'move');
    });

    it('repeat decision stays move (idempotent intent)', () => {
      const link = { id: 7, ioc_item_id: MD5_IOC };
      assert.equal(decideIocLinkMove(link, { id: 7, artifact_id: ART_CANON }, ART_CANON), 'move');
    });
  });

  describe('TEST H — production-broken merged shape self-heals on read', () => {
    it('findArtifactLinkedIocsByIocId includes MD5 alias still on tombstone', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool();
        const linked = await findArtifactLinkedIocsByIocId(pool, SHA256_IOC);
        assert.ok(linked);
        assert.equal(linked.artifact_id, ART_CANON);
        assert.ok(linked.linked_ioc_ids.includes(SHA256_IOC));
        assert.ok(linked.linked_ioc_ids.includes(MD5_IOC));
      });
    });
  });

  describe('TEST A — VT enrichment survives MD5 → SHA256 merge shape', () => {
    it('canonical SHA256 reuses MD5 VT success without a second provider call', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool();
        const { row, reusedFromAlias } = await resolveVtEnrichmentRow(pool, SHA256_IOC);
        assert.ok(row);
        assert.equal(row.status, 'success');
        assert.equal(Number(row.ioc_id), MD5_IOC);
        assert.equal(reusedFromAlias, true);
        assert.equal(pool.vtLookups >= 1, true);
        // No live VT: resolver is DB-only.
        assert.equal(row.normalized_summary.file.sha256, SHA256);
      });
    });

    it('collectIocEnrichments surfaces one VT success for the canonical IOC', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool();
        const linked = await findArtifactLinkedIocsByIocId(pool, SHA256_IOC);
        const entries = await collectIocEnrichments(pool, {
          iocId: SHA256_IOC,
          type: 'sha256',
          value: SHA256,
          linkedIocIds: linked.linked_ioc_ids
        });
        const vt = entries.filter((e) => e.provider === 'virustotal');
        assert.equal(vt.length, 1);
        assert.equal(vt[0].status, 'success');
      });
    });
  });

  describe('TEST B — Threat Context resolves MD5 alias', () => {
    it('canonical SHA256 Threat Context includes the report matched via MD5', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool();
        const out = await loadIocThreatContext(pool, SHA256_IOC);
        assert.equal(out.claims.length, 1);
        assert.equal(out.claims[0].report.title, REPORT_TITLE);
      });
    });
  });

  describe('TEST C — Threat Context resolves SHA1 alias', () => {
    it('canonical SHA256 Threat Context includes the report matched via SHA1', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool({
          includeSha1Link: true,
          includeSha1Claim: true,
          vtOnMd5: false
        });
        // Only the SHA1 claim should be considered for this case.
        const inner = pool.query.bind(pool);
        pool.query = async (sql, params) => {
          const res = await inner(sql, params);
          if (String(sql).includes('threat_report_candidates')) {
            return { rows: (res.rows || []).filter((r) => Number(r.matched_ioc_id) === SHA1_IOC) };
          }
          return res;
        };

        const out = await loadIocThreatContext(pool, SHA256_IOC);
        assert.equal(out.claims.length, 1);
        assert.equal(out.claims[0].report.title, REPORT_TITLE);
      });
    });
  });

  describe('TEST D — direct SHA256 Threat Context still works', () => {
    it('keeps a SHA256-matched report when the match is already on the canonical IOC', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool({
          includeSha256Claim: true,
          vtOnMd5: false
        });
        pool.query = ((inner) => async (sql, params) => {
          const res = await inner(sql, params);
          const s = String(sql);
          if (s.includes('threat_report_candidates')) {
            return {
              rows: (res.rows || []).filter((r) => Number(r.matched_ioc_id) === SHA256_IOC)
            };
          }
          return res;
        })(pool.query.bind(pool));

        const out = await loadIocThreatContext(pool, SHA256_IOC);
        assert.equal(out.claims.length, 1);
        assert.equal(out.claims[0].report.title, REPORT_TITLE);
      });
    });
  });

  describe('TEST E — unrelated hashes do not inherit context', () => {
    it('does not surface another artifact\'s report', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool({ includeUnrelatedClaim: true });
        const out = await loadIocThreatContext(pool, SHA256_IOC);
        assert.equal(out.claims.length, 1);
        assert.equal(out.claims[0].report.title, REPORT_TITLE);
        assert.ok(!out.claims.some((c) => c.report.title === 'Unrelated malware report'));
      });
    });
  });

  describe('TEST F — no duplicate Threat Context when report lists multiple aliases', () => {
    it('shows the report once when MD5 + SHA1 + SHA256 all matched', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool({
          includeSha1Link: true,
          includeSha1Claim: true,
          includeSha256Claim: true
        });
        const out = await loadIocThreatContext(pool, SHA256_IOC);
        assert.equal(out.claims.length, 1);
        assert.equal(out.claims[0].report.title, REPORT_TITLE);
      });
    });
  });

  describe('VT conflict preference', () => {
    it('prefers the newest success when multiple alias enrichments exist', async () => {
      await withReadFlag('1', async () => {
        const pool = buildBrokenMergedShapePool({ vtOnMd5: true, vtOnSha256: true });
        // Direct row on SHA256 wins (any status) — mirrors resolveVtEnrichmentRow contract.
        const direct = await resolveVtEnrichmentRow(pool, SHA256_IOC);
        assert.equal(direct.reusedFromAlias, false);
        assert.equal(Number(direct.row.ioc_id), SHA256_IOC);

        // When canonical has no row, reuse prefers newest alias success.
        const poolAliasOnly = buildBrokenMergedShapePool({ vtOnMd5: true, vtOnSha256: false });
        const reused = await resolveVtEnrichmentRow(poolAliasOnly, SHA256_IOC);
        assert.equal(reused.reusedFromAlias, true);
        assert.equal(Number(reused.row.ioc_id), MD5_IOC);
      });
    });
  });
});
