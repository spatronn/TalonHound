/**
 * Post-fetch identity claim for Threat Library URL reports.
 *
 * The import route can only dedupe on the URL the analyst typed. After the
 * worker fetches the page it knows more: the URL the server delivered after
 * redirects, the publisher's corroborated canonical URL and, on WordPress
 * sites, the post id (sourceIdentity.js). This module claims those keys for
 * the report — or, when another live report already owns one of them,
 * supersedes the freshly imported report into that existing one BEFORE any
 * extraction, AI call or candidate write happens.
 *
 * Safety rules:
 *  - Keys are claimed under per-key advisory locks (sorted) plus the UNIQUE
 *    index on identity_key, so two workers resolving equivalent URLs at the
 *    same time serialise and the second sees the first one's keys.
 *  - Only a report with no analyst-visible work (no candidates, never
 *    finalized) may be superseded automatically. A report that already holds
 *    extraction results / decisions only records the conflict; reconciling it
 *    is an explicit, audited operation (reportSupersession.js).
 *  - Exactly one matching primary report is required. Matches to two
 *    different logical reports are recorded as `ambiguous` and nothing merges.
 *  - A failed or deleted report never becomes a primary.
 *  - Translations (hreflang) merge only when BOTH documents list each other.
 */

import { findIdentityKeyOwners, lockIdentityKeys, recordIdentityKeys } from './importIdentity.js';

/**
 * @param {object|null} primary
 * @param {number} selfId
 */
function isEligiblePrimary(primary, selfId) {
  return Boolean(primary)
    && Number(primary.id) !== Number(selfId)
    && primary.deleted_at == null
    && primary.superseded_by_report_id == null
    && primary.import_status !== 'failed';
}

/**
 * Mark `reportId` as superseded by `primaryId`. Writes only the supersession
 * columns (and updated_at); every row the report owns stays in place.
 * @param {{ query: Function }} client inside a transaction
 * @param {{ reportId: number, primaryId: number, supersession: object }} input
 * @returns {Promise<boolean>} false when the row was already superseded / deleted
 */
export async function markReportSuperseded(client, { reportId, primaryId, supersession }) {
  const res = await client.query(
    `UPDATE threat_reports
        SET superseded_by_report_id = $2,
            superseded_at = NOW(),
            supersession = $3::jsonb,
            updated_at = NOW()
      WHERE id = $1
        AND $1 <> $2
        AND superseded_by_report_id IS NULL
        AND deleted_at IS NULL`,
    [reportId, primaryId, JSON.stringify(supersession || {})]
  );
  return res.rowCount === 1;
}

function addMatch(matches, primary, evidence) {
  const id = Number(primary.id);
  if (!matches.has(id)) matches.set(id, { primary, evidence: [] });
  matches.get(id).evidence.push(evidence);
}

function hreflangKeysOf(row) {
  const list = row?.source_identity?.hreflang;
  return Array.isArray(list) ? list.map((h) => h?.key).filter(Boolean) : [];
}

/**
 * @param {{ connect: Function, query: Function }} pool (fenced pools supported)
 * @param {{
 *   reportId: number,
 *   identity: ReturnType<import('./sourceIdentity.js').resolveSourceIdentity>,
 *   allowSupersede: boolean
 * }} input
 * @returns {Promise<{
 *   outcome: 'claimed'|'duplicate'|'conflict'|'ambiguous'|'skipped',
 *   primary?: object,
 *   evidence?: object[],
 *   matches?: { report_id: number, public_id: string, evidence: object[] }[],
 *   conflicts?: { key: string, report_id: number }[]
 * }>}
 */
export async function claimFetchedReportIdentity(pool, { reportId, identity, allowSupersede }) {
  const keys = (identity?.keys || []).map((k) => k.key).filter(Boolean);
  const hreflangKeys = (identity?.hreflang || []).map((h) => h.key).filter(Boolean);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await lockIdentityKeys(client, [...keys, ...hreflangKeys]);
    const { rows: selfRows } = await client.query(
      'SELECT id, public_id, deleted_at, superseded_by_report_id, finalized_at FROM threat_reports WHERE id = $1 FOR UPDATE',
      [reportId]
    );
    const self = selfRows[0];
    if (!self || self.deleted_at || self.superseded_by_report_id) {
      await client.query('ROLLBACK');
      return { outcome: 'skipped' };
    }

    const matches = new Map();
    for (const owner of await findIdentityKeyOwners(client, keys)) {
      if (!isEligiblePrimary(owner.primary, reportId)) continue;
      addMatch(matches, owner.primary, {
        via: 'identity_key',
        key: owner.identity_key,
        key_report_id: owner.key_report_id,
        evidence: (identity.keys.find((k) => k.key === owner.identity_key) || {}).evidence || []
      });
    }
    if (hreflangKeys.length) {
      const altOwners = (await findIdentityKeyOwners(client, hreflangKeys))
        .filter((o) => isEligiblePrimary(o.primary, reportId));
      if (altOwners.length) {
        const { rows: keyReports } = await client.query(
          'SELECT id, source_identity FROM threat_reports WHERE id = ANY($1::bigint[])',
          [[...new Set(altOwners.map((o) => o.key_report_id))]]
        );
        const byId = new Map(keyReports.map((r) => [Number(r.id), r]));
        for (const o of altOwners) {
          const listed = new Set([...hreflangKeysOf(byId.get(o.key_report_id)), ...hreflangKeysOf(o.primary)]);
          const reciprocal = keys.some((k) => listed.has(k));
          if (!reciprocal) continue;
          addMatch(matches, o.primary, {
            via: 'reciprocal_hreflang',
            key: o.identity_key,
            key_report_id: o.key_report_id,
            lang: (identity.hreflang.find((h) => h.key === o.identity_key) || {}).lang || null
          });
        }
      }
    }

    const matchList = [...matches.values()].map((m) => ({
      report_id: Number(m.primary.id),
      public_id: m.primary.public_id,
      evidence: m.evidence
    }));
    const claimedAt = new Date().toISOString();

    if (matches.size === 1 && allowSupersede && !self.finalized_at) {
      const [match] = matches.values();
      const supersession = {
        reason: 'source_identity',
        decided_by: 'import_identity',
        identity_version: identity.version,
        primary_public_id: match.primary.public_id,
        evidence: match.evidence,
        decided_at: claimedAt
      };
      const marked = await markReportSuperseded(client, { reportId, primaryId: Number(match.primary.id), supersession });
      if (!marked) {
        await client.query('ROLLBACK');
        return { outcome: 'skipped' };
      }
      const rec = await recordIdentityKeys(client, reportId, identity.keys, 'fetch');
      await client.query(
        'UPDATE threat_reports SET source_identity = $2::jsonb WHERE id = $1',
        [reportId, JSON.stringify({ ...identity, outcome: 'duplicate', matches: matchList, conflicts: rec.conflicts, claimed_at: claimedAt })]
      );
      await client.query('COMMIT');
      return { outcome: 'duplicate', primary: match.primary, evidence: match.evidence, matches: matchList, conflicts: rec.conflicts };
    }

    const rec = await recordIdentityKeys(client, reportId, identity.keys, 'fetch');
    const outcome = matches.size === 0 ? 'claimed' : matches.size > 1 ? 'ambiguous' : 'conflict';
    await client.query(
      'UPDATE threat_reports SET source_identity = $2::jsonb WHERE id = $1',
      [reportId, JSON.stringify({ ...identity, outcome, matches: matchList, conflicts: rec.conflicts, claimed_at: claimedAt })]
    );
    await client.query('COMMIT');
    return { outcome, matches: matchList, conflicts: rec.conflicts };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
