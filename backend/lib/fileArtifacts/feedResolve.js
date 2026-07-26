/**
 * Resolve integration_feeds.integration_id from an IOC source_name.
 * Kept inside fileArtifacts so the integration worker image (which mounts
 * fileArtifacts under /backend/lib/fileArtifacts) does not need to import
 * backend/lib/iocExpiration.js.
 */

/** Mirrors FEED_SOURCE_RULES exact/prefix/includes entries used by import paths. */
const FEED_SOURCE_RULES = Object.freeze([
  { key: 'usom-trcert', exact: 'USOM:TR-CERT' },
  { key: 'urlhaus-abusech', exact: 'URLhaus:abuse.ch' },
  { key: 'threatfox-abusech', exact: 'ThreatFox:abuse.ch' },
  { key: 'malwarebazaar-abusech', exact: 'MalwareBazaar:abuse.ch' },
  { key: 'et-blockrules', prefix: 'EmergingThreats:' },
  { key: 'phishtank-opendnsrr', includes: ['phishtank', 'PhishTank'] },
  { key: 'alienvault-otx', exact: 'AlienVault OTX' }
]);

/**
 * @param {string|null|undefined} sourceName
 * @param {string} feedKey
 */
export function sourceNameMatchesFeed(sourceName, feedKey) {
  const sn = String(sourceName || '');
  const rule = FEED_SOURCE_RULES.find((r) => r.key === feedKey);
  if (!rule) return false;
  if (rule.exact) return sn === rule.exact;
  if (rule.prefix) return sn.startsWith(rule.prefix);
  if (rule.includes) return rule.includes.some((p) => sn.includes(p));
  return false;
}

/**
 * @param {string|null|undefined} sourceName
 */
export function feedKeyForSourceName(sourceName) {
  const hit = FEED_SOURCE_RULES.find((r) => sourceNameMatchesFeed(sourceName, r.key));
  return hit?.key || null;
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} client
 * @param {string|null|undefined} sourceName
 * @returns {Promise<string|null>}
 */
export async function resolveFeedIdBySourceName(client, sourceName) {
  const key = feedKeyForSourceName(sourceName);
  if (key) {
    const { rows } = await client.query(
      `SELECT integration_id FROM integration_feeds WHERE key = $1 LIMIT 1`,
      [key]
    );
    if (rows[0]?.integration_id) return rows[0].integration_id;
  }
  const sn = String(sourceName || '').trim();
  if (!sn) return null;
  const { rows } = await client.query(
    `SELECT integration_id FROM integration_feeds
     WHERE feed_kind = 'custom' AND name = $1
     LIMIT 1`,
    [sn]
  );
  return rows[0]?.integration_id || null;
}
