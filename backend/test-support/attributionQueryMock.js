/**
 * Fake-pool answers for the effective IOC attribution read
 * (iocSourceAttributions.loadEffectiveIocAttributions): analyst Threat Actors,
 * analyst Malware Families, source-reported assertions and active
 * suppressions. Shared by unit-test pools so a new attribution consumer does
 * not need a fresh hand-written branch per test file.
 *
 * Rows are filtered by the (ioc_id, observable_type) pairs the query binds, so
 * a test can seed several IOCs and still prove the read is scoped to the one
 * requested. Unrecognised SQL returns undefined and the calling pool decides
 * (strict pools throw), so production query drift still fails loudly.
 * Real PostgreSQL behaviour (row-value IN (VALUES …), joins, casts) is covered
 * by the *.integration.test.js suites, not here.
 */

/**
 * @typedef {object} AttributionFixtures
 * @property {object[]} [analystThreatActors] rows shaped like the analyst actor SELECT
 * @property {object[]} [analystMalwareFamilies] rows shaped like the analyst family SELECT
 * @property {object[]} [sourceAttributions] ioc_source_attributions rows (+ resolved_* columns)
 * @property {object[]} [suppressions] active ioc_attribution_overrides suppress rows
 */

/** Pairs bound as ($1::bigint, $2::text), ($3::bigint, $4::text), … */
function boundPairs(params, pairCount) {
  const out = new Set();
  for (let i = 0; i < pairCount; i += 1) out.add(`${Number(params[i * 2])}\u0000${String(params[i * 2 + 1])}`);
  return out;
}

function pairCountOf(sql) {
  const m = /IN \(VALUES (.*?)\)(?: AND| ORDER|$)/.exec(sql);
  if (!m) return 0;
  return (m[1].match(/::bigint/g) || []).length;
}

const inPairs = (pairs) => (row) => pairs.has(`${Number(row.ioc_id)}\u0000${String(row.ioc_observable_type)}`);

/**
 * @param {string} sql whitespace-normalised SQL
 * @param {unknown[]} params
 * @param {AttributionFixtures} [fixtures]
 * @returns {object[]|undefined} rows, or undefined when the SQL is not an attribution read
 */
export function attributionQueryRows(sql, params = [], fixtures = {}) {
  const pairs = boundPairs(params, pairCountOf(sql));
  if (sql.includes('FROM ioc_threat_actors ita') && sql.includes('JOIN threat_actors ta')) {
    return (fixtures.analystThreatActors || []).filter(inPairs(pairs));
  }
  if (sql.includes('FROM ioc_malware_families imf') && sql.includes('JOIN malware_families mf')) {
    return (fixtures.analystMalwareFamilies || []).filter(inPairs(pairs));
  }
  if (sql.includes('FROM ioc_source_attributions a') && sql.includes('LEFT JOIN threat_actors ta') && sql.includes("a.assertion_status = 'current'")) {
    const includeWithdrawn = params[pairs.size * 2] === true;
    return (fixtures.sourceAttributions || [])
      .filter(inPairs(pairs))
      .filter((r) => includeWithdrawn || r.assertion_status === 'current');
  }
  if (sql.includes('FROM ioc_attribution_overrides') && sql.includes("action = 'suppress'")) {
    return (fixtures.suppressions || []).filter(inPairs(pairs));
  }
  return undefined;
}
