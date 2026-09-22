/**
 * Threat Library report tags — analyst-managed campaign/threat context on a
 * report, drawn from the global `tags` catalog (same vocabulary as IOC tags).
 *
 * Storage is threat_report_tags (report_id, tag_id) only. IOC inheritance is
 * derived at read time (reportTagInheritance.js); nothing here writes ioc_tags.
 */

/**
 * Tags of several reports in one query.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<number|string>} reportIds internal report ids
 * @returns {Promise<Map<number, Array<{ id: number, name: string, type: string|null }>>>}
 */
export async function loadReportTagsByReportIds(db, reportIds) {
  const ids = [...new Set(
    (Array.isArray(reportIds) ? reportIds : [])
      .map((n) => Number(n))
      .filter((n) => Number.isFinite(n) && n > 0)
  )];
  const out = new Map(ids.map((id) => [id, []]));
  if (!ids.length) return out;
  try {
    const { rows } = await db.query(
      `SELECT rt.report_id, t.id, t.name, t.type
       FROM threat_report_tags rt
       JOIN tags t ON t.id = rt.tag_id AND t.enabled = TRUE
       WHERE rt.report_id = ANY($1::bigint[])
       ORDER BY rt.report_id, t.name ASC`,
      [ids]
    );
    for (const row of rows) {
      out.get(Number(row.report_id))?.push({ id: Number(row.id), name: row.name, type: row.type || null });
    }
  } catch (err) {
    if (!(err && err.code === '42P01')) throw err;
  }
  return out;
}

/** @returns {Promise<Array<{ id: number, name: string, type: string|null }>>} */
export async function loadReportTags(db, reportId) {
  const map = await loadReportTagsByReportIds(db, [reportId]);
  return map.get(Number(reportId)) || [];
}

/**
 * Enabled catalog tag by id, or null.
 * @returns {Promise<{ id: number, name: string, type: string|null }|null>}
 */
export async function findEnabledTag(db, tagId) {
  const id = Number(tagId);
  if (!Number.isInteger(id) || id <= 0) return null;
  const { rows } = await db.query(
    'SELECT id, name, type FROM tags WHERE id = $1 AND enabled = TRUE LIMIT 1',
    [id]
  );
  return rows[0] ? { id: Number(rows[0].id), name: rows[0].name, type: rows[0].type || null } : null;
}

/**
 * Idempotent add. @returns {Promise<boolean>} true when a new row was inserted.
 */
export async function addReportTag(db, reportId, tagId) {
  const { rowCount } = await db.query(
    `INSERT INTO threat_report_tags (report_id, tag_id)
     VALUES ($1, $2)
     ON CONFLICT (report_id, tag_id) DO NOTHING`,
    [reportId, tagId]
  );
  return rowCount > 0;
}

/**
 * Idempotent remove. Only the report↔tag row is deleted: IOC direct tags and the
 * same tag on other reports are untouched. @returns {Promise<boolean>} true when removed.
 */
export async function removeReportTag(db, reportId, tagId) {
  const { rowCount } = await db.query(
    'DELETE FROM threat_report_tags WHERE report_id = $1 AND tag_id = $2',
    [reportId, tagId]
  );
  return rowCount > 0;
}

/**
 * How many IOC records currently inherit this report's tags (for audit/UI context).
 * Uses the same eligibility rule as inheritance.
 */
export async function countReportTagInheritingIocs(db, reportId, eligibleSql) {
  const { rows } = await db.query(
    `SELECT count(DISTINCT c.matched_ioc_id)::int AS n
     FROM threat_report_candidates c
     JOIN threat_reports r ON r.id = c.report_id
     WHERE r.id = $1 AND ${eligibleSql}`,
    [reportId]
  );
  return rows[0]?.n ?? 0;
}
