/**
 * Threat Library report tags → IOC tags.
 *
 * Single source of truth for WHICH report↔IOC links carry a report's tags, shared
 * by read-time hydration (IOC Details, MCP/REST tags, CSV export) and the IOC
 * Search DSL (`tag …`). Nothing is copied into ioc_tags: inheritance is derived
 * from the live relationship, so it follows report tag edits, report deletion
 * and candidate review decisions immediately and can never duplicate.
 *
 * Report context is not an IOC assertion. A report tag describes the report
 * (its campaign, sector, theme); a report about bank fraud does not make every
 * hash it lists a "banking" IOC. So a report tag is an IOC-level tag only when
 * the IOC's OWN evidence in that report names it (reportTagIocEvidenceSql).
 * Every other report tag stays report context, visible through the report link
 * (IOC Details "Threat Context" row, `report_context_tags`).
 *
 * A report tag reaches the IOC a candidate is linked to when:
 *   - the report is active: not deleted and in a Threat Context-visible
 *     import_status (same set as store.getIocThreatContext);
 *   - the candidate is linked to an IOC record (matched_ioc_id);
 *   - the candidate is an IOC of this report — not context-only, ignored,
 *     rejected or invalid (mirrors promotion.isContextOrIgnored + 'rejected').
 *     A benign domain merely mentioned in a campaign report must not inherit
 *     the campaign's tags;
 *   - and, to be an IOC tag rather than report context, the candidate's own
 *     evidence (evidence_text, occurrence section heading / surrounding text)
 *     names the tag.
 *
 * Classification is intentionally NOT inherited — report tags describe the
 * threat/campaign context, an IOC's classification describes the observable.
 *
 * Standalone (no imports) so the search builder can use it without cycles.
 */

export const REPORT_TAG_CONTEXT_IMPORT_STATUSES = Object.freeze(['ready', 'imported', 'review_required']);

/**
 * Boolean SQL: candidate `c` of report `r` passes report tags to c.matched_ioc_id.
 * @param {string} [c] candidate alias
 * @param {string} [r] report alias
 */
export function reportTagInheritanceEligibleSql(c = 'c', r = 'r') {
  return `${r}.deleted_at IS NULL
       AND ${r}.import_status IN (${REPORT_TAG_CONTEXT_IMPORT_STATUSES.map((s) => `'${s}'`).join(', ')})
       AND ${c}.matched_ioc_id IS NOT NULL
       AND ${c}.is_ioc IS NOT FALSE
       AND ${c}.review_status NOT IN ('ignored', 'context_only', 'rejected')
       AND ${c}.assessment NOT IN ('context_only', 'invalid')
       AND ${c}.match_state NOT IN ('context_only', 'invalid')`;
}

/**
 * Boolean SQL: candidate `c`'s own evidence names tag `t`.
 *
 * IOC-specific evidence = the candidate's evidence_text plus, per persisted
 * occurrence, its section heading and surrounding text (where THIS value
 * appears in the report). The tag name must appear as a whole term,
 * case-insensitively; space / hyphen / underscore spellings are equivalent
 * ("credential theft" ~ "credential-theft"). The report title, summary and
 * other indicators' rows are not consulted — they are report context.
 * @param {string} [c] candidate alias
 * @param {string} [t] tags alias
 */
export function reportTagIocEvidenceSql(c = 'c', t = 't') {
  const escaped = String.raw`regexp_replace(lower(${t}.name), '([.^$*+?()\[\]{}|\\])', '\\\1', 'g')`;
  const term = `regexp_replace(${escaped}, '[[:space:]_-]+', '[[:space:]_-]+', 'g')`;
  const pattern = `'(^|[^[:alnum:]])' || ${term} || '($|[^[:alnum:]])'`;
  return `EXISTS (
         SELECT 1
           FROM (
             SELECT ${c}.evidence_text AS txt
             UNION ALL
             SELECT concat_ws(' ', occ->>'section_heading', occ->>'surrounding_text')
               FROM jsonb_array_elements(
                      CASE WHEN jsonb_typeof(${c}.evidence->'occurrences') = 'array'
                           THEN ${c}.evidence->'occurrences' ELSE '[]'::jsonb END
                    ) AS occ
           ) ev
          WHERE ev.txt ~* (${pattern})
       )`;
}

/**
 * Row-wise IOC membership for search: every (observable_type, id) that carries,
 * as an IOC-level tag, a report tag matching `tagCondSql` (a predicate over `t`,
 * the tags row). Driven from the tag → report_tags → candidates(report_id)
 * indexes; the caller UNIONs it with the direct ioc_tags membership.
 * @param {string} tagCondSql predicate referencing alias `t` (bind placeholders only)
 */
export function inheritedTagIocMembershipSql(tagCondSql) {
  return `SELECT trc.matched_ioc_observable_type, trc.matched_ioc_id
        FROM threat_report_tags trt
        JOIN tags t ON t.id = trt.tag_id
        JOIN threat_reports trr ON trr.id = trt.report_id
        JOIN threat_report_candidates trc ON trc.report_id = trr.id
       WHERE ${tagCondSql}
         AND ${reportTagInheritanceEligibleSql('trc', 'trr')}
         AND ${reportTagIocEvidenceSql('trc', 't')}`;
}

/**
 * Batched report tags of the reports linked to a set of IOC ids (one query, no
 * N+1). Only enabled catalog tags are returned (same rule as direct tag display).
 * Every linked report tag is returned — it is report context for the IOC —
 * with `ioc_evidence` telling whether the IOC's own evidence in that report
 * names the tag; only those rows are IOC-level tags.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<number|string>} iocIds
 * @returns {Promise<Array<{ ioc_id: number, tag_id: number, name: string, type: string|null,
 *   report_id: string, report_title: string, tlp: string|null, ioc_evidence: boolean }>>}
 *   one row per (IOC, tag, report); report_id is the report public_id
 */
export async function loadInheritedReportTagRows(db, iocIds) {
  const ids = [...new Set(
    (Array.isArray(iocIds) ? iocIds : [])
      .map((n) => Number(n))
      .filter((n) => Number.isFinite(n) && n > 0)
  )];
  if (!ids.length) return [];
  try {
    const { rows } = await db.query(
      `SELECT c.matched_ioc_id AS ioc_id, t.id AS tag_id, t.name, t.type,
              r.public_id AS report_id, r.title AS report_title, r.tlp,
              r.published_at, r.created_at AS report_created_at,
              bool_or(${reportTagIocEvidenceSql('c', 't')}) AS ioc_evidence
       FROM threat_report_candidates c
       JOIN threat_reports r ON r.id = c.report_id
       JOIN threat_report_tags rt ON rt.report_id = r.id
       JOIN tags t ON t.id = rt.tag_id AND t.enabled = TRUE
       WHERE c.matched_ioc_id = ANY($1::bigint[])
         AND ${reportTagInheritanceEligibleSql('c', 'r')}
       GROUP BY c.matched_ioc_id, t.id, t.name, t.type, r.public_id, r.title, r.tlp,
                r.published_at, r.created_at
       ORDER BY t.name ASC, r.published_at DESC NULLS LAST, r.created_at DESC`,
      [ids]
    );
    return rows.map((row) => ({
      ioc_id: Number(row.ioc_id),
      tag_id: Number(row.tag_id),
      name: row.name,
      type: row.type || null,
      report_id: String(row.report_id),
      report_title: row.report_title,
      tlp: row.tlp || null,
      ioc_evidence: row.ioc_evidence === true
    }));
  } catch (err) {
    // Schema without Threat Library report tags (pre-030) — no inheritance.
    if (err && err.code === '42P01') return [];
    throw err;
  }
}

/**
 * Group report-tag rows per requested seed IOC. A report appears once per tag;
 * its `ioc_evidence` is true when any IOC of the seed's artifact scope has
 * evidence naming the tag in that report (entry.ioc_evidence = any report).
 * @param {ReturnType<typeof loadInheritedReportTagRows> extends Promise<infer R> ? R : never} rows
 * @param {Map<number, number[]>} scopeBySeed seed id → IOC ids in its artifact scope
 * @returns {Map<number, Array<{ name: string, type: string|null, ioc_evidence: boolean,
 *   reports: Array<{ id: string, title: string, tlp: string|null, ioc_evidence: boolean }> }>>}
 */
export function groupInheritedTagsBySeed(rows, scopeBySeed) {
  const byIoc = new Map();
  for (const row of rows) {
    if (!byIoc.has(row.ioc_id)) byIoc.set(row.ioc_id, []);
    byIoc.get(row.ioc_id).push(row);
  }
  const out = new Map();
  for (const [seed, scope] of scopeBySeed) {
    const byName = new Map();
    for (const id of scope) {
      for (const row of byIoc.get(Number(id)) || []) {
        if (!byName.has(row.name)) {
          byName.set(row.name, { name: row.name, type: row.type, ioc_evidence: false, reports: [] });
        }
        const entry = byName.get(row.name);
        const evidence = row.ioc_evidence === true;
        const known = entry.reports.find((rep) => rep.id === row.report_id);
        if (known) {
          known.ioc_evidence = known.ioc_evidence || evidence;
        } else {
          entry.reports.push({ id: row.report_id, title: row.report_title, tlp: row.tlp, ioc_evidence: evidence });
        }
        entry.ioc_evidence = entry.ioc_evidence || evidence;
      }
    }
    out.set(Number(seed), [...byName.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)));
  }
  return out;
}
