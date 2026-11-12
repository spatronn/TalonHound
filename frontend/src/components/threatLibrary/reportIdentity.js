/**
 * Logical article identity on the report page: a superseded report (another
 * URL of an article already in the library) names its primary; a primary
 * lists the URL variants it groups. Reads only the API fields
 * `superseded_by` and `source_variants`.
 */

/**
 * URL variants (superseded reports) grouped under this primary report.
 * @param {{ source_variants?: object[] }|null|undefined} report
 * @returns {{ report_id: string, source_url?: string|null }[]}
 */
export function supersededVariants(report) {
  const list = Array.isArray(report?.source_variants) ? report.source_variants : [];
  return list.filter((v) => v?.relation === 'superseded' && v.report_id);
}

/**
 * Route of the primary report when this report is a superseded duplicate.
 * @param {{ superseded_by?: { report_id?: string }|null }|null|undefined} report
 * @returns {string|null}
 */
export function primaryReportHref(report) {
  const id = report?.superseded_by?.report_id;
  return id ? `/threat-intelligence/threat-library/${id}` : null;
}
