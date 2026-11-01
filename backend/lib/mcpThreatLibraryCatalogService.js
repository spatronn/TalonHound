/**
 * MCP Threat Library report catalog (threat_library_list_reports /
 * threat_library_check_report_urls). Thin outcome mapping over
 * lib/threatLibrary/reportCatalog.js, which owns the queries, the URL identity
 * and the report state; this module never touches reports, candidates or IOCs.
 */

import { listReportCatalog, checkReportUrls, CatalogInputError } from './threatLibrary/reportCatalog.js';

async function asOutcome(run) {
  try {
    return { status: 200, body: await run() };
  } catch (err) {
    if (err instanceof CatalogInputError) {
      return { status: 400, error: { code: err.code, message: err.message } };
    }
    throw err;
  }
}

/** @param {import('pg').Pool} pool */
export function mcpThreatLibraryListReports(pool, args = {}) {
  return asOutcome(() => listReportCatalog(pool, args));
}

/** @param {import('pg').Pool} pool */
export function mcpThreatLibraryCheckReportUrls(pool, args = {}) {
  return asOutcome(() => checkReportUrls(pool, args.urls));
}
